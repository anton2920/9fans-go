package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/anton2920/9fans-go/acme"
	"github.com/anton2920/gofa/ints"
)

type Line struct {
	GoLine   string
	AsmLines []string
}

type Function struct {
	Text []byte

	Name string
	File string

	Lines       []Line
	LinesSearch map[string][]int
}

type Program struct {
	sync.RWMutex

	Name         string
	LastModified time.Time

	Disassembly []byte
	Functions   []Function

	Search map[string]map[string]*Function
}

type WinInfo struct {
	Name     string
	NameChan chan string
}

const (
	Prefix = "TEXT"
	Suffix = "\n\n"
)

func Assert(pred bool) {
	if !pred {
		panic("ASSERTION FAILED")
	}
}

func MonitorWindow(wID int, prog *Program, nameChan <-chan string, dataChan chan<- []byte) {
	var buf bytes.Buffer
	var wName string

	w, err := acme.Open(wID, nil)
	if err != nil {
		log.Fatalf("[%d]: failed to open window: %v", wID, err)
	}
	defer w.CloseFiles()

	w.ReadAddr()
	var q0, q1 int
	var s0, s1 int

	for {
		select {
		case wName = <-nameChan:
		default:
			w.Ctl("addr=dot")
			m0, m1, err := w.ReadAddr()
			if err != nil {
				// log.Fatalf("[%d]: failed to read dot address: %v", wID, err)
				return
			}

			if (m0 != q0) || (m1 != q1) {
				q0, q1 = m0, m1

				w.Addr("-/^/,/$/")
				m0, m1, err := w.ReadAddr()
				if err != nil {
					// log.Fatalf("[%d]: failed to read selection address: %v", wID, err)
					continue
				}
				if m0 > q0 {
					m0 = 0
					w.Addr("#%d,#%d", m0, m1)
				}

				/* If selection changed. */
				if (m0 != s0) || (m1 != s1) {
					s0, s1 = m0, m1

					selection, err := w.ReadAll("xdata")
					if err != nil {
						// log.Fatalf("[%d]: failed to read all selected contents: %v", wID, err)
						continue
					}

					w.Ctl("addr=dot")
					w.Addr("-/^func.*/")
					w.Addr(".,/^}/")
					f0, f1, err := w.ReadAddr()
					if err != nil {
						// log.Fatalf("[%d]: failed to read function address: %v", wID, err)
						continue
					}

					funcBody, err := w.ReadAll("xdata")
					if err != nil {
						// log.Fatalf("[%d]: failed to read func body: %v", wID, err)
						continue
					}

					if (len(funcBody) > 0) && (s0 >= f0) && (s1 <= f1) {
						funcLines := strings.Split(string(funcBody), "\n")
						funcLinesSearch := make(map[string][]int)
						for i := 0; i < len(funcLines); i++ {
							funcLinesSearch[funcLines[i]] = append(funcLinesSearch[funcLines[i]], i)
						}

						fmt.Printf("[%d]: s=#%d,#%d, f=#%d,#%d %s\n", wID, s0, s1, f0, f1, funcLines[0])
						prog.RLock()

						fn, ok := prog.Search[wName][funcLines[0]]
						if ok {
							selectionLines := strings.Split(string(selection), "\n")
							if ((len(selectionLines) == 1) && (len(selectionLines[0]) == 0)) || ((s0 == f0) && (s1 == f1)) {
								dataChan <- fn.Text
							} else {
								buf.Reset()

								target := s0 - f0
								Assert(target >= 0)

								var count int
								var nl int
								for count < target {
									newline := bytes.IndexRune(funcBody[count:], '\n')
									Assert(newline >= 0)

									count += newline + 1
									nl++
								}
								Assert(count == target)

								selectionBegin := nl
								selectionEnd := nl + len(selectionLines)

								for s := selectionBegin; s < selectionEnd; s++ {
									sl := funcLines[s]

									likes, ok := funcLinesSearch[sl]
									Assert(ok)

									candidates_, ok := fn.LinesSearch[sl]
									if ok {
										var candidates []int
										candidates = append(candidates, candidates_...)
										if len(likes) > 1 {
											var selectedLike int
											for i := 0; i < len(likes); i++ {
												if likes[i] == s {
													selectedLike = i
												}
											}
											if len(candidates) == len(likes) {
												save := candidates[selectedLike]
												candidates = candidates[:0]
												candidates = append(candidates, save)
											} else {
												var maxLikeness int
												var mostLikedCandidates []int

												const window = 5
												for i := 0; i < len(candidates); i++ {
													var likeness int
													c := candidates[i]

													fl := likes[selectedLike]
													for j := c; (j < len(fn.Lines)) && (j < c+window) && (fl < len(funcLines)); j++ {
														for len(strings.TrimSpace(funcLines[fl])) == 0 {
															fl++
														}
														if funcLines[fl] == fn.Lines[j].GoLine {
															likeness++
														}
														fl++
													}

													if likeness > maxLikeness {
														maxLikeness = likeness
														mostLikedCandidates = mostLikedCandidates[:0]
													}
													if likeness == maxLikeness {
														mostLikedCandidates = append(mostLikedCandidates, c)
													}
												}

												if len(mostLikedCandidates) > 0 {
													candidates = append(candidates[:0], mostLikedCandidates...)
												}
											}
										}
										for i := 0; i < len(candidates); i++ {
											c := candidates[i]
											if c+1 < len(fn.Lines) {
												if _, ok := funcLinesSearch[fn.Lines[c+1].GoLine]; !ok {
													candidates = ints.InsertAt(candidates, c+1, i+1)
												}
											}
										}
										for i := 0; i < len(candidates); i++ {
											c := candidates[i]
											line := fn.Lines[c]

											allNOPs := true
											for j := 0; (j < len(line.AsmLines)) && (allNOPs); j++ {
												allNOPs = (allNOPs) && (strings.Index(line.AsmLines[j], "NOP") > 0)
											}
											if allNOPs {
												for j := c + 1; j < len(fn.Lines); j++ {
													if _, ok := funcLinesSearch[fn.Lines[j].GoLine]; !ok {
														var found bool
														for k := 0; k < len(candidates); k++ {
															if j == candidates[k] {
																found = true
															}
														}
														if !found {
															candidates = ints.InsertAt(candidates, j, i+1)
														}
														break
													}
												}
											}
										}
										for i := 0; i < len(candidates); i++ {
											line := &fn.Lines[candidates[i]]

											buf.WriteString(line.GoLine)
											buf.WriteRune('\n')
											for j := 0; j < len(line.AsmLines); j++ {
												buf.WriteString(line.AsmLines[j])
												buf.WriteRune('\n')
											}
										}
									}
								}

								/*
									for i := 0; i < len(fn.Lines); i++ {
										fmt.Fprintf(&buf, "%5d: %s\n", i, fn.Lines[i].GoLine)
									}
								*/

								dataChan <- buf.Bytes()
							}
						}

						prog.RUnlock()
					}
				}
			}

			time.Sleep(200 * time.Millisecond)
		}
	}
}

func MonitorWindows(prog *Program, dataChan chan<- []byte) {
	windows := make(map[int]*WinInfo)

	for {
		ws, err := acme.Windows()
		if err != nil {
			// log.Fatalf("Failed to get acme windows: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		for i := 0; i < len(ws); i++ {
			w := ws[i]

			if info, ok := windows[w.ID]; ok {
				if info.Name != w.Name {
					info.Name = w.Name
					info.NameChan <- w.Name
				}
			} else {
				if strings.HasSuffix(w.Name, ".go") {
					nameChan := make(chan string, 1)
					nameChan <- w.Name
					windows[w.ID] = &WinInfo{Name: w.Name, NameChan: nameChan}
					go MonitorWindow(w.ID, prog, nameChan, dataChan)
				}
			}
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func ParseFunction(buf []byte, fn *Function) {
	Assert(bytes.HasPrefix(buf, []byte(Prefix)))
	buf = buf[len(Prefix)+1:]

	newline := bytes.IndexRune(buf, '\n')
	Assert(newline >= 0)

	space := bytes.IndexRune(buf[:newline], ' ')
	if space == -1 {
		space = newline - 1
	}
	fn.Name = string(buf[:space])
	fn.File = string(buf[space+1 : newline])
	buf = buf[newline+1:]

	fn.Text = buf

	var goLine int
	var asmBegin, asmEnd int

	lines := strings.Split(string(buf), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		hasPrefix := strings.HasPrefix(line, "  0x")
		if !hasPrefix {
			asmEnd = i
			if asmEnd > 0 {
				fn.Lines = append(fn.Lines, Line{GoLine: lines[goLine], AsmLines: lines[asmBegin:asmEnd]})
			}
			goLine = i
			asmBegin = i + 1
		}
	}
	fn.Lines = append(fn.Lines, Line{GoLine: lines[goLine], AsmLines: lines[asmBegin:len(lines)]})

	fn.LinesSearch = make(map[string][]int)
	for i := 0; i < len(fn.Lines); i++ {
		fn.LinesSearch[fn.Lines[i].GoLine] = append(fn.LinesSearch[fn.Lines[i].GoLine], i)
	}
}

func UpdateDisassembly(prog *Program) {
	prog.Lock()
	defer prog.Unlock()

	cmd := exec.Command("go", "tool", "objdump", "-S", prog.Name)
	disas, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to get disassembly output: %v", err)
	}
	prog.Disassembly = disas

	var end int
	for {
		begin := bytes.Index(disas, []byte(Prefix))
		Assert(begin >= 0)

		newline := bytes.IndexRune(disas[begin+1:], '\n')
		Assert(newline >= 0)
		newline += begin + 1

		end = bytes.Index(disas[begin+1:], []byte(Suffix))
		end += begin + 1

		if newline == end {
			end = bytes.Index(disas[newline+1:], []byte(Suffix))
			if end == -1 {
				end = len(disas) - begin
			} else {
				end += newline + 1
			}
		}

		var fn Function
		ParseFunction(disas[begin:end], &fn)
		prog.Functions = append(prog.Functions, fn)

		if end+2 > len(disas) {
			break
		}
		disas = disas[end+2:]
	}

	prog.Search = make(map[string]map[string]*Function)
	for i := 0; i < len(prog.Functions); i++ {
		fn := &prog.Functions[i]

		m := prog.Search[fn.File]
		if m == nil {
			prog.Search[fn.File] = make(map[string]*Function)
		}

		prog.Search[fn.File][fn.Lines[0].GoLine] = fn
	}
}

func MonitorProgram(prog *Program) {
	for {
		st, err := os.Stat(prog.Name)
		if err != nil {
			log.Fatalf("Failed to get stat of the program: %v", err)
		}

		lastModified := st.ModTime()
		if lastModified.After(prog.LastModified) {
			prog.LastModified = lastModified
			UpdateDisassembly(prog)
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func main() {
	pwd, _ := os.Getwd()
	if pwd[len(pwd)-1] == '/' {
		pwd = pwd[:len(pwd)-1]
	}

	win, err := acme.New()
	if err != nil {
		log.Fatalf("Failed to create new acme window: %v", err)
	}
	win.Name(pwd + "/+acmeas")

	name := "./acmeas"
	if len(os.Args) == 2 {
		name = os.Args[1]
	}

	prog := Program{Name: name}
	go MonitorProgram(&prog)

	dataChan := make(chan []byte)
	go MonitorWindows(&prog, dataChan)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		win.Del(true)
		os.Exit(0)
	}()

	eventChan := win.EventChan()
	var quit bool
	for !quit {
		select {
		case event := <-eventChan:
			switch event.C2 {
			case 'x', 'X': /* execute. */
				if string(event.Text) == "Del" {
					win.Del(true)
					quit = true
				}
			}
			win.WriteEvent(event)
		case data := <-dataChan:
			win.Addr(",")
			win.Write("data", data)
			win.Ctl("clean")
			win.Addr("#0")
			win.Ctl("dot=addr")
			win.Ctl("show")
		}
	}
}
