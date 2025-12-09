package main

import (
	stdbytes "bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	stdstrings "strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anton2920/gofa/bytes"
	"github.com/anton2920/gofa/ints"
	"github.com/anton2920/gofa/strings"

	"github.com/anton2920/9fans-go/acme"
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

	LineByAddr map[int64]*Line
	FuncByName map[string]*Function
	FuncByFile map[string]map[string]*Function
}

type WinInfo struct {
	Name     string
	NameChan chan string
}

type HistoryItem struct {
	Body []byte
	Q0   int
	Q1   int
}

const Prefix = "TEXT"

var Epoch uint64

func Assert(p bool) {
	if !p {
		panic("ASSERTION FAILED")
	}
}

func FindReference(win *acme.Win, event *acme.Event, prog *Program, dataChan chan<- []byte) ([]byte, bool) {
	win.Addr("#%d-/ /,#%d/,|	/", event.Q0, event.Q1)
	data, err := win.ReadAll("xdata")
	if (err != nil) || (len(data) <= 2) {
		return nil, false
	}
	selection := stdstrings.Trim(stdstrings.TrimSpace(bytes.AsString(data)), ",")

	fn, ok := prog.FuncByName[selection]
	if ok {
		return fn.Text, true
	}

	win.Addr("#0")
	contents, err := win.ReadAll("data")
	if err != nil {
		return nil, false
	}
	if stdbytes.Count(contents, data) > 1 {
		return nil, false
	}

	addr, err := strconv.ParseInt(selection[2:], 16, 64)
	if err != nil {
		return nil, false
	}
	line, ok := prog.LineByAddr[addr]
	if ok {
		var buf stdbytes.Buffer

		buf.WriteString(line.GoLine)
		buf.WriteRune('\n')
		for i := 0; i < len(line.AsmLines); i++ {
			buf.WriteString(line.AsmLines[i])
			buf.WriteRune('\n')
		}

		return buf.Bytes(), true
	}

	return nil, false
}

func GetSelectionDisassembly(prog *Program, filename string, funcLines []string, selectionLines []string, selectAll bool) []byte {
	fn, ok := prog.FuncByFile[filename][funcLines[0]]
	if ok {
		funcLinesSearch := make(map[string][]int)
		for i := 0; i < len(funcLines); i++ {
			funcLinesSearch[funcLines[i]] = append(funcLinesSearch[funcLines[i]], i)
		}

		if (selectAll) || ((len(selectionLines) == 1) && (len(selectionLines[0]) == 0)) {
			return fn.Text
		} else {
			var buf stdbytes.Buffer

			var nl int
			for i := 0; i < len(funcLines); i++ {
				if selectionLines[0] == funcLines[i] {
					nl = i
					break
				}
			}

			for s := nl; s < nl+len(selectionLines); s++ {
				sl := funcLines[s]

				/* Get indicies into 'funcLines' of all lines that exactly match selected line. */
				likes, ok := funcLinesSearch[sl]
				Assert(ok)

				/* Get indicies into 'fn.Lines' of all disassebly lines that exactly match selected line. */
				candidates_, ok := fn.LinesSearch[sl]
				if ok {
					var candidates []int
					candidates = append(candidates, candidates_...)

					/* If there are multiple copies of selected line, we need to find the best candidates among disassembly lines. */
					if len(likes) > 1 {
						/* If there are the same number of copies of selected line as disassembly candidates, it probably means that they have one-to-one correspondence with each other. */
						if len(candidates) == len(likes) {
							var selectedLike int
							for i := 0; i < len(likes); i++ {
								if likes[i] == s {
									selectedLike = i
								}
							}
							save := candidates[selectedLike]
							candidates = candidates[:0]
							candidates = append(candidates, save)
						} else { /* Else find the most likely candidates by trying to match some lines after selected with some line after a candidate one-by-one. Leave only candidates that matches the most. */
							var maxLikeness int
							var mostLikedCandidates []int

							const window = 5
							for i := 0; i < len(candidates); i++ {
								var likeness int
								c := candidates[i]

								fl := s
								for j := c; (j < len(fn.Lines)) && (j < c+window) && (fl < len(funcLines)); j++ {
									for len(stdstrings.TrimSpace(funcLines[fl])) == 0 {
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

					/* Add next line of disassembly to candidates, if it does not appear anywhere in the program (most likely function has been inlined). */
					for i := 0; i < len(candidates); i++ {
						c := candidates[i]
						if c+1 < len(fn.Lines) {
							if _, ok := funcLinesSearch[fn.Lines[c+1].GoLine]; !ok {
								candidates = ints.InsertAt(candidates, c+1, i+1)
							}
						}
					}

					/* Find closest disassembly line that does not appear anywhere in the program and add it to candidates, if all current line does are NOPs (most likely function has been inlined). */
					for i := 0; i < len(candidates); i++ {
						c := candidates[i]
						line := fn.Lines[c]

						allNOPs := true
						for j := 0; (j < len(line.AsmLines)) && (allNOPs); j++ {
							allNOPs = (allNOPs) && (stdstrings.Index(line.AsmLines[j], "NOP") > 0)
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

					/* Display all disassembly candidates .*/
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

			return buf.Bytes()
		}
	}

	return nil
}

func MonitorWindow(wID int, prog *Program, nameChan <-chan string, dataChan chan<- []byte) {
	var wName string
	var epoch uint64

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
				if (m0 != s0) || (m1 != s1) || (atomic.LoadUint64(&Epoch) != epoch) {
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
						funcLines := stdstrings.Split(bytes.AsString(funcBody), "\n")
						selectionLines := stdstrings.Split(bytes.AsString(selection), "\n")
						// fmt.Printf("[%d]: s=#%d,#%d, f=#%d,#%d %s\n", wID, s0, s1, f0, f1, funcLines[0])

						prog.RLock()
						disas := GetSelectionDisassembly(prog, wName, funcLines, selectionLines, (s0 == f0) && (s1 == f1))
						if len(disas) > 0 {
							epoch = atomic.LoadUint64(&Epoch) + 1
							dataChan <- disas
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
				if stdstrings.HasSuffix(w.Name, ".go") {
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
	Assert(stdbytes.HasPrefix(buf, []byte(Prefix)))
	buf = buf[len(Prefix)+1:]

	newline := stdbytes.IndexRune(buf, '\n')
	Assert(newline >= 0)

	space := stdbytes.IndexRune(buf[:newline], ' ')
	if space == -1 {
		space = newline - 1
	}
	fn.Name = bytes.AsString(buf[:space])
	fn.File = bytes.AsString(buf[space+1 : newline])
	buf = buf[newline+1:]

	fn.Text = buf

	var goLine int
	var asmBegin, asmEnd int

	lines := stdstrings.Split(bytes.AsString(buf), "\n")
	for i := 0; i < len(lines)-1; i++ {
		if len(lines[i]) == 0 {
			lines = strings.RemoveAt(lines, i)
			i--
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		hasPrefix := strings.StartsWith(line, "  0x")
		if !hasPrefix {
			asmEnd = i
			if asmEnd > 0 {
				fn.Lines = append(fn.Lines, Line{GoLine: lines[goLine], AsmLines: lines[ints.Or(asmBegin, goLine+1):asmEnd]})
			}
			goLine = i
			asmBegin = i + 1
		}
	}
	fn.Lines = append(fn.Lines, Line{GoLine: lines[goLine], AsmLines: lines[ints.Or(asmBegin, goLine+1):len(lines)]})

	fn.LinesSearch = make(map[string][]int)
	for i := 0; i < len(fn.Lines); i++ {
		fn.LinesSearch[fn.Lines[i].GoLine] = append(fn.LinesSearch[fn.Lines[i].GoLine], i)
	}
}

func UpdateDisassembly(prog *Program) {
	prog.Lock()
	defer prog.Unlock()

	prog.Disassembly = nil
	prog.FuncByName = nil
	prog.LineByAddr = nil
	prog.FuncByFile = nil
	runtime.GC()

	cmd := exec.Command("go", "tool", "objdump", "-S", prog.Name)
	disas, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to get disassembly output: %v", err)
	}
	prog.Disassembly = disas
	prog.LineByAddr = make(map[int64]*Line)
	prog.FuncByName = make(map[string]*Function)

	var end int
	for {
		begin := stdbytes.Index(disas, []byte(Prefix))
		Assert(begin >= 0)

		end = stdbytes.Index(disas[begin+1:], []byte(Prefix))
		if end == -1 {
			end = len(disas)
		} else {
			end += begin + 1
		}

		var fn Function
		ParseFunction(disas[begin:end], &fn)
		prog.FuncByName[fn.Name] = &fn

		for i := 0; i < len(fn.Lines); i++ {
			line := &fn.Lines[i]

			for j := 0; j < len(line.AsmLines); j++ {
				al := line.AsmLines[j][4:]
				addr, err := strconv.ParseInt(al[:stdstrings.IndexRune(al, '\t')], 16, 64)
				Assert(err == nil)
				prog.LineByAddr[addr] = line
			}
		}

		if end >= len(disas) {
			break
		}
		disas = disas[end:]
	}

	prog.FuncByFile = make(map[string]map[string]*Function)
	for _, fn := range prog.FuncByName {
		m := prog.FuncByFile[fn.File]
		if m == nil {
			prog.FuncByFile[fn.File] = make(map[string]*Function)
		}
		prog.FuncByFile[fn.File][fn.Lines[0].GoLine] = fn
	}
}

func MonitorProgram(prog *Program, dataChan chan<- []byte) {
	for {
		st, err := os.Stat(prog.Name)
		if err != nil {
			log.Fatalf("Failed to get stat of the program: %v", err)
		}

		lastModified := st.ModTime()
		if lastModified.After(prog.LastModified) {
			prog.LastModified = lastModified

			dataChan <- []byte("Updating disassembly...")
			UpdateDisassembly(prog)
			dataChan <- []byte("Ready!")
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func ClearTag(win *acme.Win) {
	win.Ctl("cleartag")
	win.Write("tag", []byte(" Look "))
}

func WriteBody(win *acme.Win, data []byte, q0 int, q1 int) {
	atomic.AddUint64(&Epoch, 1)
	win.Addr(",")
	win.Write("data", data)
	win.Ctl("clean")
	win.Addr("#%d,#%d", q0, q1)
	win.Ctl("dot=addr")
	win.Ctl("show")
}

func WinMode(prog *Program) error {
	win, err := acme.New()
	if err != nil {
		return fmt.Errorf("failed to create new acme window: %v", err)
	}
	defer win.CloseFiles()

	win.Name(filepath.Dir(prog.Name) + "/+acmeas")

	dataChan := make(chan []byte)
	go MonitorProgram(prog, dataChan)
	go MonitorWindows(prog, dataChan)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		win.Del(true)
		os.Exit(0)
	}()

	var history []HistoryItem
	var current int

	eventChan := win.EventChan()
	var quit bool
	for !quit {
		select {
		case event := <-eventChan:
			//fmt.Printf("C1=%q C2=%q Q=#%d,#%d OrigQ=#%d,#%d Flag=%d Nb=%d Nr=%d Text=%q Arg=%q Loc=%q\n", event.C1, event.C2, event.Q0, event.Q1, event.OrigQ0, event.OrigQ1, event.Flag, event.Nb, event.Nr, event.Text, event.Arg, event.Loc)
			switch event.C2 {
			case 'L': /* look. */
				if ref, ok := FindReference(win, event, prog, dataChan); ok {
					win.Addr("#0")
					data, err := win.ReadAll("data")
					if err != nil {
						continue
					}
					history = history[:current]
					history = append(history, HistoryItem{Body: data, Q0: event.Q0, Q1: event.Q1}, HistoryItem{Body: ref})
					current++

					ClearTag(win)
					win.Write("tag", []byte("Back "))

					WriteBody(win, ref, 0, 0)
					continue
				}
			case 'x', 'X': /* execute. */
				switch bytes.AsString(event.Text) {
				case "Back":
					if current > 0 {
						current--
						item := history[current]
						WriteBody(win, item.Body, item.Q0, item.Q1)
					}
				case "Forward":
					if current < len(history)-1 {
						current++
						item := history[current]
						WriteBody(win, item.Body, item.Q0, item.Q1)
					}
				case "Del":
					win.Del(true)
					quit = true
				}

				ClearTag(win)
				if current > 0 {
					win.Write("tag", []byte("Back "))
				}
				if current < len(history)-1 {
					win.Write("tag", []byte("Forward "))
				}
			}
			win.WriteEvent(event)
		case data := <-dataChan:
			history = history[:0]
			current = 0

			ClearTag(win)
			WriteBody(win, data, 0, 0)
		}
	}

	return nil
}

func HeadlessMode(prog *Program) error {
	UpdateDisassembly(prog)

	for i := 2; i < len(os.Args); i++ {
		target := os.Args[i]

		name, numbers, ok := stdstrings.Cut(target, ":")
		path, err := filepath.Abs(name)
		if err != nil {
			return fmt.Errorf("failed to resove path for %q: %v", name, err)
		}

		if !ok {
			funcs := prog.FuncByFile[path]
			for _, fn := range funcs {
				fmt.Printf("%s\n", fn.Text)
			}
		} else {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open file %q: %v", name, err)
			}

			contents, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("failed to read entire file %q: %v", name, err)
			}
			lines := stdstrings.Split(stdstrings.TrimSpace(bytes.AsString(contents)), "\n")

			begin, end, ok := stdstrings.Cut(numbers, "-")
			if !ok {
				end = begin
			}
			selectionBegin, err := strconv.Atoi(begin)
			if err != nil {
				return fmt.Errorf("invalid selection begin line number %q: %v", begin, err)
			}
			if (selectionBegin < 0) || (selectionBegin >= len(lines)) {
				return fmt.Errorf("selection begin line number is out of range [%d;%d]", 0, len(lines))
			}
			selectionEnd, err := strconv.Atoi(end)
			if err != nil {
				return fmt.Errorf("invalid selection end line number %q: %v", end, err)
			}
			if (selectionEnd < 0) || (selectionEnd >= len(lines)) {
				return fmt.Errorf("selection end line number is out of range [%d;%d]", 0, len(lines))
			}
			selectionLines := lines[selectionBegin-1 : selectionEnd]

			var funcBegin, funcEnd int
			for i := selectionBegin; i >= 0; i-- {
				if strings.StartsWith(lines[i], "func") {
					funcBegin = i
					break
				}
			}
			for i := selectionBegin; i < len(lines); i++ {
				if lines[i] == "}" {
					funcEnd = i + 1
					break
				}
			}
			funcLines := lines[funcBegin:funcEnd]

			if disas := GetSelectionDisassembly(prog, path, funcLines, selectionLines, false); len(disas) > 0 {
				fmt.Printf("%s\n", disas)
			}
		}
	}

	return nil
}

func main() {
	name := "./acmeas"
	if len(os.Args) >= 2 {
		name = os.Args[1]
	}

	path, err := filepath.Abs(name)
	if err != nil {
		log.Fatalf("Failed to get absolute path for program: %v", err)
	}
	prog := Program{Name: path}

	if len(os.Args) <= 2 {
		err = WinMode(&prog)
	} else {
		err = HeadlessMode(&prog)
	}
	if err != nil {
		log.Fatalf("acmeas: %v", err)
	}
}
