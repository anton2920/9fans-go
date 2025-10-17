package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/anton2920/9fans-go/acme"
)

type Event struct {
	*acme.Win
	Name string
	Q0   int
	Q1   int
}

type WinInfo struct {
	Name     string
	NameChan chan<- string
}

func ProcessEvents(win *acme.Win, disas []byte, eventsChan <-chan Event) {
	for event := range eventsChan {
		w := event.Win
		wID := w.ID()
		wName := event.Name

		q0 := event.Q0

		w.Addr("-/^/,/$\\n/")
		m0, m1, err := w.ReadAddr()
		if err != nil {
			log.Fatalf("[%d]: failed to get address: %v", wID, err)
		}
		if m0 > q0 {
			w.Addr("#0,#%d", m1)
		}
		selection, err := w.ReadAll("xdata")
		if err != nil {
			log.Fatalf("[%d]: failed to read all selected contents: %v", wID, err)
		}
		selectionLines := strings.Split(string(selection), "\n")
		_ = selectionLines

		w.Ctl("addr=dot")
		w.Addr("-/^func.* {/,/^}/")
		funcBody, err := w.ReadAll("xdata")
		if err != nil {
			log.Fatalf("[%d]: failed to read func body: %v", wID, err)
		}
		if len(funcBody) == 0 {
			continue
		}
		funcLines := strings.Split(string(funcBody), "\n")

		funcBegin := bytes.Index(disas, []byte(fmt.Sprintf("%s\n%s", wName, funcLines[0])))
		if funcBegin == -1 {
			continue
		}
		funcEnd := bytes.Index(disas[funcBegin:], []byte("TEXT"))
		if funcEnd == -1 {
			funcEnd = len(disas) - funcBegin
		}

		win.Addr(",")
		win.Write("data", disas[funcBegin:funcBegin+funcEnd])
		win.Ctl("clean")
		win.Addr("#0")
		win.Ctl("dot=addr")
		win.Ctl("show")
	}
}

func MonitorWindow(wID int, nameChan <-chan string, eventsChan chan<- Event) {
	var wName string
	var ok bool

	w, err := acme.Open(wID, nil)
	if err != nil {
		log.Fatalf("[%d]: failed to open window: %v", wID, err)
	}
	defer w.CloseFiles()

	w.ReadAddr()
	var q0, q1 int

	for {
		select {
		default:
			w.Ctl("addr=dot")
			m0, m1, err := w.ReadAddr()
			if err != nil {
				log.Fatalf("[%d]: failed to read address: %v", wID, err)
			}

			if (m0 != q0) || (m1 != q1) {
				q0, q1 = m0, m1
				eventsChan <- Event{Win: w, Name: wName, Q0: q0, Q1: q1}
			}

			time.Sleep(200 * time.Millisecond)
		case wName, ok = <-nameChan:
			if !ok {
				return
			}
			fmt.Printf("[%d]: %s\n", wID, wName)
		}
	}
}

func MonitorWindows(eventsChan chan<- Event) {
	windows := make(map[int]*WinInfo)

	for {
		openWindows := make(map[int]struct{})

		ws, err := acme.Windows()
		if err != nil {
			log.Fatalf("Failed to get acme windows: %v", err)
		}
		for i := 0; i < len(ws); i++ {
			w := ws[i]

			openWindows[w.ID] = struct{}{}
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
					go MonitorWindow(w.ID, nameChan, eventsChan)
				}
			}
		}

		for id, info := range windows {
			if _, ok := openWindows[id]; !ok {
				close(info.NameChan)
				delete(windows, id)
			}
		}

		time.Sleep(200 * time.Millisecond)
	}
}

func main() {
	prog := "./acmeas"

	win, err := acme.New()
	if err != nil {
		log.Fatalf("Failed to create new acme window: %v", err)
	}

	pwd, _ := os.Getwd()
	if pwd[len(pwd)-1] == '/' {
		pwd = pwd[:len(pwd)-1]
	}
	win.Name(pwd + "/+acmeas")

	cmd := exec.Command("go", "tool", "objdump", "-S", prog)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to get cmd output: %v", err)
	}

	eventsChan := make(chan Event)
	go MonitorWindows(eventsChan)
	go ProcessEvents(win, out, eventsChan)

	lgr, err := acme.Log()
	for {
		ev, err := lgr.Read()
		if err != nil {
			log.Fatalf("Failed to read log event: %v", err)
		}
		_ = ev
		// fmt.Printf("%#v\n", ev)
	}
}
