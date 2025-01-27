// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Acmego watches acme for .go files being written.
//
// Usage:
//
//	acmego [-f]
//
// Each time a .go file is written, acmego checks whether the
// import block needs adjustment. If so, it makes the changes
// in the window body but does not write the file.
// It depends on “goimports” being installed.
//
// If the -f option is given, reformats the Go source file body
// as well as updating the imports. It also watches for other
// known extensions and runs their formatters if found in
// the executable path.
//
// The other known extensions and formatters are:
//
//	.c/.h  - cb (plan9)
//	.rs      - rustfmt (!plan9)
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/anton2920/9fans-go/acme"
)

var gofmt = flag.Bool("f", false, "format the entire file after Put")

var formatters = map[string][]string{
	".go": []string{"goimports"},
}

// Non-Go formatters (only loaded with -f option).
var otherFormatters = map[string][]string{
	".rs": []string{"rustfmt", "--emit", "stdout"},
	".c":  []string{"cb", "-s"},
	".h":  []string{"cb", "-s"},
	".l":  []string{"cb", "-s"},
}

func main() {
	flag.Parse()
	if *gofmt {
		for suffix, formatter := range otherFormatters {
			formatters[suffix] = formatter
		}
	}
	l, err := acme.Log()
	if err != nil {
		log.Fatal(err)
	}

	for {
		event, err := l.Read()
		if err != nil {
			log.Fatal(err)
		}
		if event.Name == "" || event.Op != "put" {
			continue
		}
		for suffix, formatter := range formatters {
			if strings.HasSuffix(event.Name, suffix) {
				reformat(event.ID, event.Name, formatter)
				break
			}
		}
	}
}

func reformat(id int, name string, formatter []string) {
	w, err := acme.Open(id, nil)
	if err != nil {
		log.Print(err)
		return
	}
	defer w.CloseFiles()

	old, err := ioutil.ReadFile(name)
	if err != nil {
		//log.Print(err)
		return
	}

	exe, err := exec.LookPath(formatter[0])
	if err != nil {
		// Formatter not installed.
		return
	}

	new, err := exec.Command(exe, append(formatter[1:], name)...).CombinedOutput()
	if err != nil {
		if strings.Contains(string(new), "fatal error") {
			fmt.Fprintf(os.Stderr, "goimports %s: %v\n%s", name, err, new)
		} else {
			fmt.Fprintf(os.Stderr, "%s", new)
		}
		return
	}

	if bytes.Equal(old, new) {
		return
	}

	if !*gofmt {
		oldTop, err := readImports(bytes.NewReader(old), true)
		if err != nil {
			//log.Print(err)
			return
		}
		newTop, err := readImports(bytes.NewReader(new), true)
		if err != nil {
			//log.Print(err)
			return
		}
		if bytes.Equal(oldTop, newTop) {
			return
		}
		w.Addr("0,#%d", utf8.RuneCount(oldTop))
		w.Write("data", newTop)
		return
	}

	f, err := ioutil.TempFile("", "acmego")
	if err != nil {
		log.Print(err)
		return
	}
	if _, err := f.Write(new); err != nil {
		log.Print(err)
		return
	}
	tmp := f.Name()
	f.Close()
	defer os.Remove(tmp)

	diff, _ := ExecDiff(name, tmp).CombinedOutput()

	latest, err := w.ReadAll("body")
	if err != nil {
		log.Print(err)
		return
	}
	if !bytes.Equal(old, latest) {
		log.Printf("skipped update to %s: window modified since Put\n", name)
		return
	}

	w.Write("ctl", []byte("mark"))
	w.Write("ctl", []byte("nomark"))
	diffLines := strings.Split(string(diff), "\n")
	for i := len(diffLines) - 1; i >= 0; i-- {
		line := diffLines[i]
		if line == "" {
			continue
		}
		if line[0] == '<' || line[0] == '-' || line[0] == '>' {
			continue
		}
		j := 0
		for j < len(line) && line[j] != 'a' && line[j] != 'c' && line[j] != 'd' {
			j++
		}
		if j >= len(line) {
			log.Printf("cannot parse diff line: %q", line)
			break
		}
		oldStart, oldEnd := parseSpan(line[:j])
		newStart, newEnd := parseSpan(line[j+1:])
		if newStart == 0 || (oldStart == 0 && line[j] != 'a') {
			continue
		}
		switch line[j] {
		case 'a':
			err := w.Addr("%d+#0", oldStart)
			if err != nil {
				log.Print(err)
				break
			}
			w.Write("data", findLines(new, newStart, newEnd))
		case 'c':
			err := w.Addr("%d,%d", oldStart, oldEnd)
			if err != nil {
				log.Print(err)
				break
			}
			w.Write("data", findLines(new, newStart, newEnd))
		case 'd':
			err := w.Addr("%d,%d", oldStart, oldEnd)
			if err != nil {
				log.Print(err)
				break
			}
			w.Write("data", nil)
		}
	}
	if !bytes.HasSuffix(old, nlBytes) && bytes.HasSuffix(new, nlBytes) {
		// plan9port diff doesn't report a difference if there's a mismatch in the
		// final newline, so add one if needed.
		if err := w.Addr("$"); err != nil {
			log.Print(err)
			return
		}
		w.Write("data", nlBytes)
	}
}

var nlBytes = []byte("\n")

func parseSpan(text string) (start, end int) {
	i := strings.Index(text, ",")
	if i < 0 {
		n, err := strconv.Atoi(text)
		if err != nil {
			log.Printf("cannot parse span %q", text)
			return 0, 0
		}
		return n, n
	}
	start, err1 := strconv.Atoi(text[:i])
	end, err2 := strconv.Atoi(text[i+1:])
	if err1 != nil || err2 != nil {
		log.Printf("cannot parse span %q", text)
		return 0, 0
	}
	return start, end
}

func findLines(text []byte, start, end int) []byte {
	i := 0

	start--
	for ; i < len(text) && start > 0; i++ {
		if text[i] == '\n' {
			start--
			end--
		}
	}
	startByte := i
	for ; i < len(text) && end > 0; i++ {
		if text[i] == '\n' {
			end--
		}
	}
	endByte := i
	return text[startByte:endByte]
}
