//go:build !plan9

package acme

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/anton2920/9fans-go/plan9"
	"github.com/anton2920/9fans-go/plan9/client"
)

func mountAcme() {
	fs, err := client.MountService("acme")
	fsys = fs
	fsysErr = err
}

// A LogReader provides read access to the acme log file.
type LogReader struct {
	f   *client.Fid
	buf [8192]byte
}

// Log returns a reader reading the acme/log file.
func Log() (*LogReader, error) {
	fsysOnce.Do(mountAcme)
	if fsysErr != nil {
		return nil, fsysErr
	}
	f, err := fsys.Open("log", plan9.OREAD)
	if err != nil {
		return nil, err
	}
	return &LogReader{f: f}, nil
}

// Read reads an event from the acme log file.
func (r *LogReader) Read() (LogEvent, error) {
	n, err := r.f.Read(r.buf[:])
	if err != nil {
		return LogEvent{}, err
	}
	f := strings.SplitN(string(r.buf[:n]), " ", 3)
	if len(f) != 3 {
		return LogEvent{}, fmt.Errorf("malformed log event")
	}
	id, _ := strconv.Atoi(f[0])
	op := f[1]
	name := f[2]
	name = strings.TrimSpace(name)
	return LogEvent{id, op, name}, nil
}

func (r *LogReader) Close() error {
	return r.f.Close()
}
