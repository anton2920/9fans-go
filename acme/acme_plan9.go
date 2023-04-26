//go:build plan9

package acme

import (
	"io/ioutil"
	"strings"
	"time"

	"github.com/anton2920/9fans-go/plan9"
	"github.com/anton2920/9fans-go/plan9/client"
)

func mountAcme() {
	// Already mounted at /mnt/acme
	fsys = &client.Fsys{Mtpt: "/mnt/acme"}
	fsysErr = nil
}

func GetMtime(f *client.Fid) (time.Time, error) {
	st, err := f.Stat()
	if err != nil {
		return time.Time{}, err
	}

	return st.ModTime(), nil
}

// A LogReader provides read access to the acme index file.
type LogReader struct {
	f            *client.Fid
	lastMtime    time.Time
	lastModified map[int]bool
}

// Log returns a reader reading the acme/index file.
// On Plan 9 there's no log file, so we have to work
// around using stat(2) and acme/index file.
func Log() (*LogReader, error) {
	fsysOnce.Do(mountAcme)
	if fsysErr != nil {
		return nil, fsysErr
	}
	f, err := fsys.Open("index", plan9.OREAD)
	if err != nil {
		return nil, err
	}
	return &LogReader{f: f, lastModified: make(map[int]bool)}, nil
}

func (r *LogReader) Read() (LogEvent, error) {
	for {
		time.Sleep(100 * time.Millisecond)

		mtime, err := GetMtime(r.f)
		if err != nil {
			return LogEvent{}, err
		}
		ok := mtime.After(r.lastMtime)
		r.lastMtime = mtime
		if !ok {
			continue
		}

		if _, err := r.f.Seek(0, 0); err != nil {
			return LogEvent{}, err
		}
		data, err := ioutil.ReadAll(r.f)
		if err != nil {
			return LogEvent{}, err
		}
		infos, err := ParseAcmeIndex(data)
		if err != nil {
			continue
		}
		for _, info := range infos {
			if info.IsDir {
				continue
			}

			if strings.HasSuffix(info.Name, "+watch") {
				continue
			}

			wasModified, ok := r.lastModified[info.ID]
			r.lastModified[info.ID] = info.IsModified
			if !ok {
				continue
			}
			if wasModified && !info.IsModified {
				return LogEvent{ID: info.ID, Op: "put", Name: info.Name}, nil
			}
		}
	}
}

func (r *LogReader) Close() error {
	return r.f.Close()
}
