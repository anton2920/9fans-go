//go:build !plan9

package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

func FindRCExecutable() string {
	// Find the plan9port rc.
	// There may be a different rc in the PATH,
	// but there probably won't be a different 9.
	// Don't just invoke 9, because it will change
	// the PATH.
	var rc string
	if dir := os.Getenv("PLAN9"); dir != "" {
		rc = filepath.Join(dir, "bin/rc")
	} else if nine, err := exec.LookPath("9"); err == nil {
		rc = filepath.Join(filepath.Dir(nine), "rc")
	} else {
		rc = "/usr/local/plan9/bin/rc"
	}
	return rc
}
