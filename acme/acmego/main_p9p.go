//go:build !plan9

package main

import "os/exec"

func ExecDiff(name, tmp string) *exec.Cmd {
	return exec.Command("9", "diff", name, tmp)
}
