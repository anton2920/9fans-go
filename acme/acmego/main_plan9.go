//go:build plan9

package main

import "os/exec"

// Non-Go formatters (only loaded with -f option).
var otherFormatters = map[string][]string{
	".c": []string{"cb", "-s"},
	".h": []string{"cb", "-s"},
}

func ExecDiff(name, tmp string) *exec.Cmd {
	return exec.Command("diff", name, tmp)
}
