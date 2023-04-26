//go:build !plan9

package main

import "os/exec"

// Non-Go formatters (only loaded with -f option).
var otherFormatters = map[string][]string{
	".rs": []string{"rustfmt", "--emit", "stdout"},
}

func ExecDiff(name, tmp string) *exec.Cmd {
	return exec.Command("9", "diff", name, tmp)
}
