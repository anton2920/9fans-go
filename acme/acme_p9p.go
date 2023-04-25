//go:build !plan9
// +build !plan9

package acme

import "github.com/anton2920/9fans-go/plan9/client"

func mountAcme() {
	fs, err := client.MountService("acme")
	fsys = fs
	fsysErr = err
}
