package acme

import (
	"github.com/anton2920/9fans-go/plan9/client"
)

func mountAcme() {
	// Already mounted at /mnt/acme
	fsys = &client.Fsys{Mtpt: "/mnt/acme"}
	fsysErr = nil
}
