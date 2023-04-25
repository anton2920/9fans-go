//go:build !plan9
// +build !plan9

package plumb

import (
	"github.com/anton2920/9fans-go/plan9/client"
)

func mountPlumb() {
	fsys, fsysErr = client.MountService("plumb")
}
