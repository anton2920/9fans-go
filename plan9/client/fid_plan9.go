//go:build plan9

package client

import (
	"os"
	"syscall"
)

type Fid struct {
	*os.File
}

func (fid *Fid) Write(b []byte) (n int, err error) {
	/* NOTE(anton2920): on Plan 9 (*os.File).Write doesn't allow zero-byte writes.
	 * syscall.Write, on the other hand, doesn't complain about that,
	 * so we use that, because we need it.
	 */
	return syscall.Write(int(fid.Fd()), b)
}
