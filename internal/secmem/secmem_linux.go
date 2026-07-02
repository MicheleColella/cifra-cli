//go:build linux

package secmem

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/MicheleColella/envault-cli/internal/ui"
)

func lock(buf []byte) {
	if len(buf) == 0 {
		return
	}
	if err := unix.Mlock(buf); err != nil {
		_, _ = fmt.Fprintf(ui.Err, "warning: mlock failed, secret buffer may be paged to swap: %v\n", err)
		return
	}
	// Best-effort: exclude the page range from core dumps. Not fatal if
	// unsupported (older kernels) — mlock already succeeded.
	_ = unix.Madvise(buf, unix.MADV_DONTDUMP)
}

func unlock(buf []byte) {
	if len(buf) == 0 {
		return
	}
	_ = unix.Munlock(buf)
}
