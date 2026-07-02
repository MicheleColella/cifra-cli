//go:build darwin

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
	// darwin has no MADV_DONTDUMP equivalent exposed via x/sys/unix — mlock
	// (swap protection) is the only control available here.
	if err := unix.Mlock(buf); err != nil {
		_, _ = fmt.Fprintf(ui.Err, "warning: mlock failed, secret buffer may be paged to swap: %v\n", err)
	}
}

func unlock(buf []byte) {
	if len(buf) == 0 {
		return
	}
	_ = unix.Munlock(buf)
}
