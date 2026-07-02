//go:build !linux && !darwin

package secmem

// No-op on platforms outside the darwin/linux release targets (see
// .goreleaser.yaml). Zeroing via Wipe still applies everywhere.
func lock(buf []byte)   {}
func unlock(buf []byte) {}
