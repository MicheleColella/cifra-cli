package secmem

// Lock pins buf's pages in RAM (best-effort) so they cannot be paged to swap,
// and excludes them from core dumps where the platform supports it. Failure
// (e.g. RLIMIT_MEMLOCK exceeded, common in containers) is logged to stderr
// and otherwise ignored — callers must not treat this as a hard requirement.
func Lock(buf []byte) {
	lock(buf)
}

// Unlock reverses Lock. Safe to call on a buffer that was never locked.
func Unlock(buf []byte) {
	unlock(buf)
}

// Wipe zeroes buf. It is the portable baseline required everywhere secret
// material is held (see the Zeroization invariant in CLAUDE.md) — Lock/Unlock
// are additive hardening on top of it, not a replacement for it.
func Wipe(buf []byte) {
	clear(buf)
}
