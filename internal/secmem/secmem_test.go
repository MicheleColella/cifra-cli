package secmem

import "testing"

func TestLockUnlockDoesNotPanic(t *testing.T) {
	buf := make([]byte, 32)
	Lock(buf)
	Unlock(buf)
}

func TestLockUnlockEmptyBuffer(t *testing.T) {
	Lock(nil)
	Unlock(nil)
}

func TestWipeZeroesBuffer(t *testing.T) {
	buf := []byte{1, 2, 3, 4}
	Wipe(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d not wiped: %d", i, b)
		}
	}
}
