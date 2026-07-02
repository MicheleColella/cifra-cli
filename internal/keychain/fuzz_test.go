package keychain

import (
	"errors"
	"testing"
)

// FuzzUnseal verifies that protectedStore.Unseal never panics regardless of
// what bytes happen to be sitting in the OS keychain — a corrupted blob (disk
// error, another process racing envault, an attacker probing the format)
// must always surface a typed error, never crash the CLI or misread garbage
// as key material.
func FuzzUnseal(f *testing.F) {
	inner := newMemStore()
	valid := NewProtected(inner, fixedPass("fuzz-passphrase"))
	if err := valid.Seal("seed-v2", randomKeyBytes()); err != nil {
		f.Fatalf("Seal: %v", err)
	}

	f.Add(inner.data["seed-v2"])                                           // valid v2 blob
	f.Add(make([]byte, 32))                                                // legacy raw key
	f.Add([]byte{})                                                        // empty
	f.Add([]byte(`{"v":2}`))                                               // truncated v2 envelope
	f.Add([]byte(`{"v":3,"kdf":"argon2id","salt":"AA","ct":"AA"}`))        // unknown version
	f.Add([]byte(`not json at all`))                                       // garbage
	f.Add([]byte(`{"v":2,"kdf":"argon2id","salt":"","nonce":"","ct":""}`)) // empty fields

	f.Fuzz(func(t *testing.T, raw []byte) {
		store := &memStore{data: map[string][]byte{"fuzz": raw}}
		protected := NewProtected(store, fixedPass("fuzz-passphrase"))

		key, err := protected.Unseal("fuzz")

		if err == nil {
			return // legacy or valid v2 blob happened to decrypt cleanly — fine
		}
		if key != nil {
			t.Fatalf("Unseal returned a non-nil key alongside an error: %v", err)
		}
		if !errors.Is(err, ErrBadPassphrase) && !errors.Is(err, ErrUnsupportedKeyVersion) && !errors.Is(err, ErrNotFound) {
			t.Fatalf("unexpected error type for malformed blob: %v", err)
		}
	})
}

// FuzzClassifyKeyBlob verifies classifyKeyBlob never panics on arbitrary
// bytes and only ever reports blobProtectedV2 for something that actually
// parses as our v2 JSON envelope with non-empty salt and ciphertext.
func FuzzClassifyKeyBlob(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 33))
	f.Add([]byte(`{"v":2,"kdf":"argon2id","salt":"AAAA","nonce":"AAAA","ct":"AAAA"}`))
	f.Add([]byte(`{"v":2}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		blob, kind := classifyKeyBlob(raw)
		switch kind {
		case blobProtectedV2:
			if blob.V != protectedVersion || len(blob.Salt) == 0 || len(blob.CT) == 0 {
				t.Fatalf("classified as v2 but header/fields incomplete: %+v", blob)
			}
		case blobLegacyRaw:
			if len(raw) != x25519KeyLen {
				t.Fatalf("classified as legacy but length is %d, want %d", len(raw), x25519KeyLen)
			}
		case blobUnsupported:
			// always a safe classification — nothing to assert further.
		default:
			t.Fatalf("unknown blobKind %d", kind)
		}
	})
}

func randomKeyBytes() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}
