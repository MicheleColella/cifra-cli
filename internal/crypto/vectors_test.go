package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// mustHex decodes a hex string, fatally failing the test on error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestAEAD_Vector_AES256GCM pins AES-256-GCM against NIST SP 800-38D test vectors.
// Any change to the AEAD construction or algorithm will cause these to fail.
func TestAEAD_Vector_AES256GCM(t *testing.T) {
	vectors := []struct {
		name  string
		key   string
		nonce string
		pt    string
		ad    string
		// Go's AEAD.Seal returns ciphertext || tag concatenated.
		ctTag string
	}{
		{
			// NIST SP 800-38D, AES-256, 96-bit IV, 0-byte PT, 0-byte AAD, 128-bit Tag.
			name:  "empty-PT empty-AD",
			key:   "0000000000000000000000000000000000000000000000000000000000000000",
			nonce: "000000000000000000000000",
			pt:    "",
			ad:    "",
			ctTag: "530f8afbc74536b9a963b4f1c4cb738b",
		},
		{
			// NIST SP 800-38D, AES-256, 96-bit IV, 16-byte PT, 0-byte AAD.
			name:  "16-byte PT empty-AD",
			key:   "0000000000000000000000000000000000000000000000000000000000000000",
			nonce: "000000000000000000000000",
			pt:    "00000000000000000000000000000000",
			ad:    "",
			ctTag: "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
		},
		{
			// NIST SP 800-38D Test Case 4, AES-256: non-zero key, 60-byte PT, 20-byte AAD.
			// Pins the GHASH path when authenticated data is present.
			name:  "60-byte PT 20-byte AAD",
			key:   "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			nonce: "cafebabefacedbaddecaf888",
			pt: "d9313225f88406e5a55909c5aff5269a" +
				"86a7a9531534f7da2e4c303d8a318a72" +
				"1c3c0c95956809532fcf0e2449a6b525" +
				"b16aedf5aa0de657ba637b39",
			ad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			ctTag: "522dc1f099567d07f47f37a32a84427d" +
				"643a8cdcbfe5c0c97598a2bd2555d1aa" +
				"8cb08e48590dbb3da7b08b1056828838" +
				"c5f61e6393ba7a0abcc9f662" +
				"76fc6ece0f4e1768cddf8853bb2d551b",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustHex(t, v.key)
			nonce := mustHex(t, v.nonce)
			pt := mustHex(t, v.pt)
			ad := mustHex(t, v.ad)
			wantCTTag := mustHex(t, v.ctTag)

			aead, err := newAEAD(key, AES256GCM)
			if err != nil {
				t.Fatalf("newAEAD: %v", err)
			}

			got := aead.Seal(nil, nonce, pt, ad)
			if !bytes.Equal(got, wantCTTag) {
				t.Errorf("Seal:\n got  %x\n want %x", got, wantCTTag)
			}

			// Verify Open is the inverse of the pinned vector bytes (not just of Seal's output).
			plain, err := aead.Open(nil, nonce, wantCTTag, ad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(plain, pt) {
				t.Errorf("Open roundtrip: got %x, want %x", plain, pt)
			}
		})
	}
}

// TestAEAD_Vector_ChaCha20Poly1305 pins ChaCha20-Poly1305 against RFC 8439 §2.8.2.
func TestAEAD_Vector_ChaCha20Poly1305(t *testing.T) {
	// RFC 8439 §2.8.2 — IETF ChaCha20-Poly1305 (12-byte nonce).
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "070000004041424344454647")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	ad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	// 114-byte ciphertext followed by 16-byte Poly1305 tag.
	wantCTTag := mustHex(t,
		"d31a8d34648e60db7b86afbc53ef7ec2"+
			"a4aded51296e08fea9e2b5a736ee62d6"+
			"3dbea45e8ca9671282fafb69da92728b"+
			"1a71de0a9e060b2905d6a5b67ecd3b36"+
			"92ddbd7f2d778b8c9803aee328091b58"+
			"fab324e4fad675945585808b4831d7bc"+
			"3ff4def08e4b7a9de576d26586cec64b"+
			"6116"+ // end of 114-byte ciphertext
			"1ae10b594f09e26a7e902ecbd0600691", // 16-byte Poly1305 tag
	)

	aead, err := newAEAD(key, ChaCha20Poly1305)
	if err != nil {
		t.Fatalf("newAEAD: %v", err)
	}

	got := aead.Seal(nil, nonce, pt, ad)
	if !bytes.Equal(got, wantCTTag) {
		t.Errorf("ChaCha20-Poly1305 RFC 8439 vector:\n got  %x\n want %x", got, wantCTTag)
	}

	// Independently verify Open against the pinned vector bytes.
	plain, err := aead.Open(nil, nonce, wantCTTag, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(plain, pt) {
		t.Errorf("Open roundtrip mismatch")
	}
}

// TestEnvelopeAD_Format pins the authenticated-data string format.
// A change here would silently break decryption of existing envelopes.
func TestEnvelopeAD_Format(t *testing.T) {
	cases := []struct {
		version int
		suite   CipherSuite
		want    string
	}{
		{1, AES256GCM, "cifra|v1|aes-256-gcm"},
		{1, ChaCha20Poly1305, "cifra|v1|chacha20-poly1305"},
	}
	for _, c := range cases {
		got := string(envelopeAD(c.version, c.suite))
		if got != c.want {
			t.Errorf("envelopeAD(%d, %q) = %q, want %q", c.version, c.suite, got, c.want)
		}
	}
}
