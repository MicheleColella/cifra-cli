package vault

import (
	"errors"
	"testing"
	"time"
)

func sampleStore() *Store {
	return &Store{
		Version: storeVersion,
		Entries: []Entry{{
			Name:      "API_KEY",
			Kind:      KindEnv,
			Algorithm: "AES256GCM",
			CreatedAt: time.Unix(0, 0).UTC(),
			UpdatedAt: time.Unix(0, 0).UTC(),
		}},
	}
}

func TestMarshalStore_RoundTrip(t *testing.T) {
	data, err := MarshalStore(sampleStore())
	if err != nil {
		t.Fatalf("MarshalStore: %v", err)
	}
	if data[len(data)-1] != '\n' {
		t.Error("MarshalStore output must end with a trailing newline")
	}
	back, err := ParseStore(data)
	if err != nil {
		t.Fatalf("ParseStore(MarshalStore(...)): %v", err)
	}
	if len(back.Entries) != 1 || back.Entries[0].Name != "API_KEY" {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestParseStore_RejectsConflictMarkers(t *testing.T) {
	valid, _ := MarshalStore(sampleStore())

	corrupt := [][]byte{
		[]byte("<<<<<<< HEAD\n" + string(valid) + "=======\n" + string(valid) + ">>>>>>> theirs\n"),
		append([]byte("<<<<<<< ours\n"), valid...),
		[]byte(string(valid) + "\n>>>>>>> theirs\n"),
	}
	for i, data := range corrupt {
		_, err := ParseStore(data)
		if !errors.Is(err, ErrConflictMarkers) {
			t.Errorf("case %d: expected ErrConflictMarkers, got %v", i, err)
		}
	}

	// A base64 field that merely contains these byte runs mid-line must NOT trip it.
	if hasConflictMarkers([]byte(`{"ct":"a=======b<<<<<<< c"}`)) {
		t.Error("mid-line marker-like bytes should not be treated as a conflict marker")
	}
}
