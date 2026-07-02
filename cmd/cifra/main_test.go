package main

import "testing"

// resolveVersion must prefer the ldflags-injected value (make build / GoReleaser)
// over the build-info fallback.
func TestResolveVersionPrefersLdflags(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "v1.2.3"
	if got := resolveVersion(); got != "v1.2.3" {
		t.Fatalf("resolveVersion() = %q, want v1.2.3", got)
	}
}
