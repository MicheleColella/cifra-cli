package main

import "runtime/debug"

// version is injected via ldflags by `make build` / GoReleaser. For `go install
// module@vX.Y.Z` (no ldflags) it stays "dev" and resolveVersion falls back to the
// module version embedded in the binary's build info.
var version = "dev"

func main() {
	Execute(resolveVersion())
}

func resolveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
