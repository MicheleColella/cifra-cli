package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

// newMergeCmd is the git merge driver for .cifra/secrets.enc, registered by
// `cifra init` (see internal/git/mergedriver.go). It is hidden git plumbing —
// users never call it directly; git invokes it as `cifra merge %O %A %B`.
func newMergeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "merge <base> <ours> <theirs>",
		Short:  "internal git merge driver for .cifra/secrets.enc",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			return runMerge(args[0], args[1], args[2])
		},
	}
}

// runMerge is the ciphertext-only 3-way merge driver. It reuses MergeStores (the
// same logic runPull uses) — it NEVER decrypts and NEVER re-wraps; re-wrapping
// for the current recipients stays a deliberate, key-aware step in `cifra push`.
// On success it writes the merged store to oursPath (git's %A) and exits 0. On an
// irresolvable conflict it writes nothing (leaving %A intact) and returns an
// error so git marks the file unresolved for manual resolution (`cifra pull`).
func runMerge(basePath, oursPath, theirsPath string) error {
	base, err := readStoreFile(basePath)
	if err != nil {
		return fmt.Errorf("read merge base: %w", err)
	}
	ours, err := readStoreFile(oursPath)
	if err != nil {
		return fmt.Errorf("read ours: %w", err)
	}
	theirs, err := readStoreFile(theirsPath)
	if err != nil {
		return fmt.Errorf("read theirs: %w", err)
	}

	merged, warnings, conflicts := vault.MergeStores(base, ours, theirs)

	for _, w := range warnings {
		_, _ = fmt.Fprintf(ui.Err, "cifra merge: %s (%s): %s\n", w.Name, w.Kind, w.Message)
	}

	if len(conflicts) > 0 {
		msgs := make([]string, len(conflicts))
		for i, c := range conflicts {
			msgs[i] = fmt.Sprintf("  [%s (%s)] %s", c.Name, c.Kind, c.Reason)
		}
		return fmt.Errorf(
			"cifra merge: irresolvable secret-level conflict(s) in %s — resolve manually (e.g. `cifra pull`) and rotate affected secrets:\n%s",
			oursPath, strings.Join(msgs, "\n"),
		)
	}

	data, err := vault.MarshalStore(merged)
	if err != nil {
		return fmt.Errorf("encode merged store: %w", err)
	}
	if err := os.WriteFile(oursPath, data, 0o600); err != nil {
		return fmt.Errorf("write merged store to %s: %w", oursPath, err)
	}
	return nil
}

// readStoreFile parses a secrets store from a file git handed the driver. An
// empty file (git writes one for a side that added the entry set from nothing)
// parses as an empty store rather than a JSON error.
func readStoreFile(path string) (*vault.Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return &vault.Store{Version: 1}, nil
	}
	return vault.ParseStore(data)
}
