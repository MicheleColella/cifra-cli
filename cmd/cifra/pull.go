package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/git"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newPullCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pull",
		Short: "Pull the latest encrypted vault from the Git remote",
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runPull(wd)
		},
	}
}

func runPull(repoRoot string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	before, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	if err := git.FetchOrigin(repoRoot); err != nil {
		return err
	}

	if err := git.CleanVault(repoRoot); err != nil {
		return err
	}

	mergeErr := git.MergeOrigin(repoRoot)
	if mergeErr != nil {
		if !errors.Is(mergeErr, git.ErrMergeConflict) {
			return mergeErr
		}
		// secrets.enc conflicted — attempt a structured entry-level merge.
		warnings, err := resolveSecretsConflict(repoRoot)
		if err != nil {
			_ = git.AbortMerge(repoRoot)
			return err
		}
		if err := git.ContinueMerge(repoRoot); err != nil {
			_ = git.AbortMerge(repoRoot)
			return fmt.Errorf("finalize merge: %w", err)
		}
		for _, w := range warnings {
			ui.Warn(w)
		}
	}

	after, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	changes := vault.DiffStores(before, after)
	if changes.IsEmpty() {
		ui.OK("Vault is up to date")
		return nil
	}

	ui.OK(fmt.Sprintf("Vault pulled  (%d change(s))", changes.Total()))
	if len(changes.Added) > 0 {
		ui.Info(fmt.Sprintf("added    %s", strings.Join(changes.Added, ", ")))
	}
	if len(changes.Removed) > 0 {
		ui.Info(fmt.Sprintf("removed  %s", strings.Join(changes.Removed, ", ")))
	}
	if len(changes.Rotated) > 0 {
		ui.Info(fmt.Sprintf("rotated  %s", strings.Join(changes.Rotated, ", ")))
	}
	return nil
}

// resolveSecretsConflict handles a merge conflict that involves secrets.enc.
// It reads the three stages from the git index, performs a secret-level 3-way
// merge, writes the result, and stages the file. Returns informational warnings
// (e.g., a recipient losing access). Returns an error when:
//   - non-vault files also conflict (caller must resolve manually)
//   - entry-level conflicts are irresolvable (both sides modified the same secret)
func resolveSecretsConflict(repoRoot string) ([]string, error) {
	conflicted, err := git.ConflictedFiles(repoRoot)
	if err != nil {
		return nil, err
	}

	hasSecretsConflict := false
	var otherConflicts []string
	secretsPath := filepath.ToSlash(filepath.Join(vault.DirName, "secrets.enc"))

	for _, f := range conflicted {
		if filepath.ToSlash(f) == secretsPath {
			hasSecretsConflict = true
		} else {
			otherConflicts = append(otherConflicts, f)
		}
	}

	if len(otherConflicts) > 0 {
		return nil, fmt.Errorf(
			"merge conflicts in non-vault files — resolve manually: %s",
			strings.Join(otherConflicts, ", "),
		)
	}
	if !hasSecretsConflict {
		return nil, fmt.Errorf(
			"unexpected merge state — ErrMergeConflict raised but no conflict found in %s",
			secretsPath,
		)
	}

	base, err := loadConflictStore(repoRoot, 1, secretsPath, "merge base")
	if err != nil {
		return nil, err
	}
	ours, err := loadConflictStore(repoRoot, 2, secretsPath, "ours")
	if err != nil {
		return nil, err
	}
	theirs, err := loadConflictStore(repoRoot, 3, secretsPath, "theirs")
	if err != nil {
		return nil, err
	}

	merged, warnings, entryConflicts := vault.MergeStores(base, ours, theirs)
	if len(entryConflicts) > 0 {
		msgs := make([]string, len(entryConflicts))
		for i, c := range entryConflicts {
			msgs[i] = fmt.Sprintf("  [%s (%s)] %s", c.Name, c.Kind, c.Reason)
		}
		return nil, fmt.Errorf(
			"irresolvable secret-level conflicts — rotate affected secrets after resolving:\n%s",
			strings.Join(msgs, "\n"),
		)
	}

	if err := vault.SaveStore(repoRoot, merged); err != nil {
		return nil, fmt.Errorf("save merged store: %w", err)
	}
	if err := git.StageFile(repoRoot, secretsPath); err != nil {
		return nil, fmt.Errorf("stage resolved secrets: %w", err)
	}

	warnMsgs := make([]string, len(warnings))
	for i, w := range warnings {
		warnMsgs[i] = fmt.Sprintf("%s (%s): %s", w.Name, w.Kind, w.Message)
	}
	return warnMsgs, nil
}

// loadConflictStore reads secrets.enc at a git merge stage and parses it.
// Returns an empty store when the file was absent at that stage (nil data from
// ConflictStage). A parse failure on non-nil data is surfaced as an error.
func loadConflictStore(repoRoot string, stage int, path, label string) (*vault.Store, error) {
	data, err := git.ConflictStage(repoRoot, stage, path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if data == nil {
		return &vault.Store{Version: 1}, nil
	}
	s, err := vault.ParseStore(data)
	if err != nil {
		return nil, fmt.Errorf("parse secrets.enc at stage %q: %w", label, err)
	}
	return s, nil
}
