package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

// runFilter controls which KindEnv entries are injected.
// If only is non-empty, inject only those keys.
// If except is non-empty (and only is empty), inject all except those keys.
// Both flags are mutually exclusive at the command level.
type runFilter struct {
	only   []string
	except []string
}

func newRunCmd() *cobra.Command {
	var onlyFlag, exceptFlag []string

	cmd := &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Inject decrypted secrets and execute a command",
		Long: "Decrypt env secrets into memory and run the given command with them\n" +
			"injected as environment variables. Secrets are never written to disk\n" +
			"and are zeroed from memory when the command exits.\n\n" +
			"Use -- to separate cifra flags from the child command:\n" +
			"  cifra run -- npm start\n" +
			"  cifra run --only DB_URL,API_KEY -- go test ./...",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(onlyFlag) > 0 && len(exceptFlag) > 0 {
				return fmt.Errorf("--only and --except are mutually exclusive")
			}
			kc, err := openKeychain()
			if err != nil {
				return fmt.Errorf("open keychain: %w", err)
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			err = runRun(wd, args, kc, runFilter{only: onlyFlag, except: exceptFlag})
			var ece exitCodeError
			if errors.As(err, &ece) {
				os.Exit(ece.code)
			}
			return err
		},
	}

	cmd.Flags().StringSliceVar(&onlyFlag, "only", nil, "comma-separated keys to inject (default: all)")
	cmd.Flags().StringSliceVar(&exceptFlag, "except", nil, "comma-separated keys to skip")

	return cmd
}

// exitCodeError carries the exit code of a child process so the parent can
// exit with the same code after all deferred cleanup has run.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// runRun decrypts KindEnv secrets (subject to f), injects them into the child
// environment, and runs args[0] with args[1:]. The original plaintext byte
// slices are zeroed via defer before the function returns. The derived Go
// strings in childEnv share the same logical content and cannot be zeroed
// without unsafe; they are released to the GC after exec completes.
// A non-zero child exit code is returned as exitCodeError.
func runRun(repoRoot string, args []string, kc keychain.Store, f runFilter) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	envEntries := selectEnvEntries(store, f)

	priv, id, err := loadCurrentUserKey(repoRoot, kc)
	if err != nil {
		return err
	}
	defer clear(priv[:])

	ui.Info(fmt.Sprintf("decrypting %d secret(s) in memory as %s…", len(envEntries), id))

	extraEnv, plaintexts, err := decryptEnvEntries(envEntries, priv)
	if err != nil {
		return err
	}
	defer func() {
		for _, pt := range plaintexts {
			clear(pt)
		}
	}()

	ui.OK(fmt.Sprintf("injected %d env var(s) — 0 bytes written to disk", len(envEntries)))

	// Merge parent env with vault secrets; vault entries override duplicates.
	// Pre-size to avoid the realloc that append(os.Environ(), ...) would cause.
	base := os.Environ()
	childEnv := make([]string, 0, len(base)+len(extraEnv))
	childEnv = append(childEnv, base...)
	childEnv = append(childEnv, extraEnv...)

	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec // user-supplied command is intentional
	cmd.Env = childEnv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %q: %w", args[0], err)
	}

	// Forward SIGINT and SIGTERM to the child so it can clean up.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	waitErr := cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitCodeError{exitErr.ExitCode()}
		}
		return waitErr
	}
	return nil
}

// selectEnvEntries returns the KindEnv entries of store that pass filter f
// (only/except by name). Pure — no I/O, no decryption.
func selectEnvEntries(store *vault.Store, f runFilter) []vault.Entry {
	onlySet := toSet(f.only)
	exceptSet := toSet(f.except)

	var envEntries []vault.Entry
	for _, e := range store.Entries {
		if e.Kind != vault.KindEnv {
			continue
		}
		if onlySet != nil {
			if _, ok := onlySet[e.Name]; !ok {
				continue
			}
		} else if exceptSet != nil {
			if _, ok := exceptSet[e.Name]; ok {
				continue
			}
		}
		envEntries = append(envEntries, e)
	}
	return envEntries
}

// decryptEnvEntries unseals every entry in envEntries with priv and returns
// them as "KEY=value" env lines plus the raw plaintexts (caller must clear()
// each one once done). On error, plaintexts decrypted so far are cleared
// before returning.
func decryptEnvEntries(envEntries []vault.Entry, priv envcrypto.PrivateKey) ([]string, [][]byte, error) {
	plaintexts := make([][]byte, len(envEntries))
	extraEnv := make([]string, len(envEntries))

	for i, e := range envEntries {
		pt, err := envcrypto.Unseal(e.Envelope, priv)
		if err != nil {
			for j := 0; j < i; j++ {
				clear(plaintexts[j])
			}
			return nil, nil, fmt.Errorf("decrypt %s: %w", e.Name, err)
		}
		plaintexts[i] = pt
		extraEnv[i] = fmt.Sprintf("%s=%s", e.Name, string(pt))
	}
	return extraEnv, plaintexts, nil
}

func toSet(keys []string) map[string]struct{} {
	if len(keys) == 0 {
		return nil
	}
	s := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		s[strings.TrimSpace(k)] = struct{}{}
	}
	return s
}
