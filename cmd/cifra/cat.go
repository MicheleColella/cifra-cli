package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func newCatCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "cat <KEY>",
		Short: "Decrypt a single secret to stdout (debug/migration only)",
		Long: "Decrypt a single secret and print its value to stdout.\n" +
			"A warning is written to stderr; the value goes to stdout so it can be piped.\n" +
			"Requires your private key to be available in the OS keychain.\n\n" +
			"In agent mode (CLAUDE_CODE=1 or --agent-safe) plaintext output is suppressed\n" +
			"to prevent secrets from appearing in the model context. Use --force to override,\n" +
			"or prefer `cifra run -- <cmd>` for in-memory injection.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kc, err := openKeychain()
			if err != nil {
				return err
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runCat(wd, args[0], kc, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "override agent-mode output masking (unsafe in AI contexts)")
	return cmd
}

func newExportCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Decrypt all env secrets to stdout in dotenv format (debug/migration only)",
		Long: "Decrypt all env secrets and print them to stdout as KEY=VALUE lines.\n" +
			"A warning is written to stderr; the values go to stdout so they can be piped.\n" +
			"Requires your private key to be available in the OS keychain.\n\n" +
			"In agent mode (CLAUDE_CODE=1 or --agent-safe) plaintext output is suppressed\n" +
			"to prevent secrets from appearing in the model context. Use --force to override,\n" +
			"or prefer `cifra run -- <cmd>` for in-memory injection.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			kc, err := openKeychain()
			if err != nil {
				return err
			}
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runExport(wd, kc, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "override agent-mode output masking (unsafe in AI contexts)")
	return cmd
}

func runCat(repoRoot, name string, kc keychain.Store, force bool) error {
	if ui.AgentMode && !force {
		return fmt.Errorf(
			"plaintext output suppressed in agent mode — use `cifra run -- <cmd>` for in-memory injection, or pass --force to override",
		)
	}

	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	var found *vault.Entry
	for i := range store.Entries {
		if store.Entries[i].Kind == vault.KindEnv && store.Entries[i].Name == name {
			e := store.Entries[i]
			found = &e
			break
		}
	}
	if found == nil {
		return fmt.Errorf("secret %q not found in vault", name)
	}

	priv, id, err := loadCurrentUserKey(repoRoot, kc)
	if err != nil {
		return err
	}
	defer clear(priv[:])

	_, _ = fmt.Fprintf(ui.Err, "! WARNING: decrypting %s as %s — plaintext will be visible in this terminal\n", name, id)

	plaintext, err := envcrypto.Unseal(found.Envelope, priv)
	if err != nil {
		return fmt.Errorf("decrypt %s: %w", name, err)
	}
	defer clear(plaintext)

	_, err = fmt.Fprintln(ui.Out, string(plaintext))
	return err
}

func runExport(repoRoot string, kc keychain.Store, force bool) error {
	if ui.AgentMode && !force {
		return fmt.Errorf(
			"plaintext output suppressed in agent mode — use `cifra run -- <cmd>` for in-memory injection, or pass --force to override",
		)
	}

	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	var envEntries []vault.Entry
	for _, e := range store.Entries {
		if e.Kind == vault.KindEnv {
			envEntries = append(envEntries, e)
		}
	}

	if len(envEntries) == 0 {
		ui.Info("no env secrets in vault")
		return nil
	}

	priv, id, err := loadCurrentUserKey(repoRoot, kc)
	if err != nil {
		return err
	}
	defer clear(priv[:])

	_, _ = fmt.Fprintf(ui.Err, "! WARNING: exporting %d secret(s) as %s — plaintext will be visible in this terminal\n", len(envEntries), id)

	for _, e := range envEntries {
		plaintext, err := envcrypto.Unseal(e.Envelope, priv)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", e.Name, err)
		}
		_, werr := fmt.Fprintf(ui.Out, "%s=%s\n", e.Name, string(plaintext))
		clear(plaintext)
		if werr != nil {
			return werr
		}
	}
	return nil
}
