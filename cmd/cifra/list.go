package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

// listEntry is the JSON representation of a vault entry for agent-mode output.
type listEntry struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List names and algorithms of all secrets in the vault",
		RunE: func(cmd *cobra.Command, _ []string) error {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get working directory: %w", err)
			}
			return runList(wd)
		},
	}
}

// listEntries loads the vault store and maps its entries to the agent-mode
// JSON shape. Shared by runList and the MCP cifra_list tool.
func listEntries(repoRoot string) ([]listEntry, error) {
	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return nil, err
	}
	entries := make([]listEntry, len(store.Entries))
	for i, e := range store.Entries {
		entries[i] = listEntry{
			Name:      e.Name,
			Kind:      string(e.Kind),
			Algorithm: strings.ToUpper(string(e.Algorithm)),
		}
	}
	return entries, nil
}

func runList(repoRoot string) error {
	if !vault.IsInitialized(repoRoot) {
		return fmt.Errorf("vault not initialized — run `cifra init` first")
	}

	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return err
	}

	if ui.AgentMode {
		entries, err := listEntries(repoRoot)
		if err != nil {
			return err
		}
		ui.JSONResult(entries)
		return nil
	}

	if len(store.Entries) == 0 {
		ui.Info("vault is empty — use `cifra add` or `cifra import` to add secrets")
		return nil
	}

	ui.Header(fmt.Sprintf("%d entry(ies) in vault", len(store.Entries)))
	for _, e := range store.Entries {
		ui.Info(fmt.Sprintf("  %-40s  %-8s  %s", e.Name, e.Kind, strings.ToUpper(string(e.Algorithm))))
	}
	return nil
}
