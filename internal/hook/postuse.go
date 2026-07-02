package hook

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/MicheleColella/cifra-cli/internal/agent"
	"github.com/MicheleColella/cifra-cli/internal/audit"
	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/keychain"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

// PostuseInput is the Claude Code PostToolUse hook JSON.
type PostuseInput struct {
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolResponse json.RawMessage `json:"tool_response"`
}

// RunHookPostuse reads Claude Code's PostToolUse JSON from r.
//
// If the current user's private key is available — via the key-unlock agent
// (internal/agent; no passphrase needed, see cifra agent unlock) or, failing
// that, CIFRA_PASSPHRASE — decrypts all KindEnv vault secrets and scans the
// tool response for their plaintext values (and base64-encoded variants),
// replacing each match with a structured placeholder
// `<CIFRA:NAME>` (or `<CIFRA:NAME|base64>`) before writing to w and exiting
// with code 2 so Claude Code uses the masked output instead of the original.
//
// When neither key source is available, or the vault is absent, the function
// returns nil (pass-through), logging the skip to the audit log.
func RunHookPostuse(r io.Reader, w io.Writer) error {
	var input PostuseInput
	if err := json.NewDecoder(r).Decode(&input); err != nil {
		return nil
	}

	wd, err := os.Getwd()
	if err != nil || !IsCifraDir(wd) {
		return nil
	}

	secrets, err := loadSecretsForMasking(wd)
	if err != nil || len(secrets) == 0 {
		return nil
	}

	// Stringify the tool response for scanning.
	responseStr := string(input.ToolResponse)
	masked, names := maskSecrets(responseStr, secrets)

	if len(names) == 0 {
		return nil // nothing to mask — pass through
	}

	for _, name := range names {
		_ = audit.AppendEntry(wd, input.ToolName, audit.ActionMasked, name, "")
	}

	// Write masked response to w. Exit 2 causes Claude Code to use our output
	// instead of the original tool response, preventing plaintext from entering
	// the model context.
	_, _ = fmt.Fprint(w, masked)
	return ErrBlockToolCall // caller must exit 2
}

// secretValue pairs an env-var name with its decrypted plaintext.
type secretValue struct {
	Name      string
	Plaintext []byte
}

// loadSecretsForMasking finds the current user's private key (agent cache,
// falling back to CIFRA_PASSPHRASE) and decrypts all KindEnv entries,
// returning their plaintext values. Caller must not store the returned
// slices beyond the call lifetime.
func loadSecretsForMasking(repoRoot string) ([]secretValue, error) {
	store, err := vault.LoadStore(repoRoot)
	if err != nil {
		return nil, err
	}

	recipients, err := vault.ListRecipients(repoRoot)
	if err != nil {
		return nil, err
	}

	priv, found := findMaskingKey(recipients)
	if !found {
		return nil, nil
	}
	defer clear(priv[:])

	var out []secretValue
	for _, e := range store.Entries {
		if e.Kind != vault.KindEnv {
			continue
		}
		pt, err := envcrypto.Unseal(e.Envelope, priv)
		if err != nil {
			continue
		}
		out = append(out, secretValue{Name: e.Name, Plaintext: pt})
	}
	return out, nil
}

// findMaskingKey locates the current user's private key among recipients.
// postuse runs headless (no TTY), so it can never prompt interactively —
// it prefers the key-unlock agent's cache (no passphrase needed) and falls
// back to CIFRA_PASSPHRASE-based keychain decryption, the same fallback
// order as the passphrase-vs-agent choice everywhere else in the CLI.
func findMaskingKey(recipients []vault.Recipient) (envcrypto.PrivateKey, bool) {
	var priv envcrypto.PrivateKey

	for _, rec := range recipients {
		if key, ok := agent.TryGet(rec.ID); ok && len(key) == 32 {
			copy(priv[:], key)
			clear(key)
			return priv, true
		}
	}

	passphrase := os.Getenv("CIFRA_PASSPHRASE")
	if passphrase == "" {
		return priv, false
	}

	kc, err := keychain.New()
	if err != nil {
		return priv, false
	}
	askFunc := func(_ string) ([]byte, error) { return []byte(passphrase), nil }
	protected := keychain.NewProtected(kc, askFunc)

	for _, rec := range recipients {
		raw, err := protected.Unseal(rec.ID)
		if err != nil {
			continue
		}
		if len(raw) == 32 {
			copy(priv[:], raw)
			clear(raw)
			return priv, true
		}
		clear(raw)
	}
	return priv, false
}

// maskSecrets scans text for each secret's plaintext (and its base64 variant)
// and replaces matches with structured placeholders.
// Returns the masked text and the names of secrets that were replaced.
func maskSecrets(text string, secrets []secretValue) (string, []string) {
	var replaced []string
	result := text
	for _, s := range secrets {
		if len(s.Plaintext) == 0 {
			continue
		}
		plain := string(s.Plaintext)
		b64 := base64.StdEncoding.EncodeToString(s.Plaintext)

		placeholderB64 := fmt.Sprintf("<CIFRA:%s|base64>", s.Name)
		placeholderPlain := fmt.Sprintf("<CIFRA:%s>", s.Name)

		newText := strings.ReplaceAll(result, b64, placeholderB64)
		if newText != result {
			replaced = append(replaced, s.Name)
			result = newText
		}
		newText = strings.ReplaceAll(result, plain, placeholderPlain)
		if newText != result {
			if len(replaced) == 0 || replaced[len(replaced)-1] != s.Name {
				replaced = append(replaced, s.Name)
			}
			result = newText
		}
	}
	return result, replaced
}
