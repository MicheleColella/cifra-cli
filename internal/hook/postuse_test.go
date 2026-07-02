package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MicheleColella/cifra-cli/internal/agent"
	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/vault"
)

func TestMaskSecrets_ReplacesPlaintext(t *testing.T) {
	secrets := []secretValue{
		{Name: "DB_PASSWORD", Plaintext: []byte("s3cr3t!")},
	}
	input := `{"output": "Connected with password s3cr3t!"}`
	masked, names := maskSecrets(input, secrets)

	if strings.Contains(masked, "s3cr3t!") {
		t.Error("plaintext still present after masking")
	}
	if !strings.Contains(masked, "<CIFRA:DB_PASSWORD>") {
		t.Error("placeholder not inserted")
	}
	if len(names) != 1 || names[0] != "DB_PASSWORD" {
		t.Errorf("unexpected replaced names: %v", names)
	}
}

func TestMaskSecrets_ReplacesBase64Variant(t *testing.T) {
	secrets := []secretValue{
		{Name: "API_KEY", Plaintext: []byte("mysecret")},
	}
	// base64("mysecret") = "bXlzZWNyZXQ="
	input := `token: bXlzZWNyZXQ=`
	masked, names := maskSecrets(input, secrets)

	if strings.Contains(masked, "bXlzZWNyZXQ=") {
		t.Error("base64 secret still present after masking")
	}
	if !strings.Contains(masked, "<CIFRA:API_KEY|base64>") {
		t.Errorf("base64 placeholder not inserted; got: %s", masked)
	}
	if len(names) == 0 {
		t.Error("expected at least one replaced name")
	}
}

func TestMaskSecrets_NoMatchPassesThrough(t *testing.T) {
	secrets := []secretValue{
		{Name: "DB_PASSWORD", Plaintext: []byte("s3cr3t!")},
	}
	input := `{"output": "hello world"}`
	masked, names := maskSecrets(input, secrets)

	if masked != input {
		t.Errorf("unmodified text should pass through unchanged; got %q", masked)
	}
	if len(names) != 0 {
		t.Errorf("expected no replaced names, got %v", names)
	}
}

func TestMaskSecrets_EmptySecrets(t *testing.T) {
	input := `some output`
	masked, names := maskSecrets(input, nil)
	if masked != input || len(names) != 0 {
		t.Error("empty secrets should result in pass-through")
	}
}

func TestMaskSecrets_MultipleSecrets(t *testing.T) {
	secrets := []secretValue{
		{Name: "DB_PASS", Plaintext: []byte("pass1")},
		{Name: "API_KEY", Plaintext: []byte("key2")},
	}
	input := `db=pass1 key=key2`
	masked, names := maskSecrets(input, secrets)

	if strings.Contains(masked, "pass1") || strings.Contains(masked, "key2") {
		t.Error("secrets still present after masking")
	}
	if len(names) != 2 {
		t.Errorf("expected 2 replaced names, got %d: %v", len(names), names)
	}
}

func TestMaskSecrets_EmptyPlaintextSkipped(t *testing.T) {
	secrets := []secretValue{
		{Name: "EMPTY", Plaintext: []byte("")},
	}
	input := `some output`
	masked, _ := maskSecrets(input, secrets)
	if masked != input {
		t.Error("empty secret should not modify output")
	}
}

// ---- RunHookPostuse via the key-unlock agent (no CIFRA_PASSPHRASE) -------

// withTestAgentSocket points the agent package's fixed socket path at a
// short-path temp dir for the test (see internal/agent's own tests for why
// t.TempDir() is too long on macOS), and unsets CIFRA_PASSPHRASE so any
// masking in the test can only succeed via the agent.
func withTestAgentSocket(t *testing.T) {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "cifra-hook-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	oldHome := os.Getenv("HOME")
	oldPass := os.Getenv("CIFRA_PASSPHRASE")
	_ = os.Setenv("HOME", home)
	_ = os.Unsetenv("CIFRA_PASSPHRASE")
	t.Cleanup(func() {
		_ = os.Setenv("HOME", oldHome)
		_ = os.Setenv("CIFRA_PASSPHRASE", oldPass)
		_ = os.RemoveAll(home)
	})
}

func TestRunHookPostuse_MasksViaAgent_NoPassphraseNeeded(t *testing.T) {
	withTestAgentSocket(t)

	ln, err := agent.Listen()
	if err != nil {
		t.Fatalf("agent.Listen: %v", err)
	}
	go agent.Serve(ln)
	t.Cleanup(func() { _ = ln.Close() })

	dir := t.TempDir()
	if _, err := vault.Init(dir, "", false); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}

	priv, pub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	const id = "alice@example.com"
	if err := vault.AddRecipient(dir, vault.Recipient{ID: id, PublicKey: pub}); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

	env, err := envcrypto.Seal([]byte("topsecretvalue"), []envcrypto.PublicKey{pub}, envcrypto.AES256GCM)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	store, _ := vault.LoadStore(dir)
	store = store.Upsert(vault.Entry{
		Name: "MY_SECRET", Kind: vault.KindEnv, Algorithm: envcrypto.AES256GCM,
		Recipients: []string{id}, Envelope: env,
	})
	if err := vault.SaveStore(dir, store); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}

	if err := agent.Unlock(id, priv[:], time.Minute); err != nil {
		t.Fatalf("agent.Unlock: %v", err)
	}

	origWd, _ := os.Getwd()
	_ = os.Chdir(dir)
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	input := map[string]interface{}{
		"tool_name":     "Bash",
		"tool_input":    map[string]interface{}{"command": "env"},
		"tool_response": "MY_SECRET=topsecretvalue",
	}
	b, _ := json.Marshal(input)
	var w bytes.Buffer

	err = RunHookPostuse(bytes.NewReader(b), &w)
	if err != ErrBlockToolCall {
		t.Fatalf("expected ErrBlockToolCall (masked output produced), got: %v", err)
	}
	if strings.Contains(w.String(), "topsecretvalue") {
		t.Errorf("secret plaintext leaked into masked output: %s", w.String())
	}
	if !strings.Contains(w.String(), "<CIFRA:MY_SECRET>") {
		t.Errorf("expected placeholder in masked output, got: %s", w.String())
	}
}

// ---- findMaskingKey ----

func TestFindMaskingKey_NoAgentNoPassphrase(t *testing.T) {
	withTestAgentSocket(t) // ensures CIFRA_PASSPHRASE is unset; no agent listening

	_, ok := findMaskingKey([]vault.Recipient{{ID: "nobody@example.com"}})
	if ok {
		t.Fatal("expected false with no agent running and no CIFRA_PASSPHRASE")
	}
}

func TestFindMaskingKey_PassphraseSetButKeychainUnavailable(t *testing.T) {
	withTestAgentSocket(t)
	t.Setenv("CIFRA_PASSPHRASE", "irrelevant")
	t.Setenv("PATH", t.TempDir()) // no OS keychain backend reachable

	_, ok := findMaskingKey([]vault.Recipient{{ID: "nobody@example.com"}})
	if ok {
		t.Fatal("expected false when the keychain backend is unavailable")
	}
}

func TestFindMaskingKey_PassphraseSetNoMatchingRecipient(t *testing.T) {
	withTestAgentSocket(t)
	t.Setenv("CIFRA_PASSPHRASE", "some-passphrase")

	// PATH is left as-is: on darwin this reaches the real `security` CLI,
	// which simply won't have this id — a legitimate ErrNotFound path,
	// exercised without touching any real key material.
	_, ok := findMaskingKey([]vault.Recipient{{ID: "definitely-not-a-real-recipient-id"}})
	if ok {
		t.Fatal("expected false for a recipient id with no matching keychain entry")
	}
}
