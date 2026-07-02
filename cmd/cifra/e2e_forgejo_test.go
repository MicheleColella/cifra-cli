//go:build e2e

// End-to-end integration tests (v0.9.5) that exercise real push/pull,
// multi-recipient re-wrapping, conflict resolution, and access revocation
// against a real Git server (Forgejo, Gitea's API-compatible fork) started
// in a container via testcontainers-go.
//
// Excluded from the default `go test ./...` by the `e2e` build tag — they need
// a Docker daemon, which GitHub Actions macOS runners don't have. Run them with
//
//	go test -tags=e2e ./cmd/cifra/...
//
// on a machine (or CI job) with Docker. SkipIfProviderIsNotHealthy turns a
// missing/unhealthy Docker into a skip, not a failure.
//
// ponytail: these drive the same git.*/vault.*/crypto.* functions the real
// commands use, but wire the private key through an in-memory keychain instead
// of the OS keychain — the OS keychain has its own tests, and keyctl/Keychain
// inside a CI container is a flake source unrelated to what this version proves.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	envcrypto "github.com/MicheleColella/cifra-cli/internal/crypto"
	"github.com/MicheleColella/cifra-cli/internal/git"
	"github.com/MicheleColella/cifra-cli/internal/ui"
	"github.com/MicheleColella/cifra-cli/internal/vault"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/forgejo"
)

const forgejoImage = "codeberg.org/forgejo/forgejo:11"

// forgejoServer holds the running instance and admin credentials shared by all
// subtests (container startup is the slow part — do it once).
type forgejoServer struct {
	base string // http://host:port
	user string
	pass string
}

func startForgejo(t *testing.T) forgejoServer {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t) // no Docker → skip, don't fail

	ctx := context.Background()
	ctr, err := forgejo.Run(ctx, forgejoImage)
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("start forgejo: %v", err)
	}

	base, err := ctr.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	return forgejoServer{base: base, user: ctr.AdminUsername(), pass: ctr.AdminPassword()}
}

// createRepo makes a fresh repo (auto-initialized so it has a default branch)
// via the Forgejo/Gitea REST API and returns an authenticated clone URL.
func (s forgejoServer) createRepo(t *testing.T, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name, "auto_init": true, "private": false})

	req, err := http.NewRequest(http.MethodPost, s.base+"/api/v1/user/repos", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build create-repo request: %v", err)
	}
	req.SetBasicAuth(s.user, s.pass)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create repo %q: %v", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create repo %q: status %d", name, resp.StatusCode)
	}

	u, err := url.Parse(s.base)
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	u.User = url.UserPassword(s.user, s.pass)
	u.Path = "/" + s.user + "/" + name + ".git"
	return u.String()
}

// clone checks out cloneURL into a temp dir with a git identity set.
func clone(t *testing.T, cloneURL, email, name string) string {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "clone", cloneURL, dir)
	mustGit(t, dir, "config", "user.email", email)
	mustGit(t, dir, "config", "user.name", name)
	return dir
}

// pushVault commits .cifra/ and pushes to origin — the transport half of
// runPush, without the OS-keychain rewrap step (done in-process by the tests).
func pushVault(t *testing.T, repo string) {
	t.Helper()
	if _, err := git.CommitVault(repo); err != nil && !errors.Is(err, git.ErrNothingToCommit) {
		t.Fatalf("commit vault: %v", err)
	}
	if err := git.PushOrigin(repo); err != nil {
		t.Fatalf("push vault: %v", err)
	}
}

func genKey(t *testing.T) (envcrypto.PrivateKey, envcrypto.PublicKey) {
	t.Helper()
	priv, pub, err := envcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return priv, pub
}

// TestForgejoE2E starts one Forgejo instance and runs the multi-user scenarios
// as subtests, each on its own server-side repo.
func TestForgejoE2E(t *testing.T) {
	// Silence command output; restore even on failure.
	ui.Out = &bytes.Buffer{}
	ui.Err = &bytes.Buffer{}
	t.Cleanup(func() {
		ui.Out = os.Stdout
		ui.Err = os.Stderr
	})

	srv := startForgejo(t)

	t.Run("multi_recipient_rewrap", func(t *testing.T) { testMultiRecipientRewrap(t, srv) })
	t.Run("conflict_resolution", func(t *testing.T) { testConflictResolution(t, srv) })
	t.Run("revocation_via_rotate", func(t *testing.T) { testRevocation(t, srv) })
}

// testMultiRecipientRewrap: alice seals a secret for herself, pushes; bob clones
// (can't decrypt yet); alice adds bob as recipient, re-wraps, pushes; bob pulls
// and can now decrypt — over a real remote.
func testMultiRecipientRewrap(t *testing.T, srv forgejoServer) {
	cloneURL := srv.createRepo(t, "rewrap")
	alice := clone(t, cloneURL, "alice@e2e.test", "Alice")

	if err := runInit(alice, false); err != nil {
		t.Fatalf("runInit alice: %v", err)
	}

	alicePriv, alicePub := genKey(t)
	bobPriv, bobPub := genKey(t)

	if err := vault.AddRecipient(alice, vault.Recipient{ID: "alice", PublicKey: [32]byte(alicePub)}); err != nil {
		t.Fatalf("add alice: %v", err)
	}

	entry, err := sealEntry("API_KEY", vault.KindEnv, []byte("s3cr3t-value"),
		[]envcrypto.PublicKey{alicePub}, []string{"alice"})
	if err != nil {
		t.Fatalf("sealEntry: %v", err)
	}
	store, _ := vault.LoadStore(alice)
	if err := vault.SaveStore(alice, store.Upsert(entry)); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}
	// Recipient set matches the entry → runPush needs no keychain; exercise it.
	if err := runPush(alice); err != nil {
		t.Fatalf("runPush alice: %v", err)
	}

	// Bob clones the alice-only vault: he must NOT be able to decrypt yet.
	bob := clone(t, cloneURL, "bob@e2e.test", "Bob")
	bobStore, _ := vault.LoadStore(bob)
	bobEntry := findEntry(t, bobStore, "API_KEY", vault.KindEnv)
	if _, err := envcrypto.Unseal(bobEntry.Envelope, bobPriv); err == nil {
		t.Fatal("bob decrypted before being added as recipient — access leak")
	}

	// Alice adds bob and re-wraps every entry for the new recipient set.
	if err := vault.AddRecipient(alice, vault.Recipient{ID: "bob", PublicKey: [32]byte(bobPub)}); err != nil {
		t.Fatalf("add bob: %v", err)
	}
	store, _ = vault.LoadStore(alice)
	n, rewrapped, err := rewrapStore(store, alicePriv,
		[]envcrypto.PublicKey{alicePub, bobPub}, []string{"alice", "bob"})
	if err != nil {
		t.Fatalf("rewrapStore: %v", err)
	}
	if n != 1 {
		t.Fatalf("rewrapped %d entries, want 1", n)
	}
	if err := vault.SaveStore(alice, rewrapped); err != nil {
		t.Fatalf("SaveStore rewrapped: %v", err)
	}
	pushVault(t, alice)

	// Bob pulls the re-wrapped vault and can now decrypt.
	if err := runPull(bob); err != nil {
		t.Fatalf("runPull bob: %v", err)
	}
	bobStore, _ = vault.LoadStore(bob)
	bobEntry = findEntry(t, bobStore, "API_KEY", vault.KindEnv)
	pt, err := envcrypto.Unseal(bobEntry.Envelope, bobPriv)
	if err != nil {
		t.Fatalf("bob Unseal after rewrap: %v", err)
	}
	if string(pt) != "s3cr3t-value" {
		t.Fatalf("bob decrypted %q, want %q", pt, "s3cr3t-value")
	}
}

// testConflictResolution: alice and bob diverge (each adds a different secret),
// bob's runPull hits a secrets.enc conflict and resolves it 3-way over a real
// remote — mirrors the local-bare test but across the network.
func testConflictResolution(t *testing.T, srv forgejoServer) {
	cloneURL := srv.createRepo(t, "conflict")
	alice := clone(t, cloneURL, "alice@e2e.test", "Alice")

	if err := runInit(alice, false); err != nil {
		t.Fatalf("runInit alice: %v", err)
	}
	now := time.Now().UTC()
	base := &vault.Store{Version: 1, Entries: []vault.Entry{
		{Name: "BASE_KEY", Kind: vault.KindEnv, UpdatedAt: now},
	}}
	saveTestStore(t, alice, base)
	pushVault(t, alice)

	// Bob clones the base vault.
	bob := clone(t, cloneURL, "bob@e2e.test", "Bob")

	// Alice adds KEY_A and pushes.
	saveTestStore(t, alice, &vault.Store{Version: 1, Entries: []vault.Entry{
		{Name: "BASE_KEY", Kind: vault.KindEnv, UpdatedAt: now},
		{Name: "KEY_A", Kind: vault.KindEnv, UpdatedAt: time.Now().UTC()},
	}})
	pushVault(t, alice)

	// Bob independently adds KEY_B and commits (diverged, not pushed).
	saveTestStore(t, bob, &vault.Store{Version: 1, Entries: []vault.Entry{
		{Name: "BASE_KEY", Kind: vault.KindEnv, UpdatedAt: now},
		{Name: "KEY_B", Kind: vault.KindEnv, UpdatedAt: time.Now().UTC()},
	}})
	mustGit(t, bob, "add", ".cifra/")
	mustGit(t, bob, "commit", "-m", "add KEY_B")

	// Bob pulls → conflict on secrets.enc → 3-way merge keeps all three.
	if err := runPull(bob); err != nil {
		t.Fatalf("runPull conflict: %v", err)
	}
	final, err := vault.LoadStore(bob)
	if err != nil {
		t.Fatalf("LoadStore after conflict: %v", err)
	}
	names := map[string]bool{}
	for _, e := range final.Entries {
		names[e.Name] = true
	}
	for _, want := range []string{"BASE_KEY", "KEY_A", "KEY_B"} {
		if !names[want] {
			t.Errorf("merged store missing %q; have %v", want, names)
		}
	}
}

// testRevocation: bob is a recipient and can decrypt; alice removes bob and
// rotates the secret (fresh DEK), pushes; bob pulls and can no longer decrypt
// the new ciphertext — true revocation over a real remote.
func testRevocation(t *testing.T, srv forgejoServer) {
	cloneURL := srv.createRepo(t, "revoke")
	alice := clone(t, cloneURL, "alice@e2e.test", "Alice")

	if err := runInit(alice, false); err != nil {
		t.Fatalf("runInit alice: %v", err)
	}
	alicePriv, alicePub := genKey(t)
	bobPriv, bobPub := genKey(t)

	if err := vault.AddRecipient(alice, vault.Recipient{ID: "alice", PublicKey: [32]byte(alicePub)}); err != nil {
		t.Fatalf("add alice: %v", err)
	}
	if err := vault.AddRecipient(alice, vault.Recipient{ID: "bob", PublicKey: [32]byte(bobPub)}); err != nil {
		t.Fatalf("add bob: %v", err)
	}
	entry, err := sealEntry("SECRET", vault.KindEnv, []byte("top-secret"),
		[]envcrypto.PublicKey{alicePub, bobPub}, []string{"alice", "bob"})
	if err != nil {
		t.Fatalf("sealEntry: %v", err)
	}
	store, _ := vault.LoadStore(alice)
	if err := vault.SaveStore(alice, store.Upsert(entry)); err != nil {
		t.Fatalf("SaveStore: %v", err)
	}
	if err := runPush(alice); err != nil {
		t.Fatalf("runPush alice: %v", err)
	}

	// Bob clones and confirms he currently has access.
	bob := clone(t, cloneURL, "bob@e2e.test", "Bob")
	bobStore, _ := vault.LoadStore(bob)
	bobEntry := findEntry(t, bobStore, "SECRET", vault.KindEnv)
	if pt, err := envcrypto.Unseal(bobEntry.Envelope, bobPriv); err != nil || string(pt) != "top-secret" {
		t.Fatalf("bob should decrypt before revocation: pt=%q err=%v", pt, err)
	}

	// Alice removes bob and rotates SECRET (new DEK, sealed only for alice).
	if err := vault.RemoveRecipient(alice, "bob"); err != nil {
		t.Fatalf("remove bob: %v", err)
	}
	kc := newMemStore()
	if err := kc.Seal("alice", alicePriv[:]); err != nil {
		t.Fatalf("seal alice key: %v", err)
	}
	if err := runRotate(alice, "SECRET", kc); err != nil {
		t.Fatalf("runRotate: %v", err)
	}
	pushVault(t, alice)

	// Bob pulls the rotated secret and can no longer decrypt it.
	if err := runPull(bob); err != nil {
		t.Fatalf("runPull bob: %v", err)
	}
	bobStore, _ = vault.LoadStore(bob)
	bobEntry = findEntry(t, bobStore, "SECRET", vault.KindEnv)
	if _, err := envcrypto.Unseal(bobEntry.Envelope, bobPriv); err == nil {
		t.Fatal("bob decrypted after revocation + rotation — revocation failed")
	}
	// Alice still can.
	if pt, err := envcrypto.Unseal(bobEntry.Envelope, alicePriv); err != nil || string(pt) != "top-secret" {
		t.Fatalf("alice should still decrypt after rotation: pt=%q err=%v", pt, err)
	}
}
