package agent

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func encodeKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

func decodeKey(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// detachProcess configures cmd to run in its own session, detached from the
// caller's controlling terminal, so it survives after the terminal closes.
// darwin and linux (this project's only targets) both support Setsid.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// dialTimeout bounds a single connection attempt to the agent socket.
const dialTimeout = 500 * time.Millisecond

// spawnRetryInterval/spawnMaxWait bound how long EnsureRunning waits for a
// freshly spawned agent process to start accepting connections.
const (
	spawnRetryInterval = 100 * time.Millisecond
	spawnMaxWait       = 2 * time.Second
)

// socketPathEnv overrides SocketPath when set, decoupled from $HOME. Tests
// and integration scripts use this to isolate the agent socket without also
// relocating where the OS keychain looks for its login keychain (which is
// itself derived from $HOME on macOS — overriding HOME to isolate the agent
// breaks `security` in the same process).
const socketPathEnv = "CIFRA_AGENT_SOCKET"

// SocketPath returns the fixed, per-user location of the agent socket:
// ~/.cifra/agent.sock (or $CIFRA_AGENT_SOCKET, if set). Not per-project
// — one agent serves every vault on the machine, the same way ssh-agent
// serves every repo.
func SocketPath() (string, error) {
	if p := os.Getenv(socketPathEnv); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".cifra", "agent.sock"), nil
}

func dial() (net.Conn, error) {
	path, err := SocketPath()
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("unix", path, dialTimeout)
}

func roundTrip(req request) (response, error) {
	conn, err := dial()
	if err != nil {
		return response{}, err
	}
	defer conn.Close() //nolint:errcheck

	b, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return response{}, err
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return response{}, fmt.Errorf("no response from agent")
	}
	var resp response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return response{}, err
	}
	return resp, nil
}

// TryGet asks the agent for the cached plaintext private key for id. Returns
// (nil, false) whenever the key isn't available for any reason — agent not
// running, id not cached, expired, or a transport error — so callers can
// silently fall back to the passphrase-protected keychain path. It never
// spawns an agent: only Unlock does that, since Get is on the read path used
// by every command and must stay a no-op when the user never opted in.
func TryGet(id string) ([]byte, bool) {
	resp, err := roundTrip(request{Cmd: "get", ID: id})
	if err != nil || !resp.OK {
		return nil, false
	}
	key, err := decodeKey(resp.Key)
	if err != nil {
		return nil, false
	}
	return key, true
}

// Unlock hands key (the decrypted private key for id) to the agent, caching
// it for ttl. Spawns a detached agent process first if none is reachable, so
// it keeps running after this command (and its terminal) exits.
func Unlock(id string, key []byte, ttl time.Duration) error {
	if err := EnsureRunning(); err != nil {
		return err
	}
	resp, err := roundTrip(request{
		Cmd:        "unlock",
		ID:         id,
		Key:        encodeKey(key),
		TTLSeconds: int(ttl.Seconds()),
	})
	if err != nil {
		return fmt.Errorf("talk to agent: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("agent: %s", resp.Error)
	}
	return nil
}

// Lock clears every cached key. A no-op (not an error) if no agent is running.
func Lock() error {
	resp, err := roundTrip(request{Cmd: "lock"})
	if err != nil {
		return nil // no agent running — nothing to lock
	}
	if !resp.OK {
		return fmt.Errorf("agent: %s", resp.Error)
	}
	return nil
}

// Stop clears all cached keys and terminates the agent process. A no-op (not
// an error) if no agent is running.
func Stop() error {
	resp, err := roundTrip(request{Cmd: "stop"})
	if err != nil {
		return nil // no agent running
	}
	if !resp.OK {
		return fmt.Errorf("agent: %s", resp.Error)
	}
	return nil
}

// Status reports every currently-cached identity and its remaining TTL. A
// nil, non-error result means no agent is running — that is a normal state,
// not a failure.
func Status() ([]StatusEntry, error) {
	resp, err := roundTrip(request{Cmd: "status"})
	if err != nil {
		return nil, nil // no agent running
	}
	if !resp.OK {
		return nil, fmt.Errorf("agent: %s", resp.Error)
	}
	return resp.Entries, nil
}

// IsRunning reports whether an agent is currently reachable at SocketPath.
func IsRunning() bool {
	conn, err := dial()
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// EnsureRunning starts a detached `cifra agent serve-internal` process if
// none is already reachable, then waits (briefly) for it to start accepting
// connections. The spawned process is session-detached (no controlling
// terminal) so it outlives the caller and its terminal.
func EnsureRunning() error {
	if IsRunning() {
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve cifra binary path: %w", err)
	}

	cmd := exec.Command(exe, "agent", "serve-internal") //nolint:gosec // fixed subcommand, no user input
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	detachProcess(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}
	_ = cmd.Process.Release()

	deadline := time.Now().Add(spawnMaxWait)
	for time.Now().Before(deadline) {
		if IsRunning() {
			return nil
		}
		time.Sleep(spawnRetryInterval)
	}
	return fmt.Errorf("agent did not start within %s", spawnMaxWait)
}
