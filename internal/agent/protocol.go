// Package agent implements a small ssh-agent-style background daemon that
// caches decrypted private keys in memory for a bounded TTL, so a headless
// process (like the MCP server Claude Code spawns) can unseal a vault secret
// without a passphrase prompt or CIFRA_PASSPHRASE — as long as a human has
// unlocked that key from a real terminal within the TTL window.
//
// Transport: a Unix domain socket, one JSON request/response pair per
// connection. Socket and containing directory are owner-only (0600/0700),
// keeping the same same-user threat model as CIFRA_PASSPHRASE or a raw
// keychain blob — this is a convenience trade-off (wider exposure window: a
// decrypted key lives in memory up to TTL instead of being cleared right
// after use), never the default, and strictly opt-in via `cifra agent
// unlock`.
package agent

import "time"

// DefaultTTL is used when the caller doesn't specify one.
const DefaultTTL = 8 * time.Hour

type request struct {
	Cmd        string `json:"cmd"`
	ID         string `json:"id,omitempty"`
	Key        string `json:"key,omitempty"` // base64, only set for "unlock"
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type response struct {
	OK      bool          `json:"ok"`
	Error   string        `json:"error,omitempty"`
	Key     string        `json:"key,omitempty"` // base64, only set for "get"
	Entries []StatusEntry `json:"entries,omitempty"`
}

// StatusEntry describes one cached identity.
type StatusEntry struct {
	ID               string `json:"id"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}
