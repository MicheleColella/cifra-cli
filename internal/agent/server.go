package agent

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Listen creates the Unix socket at SocketPath, ready for Serve. Returns an
// error if another agent is already listening there. A stale socket file
// left behind by a crashed agent (present on disk but nothing listening) is
// removed automatically before binding.
func Listen() (net.Listener, error) {
	path, err := SocketPath()
	if err != nil {
		return nil, err
	}
	if IsRunning() {
		return nil, fmt.Errorf("an cifra agent is already running at %s", path)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	_ = os.Remove(path) // clear a stale socket file, if any

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	return ln, nil
}

// server holds decrypted keys in memory, keyed by recipient id.
type server struct {
	mu   sync.Mutex
	keys map[string]cachedKey
}

type cachedKey struct {
	key    []byte
	expiry time.Time
}

// Serve accepts connections on ln until it is closed (by a "stop" request or
// by the caller), handling one request/response per connection. Blocks until
// the listener closes. All cached key bytes are cleared before returning.
func Serve(ln net.Listener) {
	s := &server{keys: make(map[string]cachedKey)}

	stopSweep := make(chan struct{})
	go s.sweepExpired(stopSweep)
	defer close(stopSweep)
	defer s.clearAll()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed — shut down
		}
		go s.handleConn(conn, ln)
	}
}

func (s *server) sweepExpired(stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for id, ck := range s.keys {
				if now.After(ck.expiry) {
					clear(ck.key)
					delete(s.keys, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *server) clearAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ck := range s.keys {
		clear(ck.key)
		delete(s.keys, id)
	}
}

func (s *server) handleConn(conn net.Conn, ln net.Listener) {
	defer conn.Close() //nolint:errcheck

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}

	var req request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		writeResponse(conn, response{OK: false, Error: "invalid request"})
		return
	}

	switch req.Cmd {
	case "unlock":
		s.handleUnlock(conn, req)
	case "get":
		s.handleGet(conn, req)
	case "lock":
		s.clearAll()
		writeResponse(conn, response{OK: true})
	case "stop":
		writeResponse(conn, response{OK: true})
		_ = ln.Close()
	case "status":
		s.handleStatus(conn)
	default:
		writeResponse(conn, response{OK: false, Error: "unknown command"})
	}
}

func (s *server) handleUnlock(conn net.Conn, req request) {
	if req.ID == "" || req.Key == "" {
		writeResponse(conn, response{OK: false, Error: "id and key are required"})
		return
	}
	key, err := base64.StdEncoding.DecodeString(req.Key)
	if err != nil {
		writeResponse(conn, response{OK: false, Error: "invalid key encoding"})
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	s.mu.Lock()
	s.keys[req.ID] = cachedKey{key: key, expiry: time.Now().Add(ttl)}
	s.mu.Unlock()

	writeResponse(conn, response{OK: true})
}

func (s *server) handleGet(conn net.Conn, req request) {
	if req.ID == "" {
		writeResponse(conn, response{OK: false, Error: "id is required"})
		return
	}

	s.mu.Lock()
	ck, ok := s.keys[req.ID]
	if ok && time.Now().After(ck.expiry) {
		clear(ck.key)
		delete(s.keys, req.ID)
		ok = false
	}
	s.mu.Unlock()

	if !ok {
		writeResponse(conn, response{OK: false, Error: "not cached"})
		return
	}
	writeResponse(conn, response{OK: true, Key: base64.StdEncoding.EncodeToString(ck.key)})
}

func (s *server) handleStatus(conn net.Conn) {
	s.mu.Lock()
	entries := make([]StatusEntry, 0, len(s.keys))
	now := time.Now()
	for id, ck := range s.keys {
		entries = append(entries, StatusEntry{ID: id, ExpiresInSeconds: int(ck.expiry.Sub(now).Seconds())})
	}
	s.mu.Unlock()

	writeResponse(conn, response{OK: true, Entries: entries})
}

func writeResponse(conn net.Conn, resp response) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = conn.Write(b)
}
