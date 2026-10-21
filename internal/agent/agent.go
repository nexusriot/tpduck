// Package agent caches a vault's derived key for a short while, so a sequence
// of CLI commands does not re-run the key derivation or re-prompt for every
// single invocation.
//
// It is the same bargain as ssh-agent: the key lives in one process's memory
// for a bounded time, reachable over a socket only the owning user can open.
// It is not a replacement for locking the vault -- the cache expires, and
// `tpduck agent stop` drops it immediately.
package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultTTL is how long a cached key survives.
//
// The lifetime is absolute, measured from when the key was cached, the way
// `ssh-agent -t` works. A sliding window that refreshed on every use would let
// a polling process keep a key alive indefinitely, which is exactly the bound
// the agent is supposed to provide.
const DefaultTTL = 15 * time.Minute

// maxTTL bounds what a client can ask for, so a stray flag cannot turn the
// agent into a permanent key store.
const maxTTL = 8 * time.Hour

// ErrNotRunning means no agent is listening.
var ErrNotRunning = errors.New("no tpduck agent is running")

// ErrNoKey means the agent has nothing cached for that vault.
var ErrNoKey = errors.New("agent has no key for this vault")

// SocketPath returns the socket location, preferring the per-user runtime
// directory, which is already mode 0700 and cleared at logout.
func SocketPath() string {
	if p := os.Getenv("TPDUCK_AGENT_SOCK"); p != "" {
		return p
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "tpduck-agent.sock")
	}
	// Without a runtime directory the fallback is a shared /tmp, so the socket
	// goes inside a directory of our own: Serve creates it 0700 before
	// binding, which closes the window between listening and chmod in which
	// the socket itself would be reachable by anyone on the machine.
	return filepath.Join(os.TempDir(), fmt.Sprintf("tpduck-agent-%d", os.Getuid()), "agent.sock")
}

// request and response are the whole protocol: one JSON object each way.
type request struct {
	Op    string `json:"op"` // get, put, drop, status, stop
	Vault string `json:"vault,omitempty"`
	Key   []byte `json:"key,omitempty"`
	TTL   string `json:"ttl,omitempty"`
}

type response struct {
	OK      bool   `json:"ok"`
	Err     string `json:"err,omitempty"`
	Key     []byte `json:"key,omitempty"`
	Count   int    `json:"count,omitempty"`
	Expires string `json:"expires,omitempty"`
}

type entry struct {
	key     []byte
	expires time.Time
}

// Server holds keys in memory until they expire.
type Server struct {
	mu      sync.Mutex
	entries map[string]entry
	ttl     time.Duration
	ln      net.Listener
	done    chan struct{}
	once    sync.Once
}

// Serve listens on the socket and blocks until Stop or a client "stop".
func Serve(socket string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	// A stale socket from a crashed agent would otherwise block binding.
	if conn, err := net.Dial("unix", socket); err == nil {
		conn.Close()
		return fmt.Errorf("an agent is already listening on %s", socket)
	}
	_ = os.Remove(socket)

	if dir := filepath.Dir(socket); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		// MkdirAll leaves an existing directory's mode alone, and the one we
		// just made went through the umask.
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	// Only the owner may talk to the agent.
	if err := os.Chmod(socket, 0o600); err != nil {
		ln.Close()
		return err
	}
	s := &Server{entries: map[string]entry{}, ttl: ttl, ln: ln, done: make(chan struct{})}
	defer s.Stop()

	go s.expireLoop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				return err
			}
		}
		go s.handle(conn)
	}
}

// Stop shuts the agent down and forgets every cached key.
func (s *Server) Stop() {
	s.once.Do(func() {
		close(s.done)
		if s.ln != nil {
			_ = s.ln.Close()
		}
		s.mu.Lock()
		for k, e := range s.entries {
			zero(e.key)
			delete(s.entries, k)
		}
		s.mu.Unlock()
	})
}

func (s *Server) expireLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			for k, e := range s.entries {
				if now.After(e.expires) {
					zero(e.key)
					delete(s.entries, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		writeResponse(conn, response{Err: "bad request"})
		return
	}
	switch req.Op {
	case "get":
		s.mu.Lock()
		e, ok := s.entries[req.Vault]
		if ok && time.Now().After(e.expires) {
			zero(e.key)
			delete(s.entries, req.Vault)
			ok = false
		}
		// Copy under the lock. The slice in the map is overwritten in place
		// when the key expires or is dropped, so encoding it after unlocking
		// could hand the client a key that turned to zeroes halfway through.
		var key []byte
		if ok {
			key = append([]byte(nil), e.key...)
		}
		s.mu.Unlock()
		if !ok {
			writeResponse(conn, response{Err: ErrNoKey.Error()})
			return
		}
		writeResponse(conn, response{OK: true, Key: key, Expires: e.expires.Format(time.RFC3339)})
		zero(key)
	case "put":
		if req.Vault == "" || len(req.Key) == 0 {
			writeResponse(conn, response{Err: "vault and key are required"})
			return
		}
		ttl := s.ttl
		if req.TTL != "" {
			if d, err := time.ParseDuration(req.TTL); err == nil && d > 0 {
				ttl = d
			}
		}
		if ttl > maxTTL {
			ttl = maxTTL
		}
		s.mu.Lock()
		if old, ok := s.entries[req.Vault]; ok {
			zero(old.key)
		}
		s.entries[req.Vault] = entry{key: append([]byte(nil), req.Key...), expires: time.Now().Add(ttl)}
		s.mu.Unlock()
		writeResponse(conn, response{OK: true})
	case "drop":
		s.mu.Lock()
		if e, ok := s.entries[req.Vault]; ok {
			zero(e.key)
			delete(s.entries, req.Vault)
		}
		if req.Vault == "" {
			for k, e := range s.entries {
				zero(e.key)
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
		writeResponse(conn, response{OK: true})
	case "status":
		s.mu.Lock()
		n := len(s.entries)
		s.mu.Unlock()
		writeResponse(conn, response{OK: true, Count: n})
	case "stop":
		writeResponse(conn, response{OK: true})
		s.Stop()
	default:
		writeResponse(conn, response{Err: "unknown op " + req.Op})
	}
}

func writeResponse(conn net.Conn, r response) {
	_ = json.NewEncoder(conn).Encode(r)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --- client ---

func call(req request) (response, error) {
	conn, err := net.DialTimeout("unix", SocketPath(), 2*time.Second)
	if err != nil {
		return response{}, ErrNotRunning
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return response{}, err
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return response{}, err
	}
	if !resp.OK {
		if resp.Err == ErrNoKey.Error() {
			return resp, ErrNoKey
		}
		return resp, errors.New(resp.Err)
	}
	return resp, nil
}

// Get returns a cached key for a vault.
func Get(vault string) ([]byte, error) {
	resp, err := call(request{Op: "get", Vault: vault})
	if err != nil {
		return nil, err
	}
	return resp.Key, nil
}

// Put caches a key for a vault.
func Put(vault string, key []byte, ttl time.Duration) error {
	req := request{Op: "put", Vault: vault, Key: key}
	if ttl > 0 {
		req.TTL = ttl.String()
	}
	_, err := call(req)
	return err
}

// Drop forgets one vault's key, or every key when vault is empty.
func Drop(vault string) error {
	_, err := call(request{Op: "drop", Vault: vault})
	return err
}

// Status reports how many keys the agent holds.
func Status() (int, error) {
	resp, err := call(request{Op: "status"})
	return resp.Count, err
}

// StopAgent asks a running agent to exit.
func StopAgent() error {
	_, err := call(request{Op: "stop"})
	return err
}

// Running reports whether an agent is reachable.
func Running() bool {
	_, err := Status()
	return err == nil
}
