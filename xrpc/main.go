package main

import (
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xrp/internal/coreembed"
	"xrp/internal/shared"
)

type Connector struct {
	mu           sync.RWMutex
	params       *shared.ConnectionParams
	connected    bool
	lastErr      string
	reconnects   int
	lastChange   time.Time
	logs         *shared.SSEHub
	stopCh       chan struct{}
	tunnelStates map[string]*TunnelState
	// per-tunnel last activity timestamps derived from xray stats
	lastActivity map[string]time.Time
}

type authFile struct {
	Username  string `json:"username"`
	Salt      string `json:"salt"`
	Hash      string `json:"hash"`
	CreatedAt string `json:"createdAt"`
}

func NewConnector(logs *shared.SSEHub) *Connector { return &Connector{logs: logs} }

func (c *Connector) ApplyParams(p *shared.ConnectionParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.params = p
	c.lastChange = time.Now()
	c.lastErr = ""
	c.reconnects = 0
	if c.tunnelStates == nil {
		c.tunnelStates = make(map[string]*TunnelState)
	}
	if c.lastActivity == nil {
		c.lastActivity = make(map[string]time.Time)
	}
	// reconcile tunnel states with new params
	seen := make(map[string]struct{})
	for _, t := range p.Tunnels {
		st, ok := c.tunnelStates[t.ID]
		if !ok {
			st = &TunnelState{
				ID:         t.ID,
				Tag:        t.Tag,
				EntryPort:  t.EntryPort,
				MapPort:    t.MapPortHint,
				Active:     true,
				LastChange: time.Now(),
			}
			st.Target = defaultTargetFromMapPort(st.MapPort)
			c.tunnelStates[t.ID] = st
		} else {
			st.Tag = t.Tag
			st.EntryPort = t.EntryPort
			// keep MapPort and Active as-is
			st.LastChange = time.Now()
			if st.Target == "" {
				st.Target = defaultTargetFromMapPort(st.MapPort)
			}
		}
		seen[t.ID] = struct{}{}
		c.lastActivity[t.ID] = time.Time{}
	}
	for id, st := range c.tunnelStates {
		if _, ok := seen[id]; !ok {
			// mark removed as inactive
			st.Active = false
			st.LastChange = time.Now()
		}
	}
	return nil
}

// normalizeRealityKey32 ensures the REALITY key (publicKey/password) is base64url (no padding) of 32 bytes.
func normalizeRealityKey32(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty REALITY key")
	}
	// Try raw URL (no padding)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Try URL with padding
	if b, err := base64.URLEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Try standard base64
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Try hex
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	return "", fmt.Errorf("invalid REALITY key: expect 32-byte base64url")
}

// sanitizeVLESSEncryption ensures the value is accepted by xray-core.
// Allowed: "none" or advanced strings starting with "mlkem768x25519plus.".
func sanitizeVLESSEncryption(s string) string {
	// Do NOT lowercase the whole string: base64url is case-sensitive.
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "none") {
		return "none"
	}
	// Accept prefix case-insensitively, but keep original content
	if strings.HasPrefix(strings.ToLower(s), "mlkem768x25519plus.") {
		return s
	}
	// fallback to none (Vision requires none for classic X25519 REALITY)
	return "none"
}

// SetTunnelConnected updates a single tunnel's status and overall connector state.
func (c *Connector) SetTunnelConnected(id string, ok bool) {
	c.mu.Lock()
	if st, exists := c.tunnelStates[id]; exists {
		prev := st.Active && (st.Status == "connected")
		st.Status = map[bool]string{true: "connected", false: "disconnected"}[ok]
		if ok {
			c.lastActivity[id] = time.Now()
		}
		if !prev && ok {
			// rising edge: count as a reconnect
			c.reconnects++
		}
	}
	// overall connected if any tunnel is connected
	any := false
	for _, st := range c.tunnelStates {
		if st.Active && st.Status == "connected" {
			any = true
			break
		}
	}
	c.connected = any
	c.mu.Unlock()
}

func (c *Connector) setConnected(ok bool, reason string) {
	c.mu.Lock()
	c.connected = ok
	if ok {
		c.lastErr = ""
	} else {
		c.lastErr = reason
	}
	c.mu.Unlock()
}

func (c *Connector) Status() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]any{
		"connected":  c.connected,
		"reconnects": c.reconnects,
		"lastError":  c.lastErr,
		"hasProfile": c.params != nil,
	}
}

type TunnelState struct {
	ID         string    `json:"id"`
	Tag        string    `json:"tag"`
	EntryPort  int       `json:"entry_port"`
	MapPort    int       `json:"map_port"`
	Target     string    `json:"target"`
	Active     bool      `json:"active"`
	Status     string    `json:"status"`
	LastChange time.Time `json:"last_change"`
}

func (c *Connector) listTunnels() []TunnelState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]TunnelState, 0, len(c.tunnelStates))
	for _, st := range c.tunnelStates {
		status := st.Status
		if status == "" {
			status = "disconnected"
			if c.connected && st.Active {
				status = "connected"
			}
		}
		out = append(out, TunnelState{
			ID: st.ID, Tag: st.Tag, EntryPort: st.EntryPort, MapPort: st.MapPort, Target: st.Target, Active: st.Active, Status: status, LastChange: st.LastChange,
		})
	}
	return out
}

func (c *Connector) getTunnel(id string) (TunnelState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	st, ok := c.tunnelStates[id]
	if !ok {
		return TunnelState{}, false
	}
	status := st.Status
	if status == "" {
		status = "disconnected"
		if c.connected && st.Active {
			status = "connected"
		}
	}
	return TunnelState{ID: st.ID, Tag: st.Tag, EntryPort: st.EntryPort, MapPort: st.MapPort, Target: st.Target, Active: st.Active, Status: status, LastChange: st.LastChange}, true
}

func (c *Connector) patchTunnel(id string, mapPort *int, active *bool, target *string) (TunnelState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.tunnelStates[id]
	if !ok {
		return TunnelState{}, false
	}
	if mapPort != nil {
		st.MapPort = *mapPort
		if st.Target == "" || isLocalhostTarget(st.Target) {
			st.Target = defaultTargetFromMapPort(st.MapPort)
		}
	}
	if active != nil {
		st.Active = *active
	}
	if target != nil {
		st.Target = *target
		if p, err := strconv.Atoi(st.Target); err == nil && p > 0 {
			st.Target = defaultTargetFromMapPort(p)
			st.MapPort = p
		} else {
			if _, port, ok := splitHostPort(st.Target); ok {
				st.MapPort = port
			}
		}
	}
	st.LastChange = time.Now()
	status := "disconnected"
	if c.connected && st.Active {
		status = "connected"
	}
	return TunnelState{ID: st.ID, Tag: st.Tag, EntryPort: st.EntryPort, MapPort: st.MapPort, Target: st.Target, Active: st.Active, Status: status, LastChange: st.LastChange}, true
}

func (c *Connector) deleteTunnel(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// remove runtime state entirely
	_, existed := c.tunnelStates[id]
	delete(c.tunnelStates, id)
	// also remove from applied profile so it is truly gone from config
	removed := false
	if c.params != nil && len(c.params.Tunnels) > 0 {
		dst := c.params.Tunnels[:0]
		for _, t := range c.params.Tunnels {
			if t.ID == id {
				removed = true
				continue
			}
			dst = append(dst, t)
		}
		c.params.Tunnels = dst
	}
	if existed || removed {
		c.lastChange = time.Now()
		return true
	}
	return false
}

type Server struct {
	addr       string
	conn       *Connector
	logs       *shared.SSEHub
	access     *shared.SSEHub
	errors     *shared.SSEHub
	uiFS       http.FileSystem
	start      time.Time
	logDir     string
	accessPath string
	errorPath  string
	tailAccess *shared.FileTailer
	tailError  *shared.FileTailer
	orch       *coreembed.Orchestrator
	// monitors
	monStop chan struct{}
	// auth
	authPath string
	authUser string
	authSalt string
	authHash string

	// stats store (in-memory ring buffers)
	statsMu        sync.Mutex
	statsTotal     []statsPoint
	statsPerTunnel map[string][]statsPoint
    wsStats        *shared.WSHub
    // persistence paths
    profilePath string
    statesPath  string
}

type statsPoint struct {
	TS   int64 `json:"ts"`
	Up   int64 `json:"uplink"`
	Down int64 `json:"downlink"`
}

const statsCap = 1800 // ~1 hour at 2s interval

func (s *Server) recordStats(ts int64, per map[string]struct{ up, down int64 }) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	var totUp, totDown int64
	if s.statsPerTunnel == nil {
		s.statsPerTunnel = make(map[string][]statsPoint)
	}
	for id, v := range per {
		totUp += v.up
		totDown += v.down
		arr := s.statsPerTunnel[id]
		arr = append(arr, statsPoint{TS: ts, Up: v.up, Down: v.down})
		if len(arr) > statsCap {
			arr = arr[len(arr)-statsCap:]
		}
		s.statsPerTunnel[id] = arr
	}
	s.statsTotal = append(s.statsTotal, statsPoint{TS: ts, Up: totUp, Down: totDown})
	if len(s.statsTotal) > statsCap {
		s.statsTotal = s.statsTotal[len(s.statsTotal)-statsCap:]
	}
}

// statsRange returns rate series (bytes/sec) since the given ms timestamp.
func (s *Server) statsRange(since int64, tunnelID string) (series []statsPoint, intervalMs int64) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	var arr []statsPoint
	if tunnelID == "" {
		arr = append(arr, s.statsTotal...)
	} else {
		arr = append(arr, s.statsPerTunnel[tunnelID]...)
	}
	// filter by since
	start := 0
	for i, p := range arr {
		if p.TS >= since {
			start = i
			break
		}
	}
	arr = arr[start:]
	if len(arr) < 2 {
		return nil, 0
	}
	// compute deltas to rates
	for i := 1; i < len(arr); i++ {
		dt := arr[i].TS - arr[i-1].TS
		if dt <= 0 {
			continue
		}
		up := arr[i].Up - arr[i-1].Up
		down := arr[i].Down - arr[i-1].Down
		if up < 0 {
			up = 0
		}
		if down < 0 {
			down = 0
		}
		// bytes per second
		series = append(series, statsPoint{TS: arr[i].TS, Up: up * 1000 / dt, Down: down * 1000 / dt})
	}
	// derive nominal interval from last step
	intervalMs = arr[len(arr)-1].TS - arr[len(arr)-2].TS
	if intervalMs <= 0 {
		intervalMs = 2000
	}
	return
}

// statsSnapshot gathers cumulative counters for each tunnel using xray-core stats.
// The front-end polls this endpoint and computes deltas for rate charts.
func (s *Server) statsSnapshot() map[string]any {
	// Default empty snapshot when no profile or orchestrator is not ready
	now := time.Now().UnixMilli()
	out := map[string]any{
		"ts":      now,
		"tunnels": []map[string]any{},
		"total":   map[string]any{"uplink": int64(0), "downlink": int64(0), "total": int64(0)},
	}
	if s.orch == nil {
		return out
	}
	// Snapshot params and ordering
	s.conn.mu.RLock()
	p := s.conn.params
	s.conn.mu.RUnlock()
	if p == nil || len(p.Tunnels) == 0 {
		return out
	}
	var tlist []map[string]any
	var sumUp, sumDown int64
	for i, t := range p.Tunnels {
		revTag := fmt.Sprintf("rev-link-%d", i)
		inbTag := fmt.Sprintf("r-inbound-%d", i)
		// Sum both outbound and inbound counters (uplink/downlink)
		var up, down int64
		if v, ok := s.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>uplink", revTag)); ok {
			up += v
		}
		if v, ok := s.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>downlink", revTag)); ok {
			down += v
		}
		if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok {
			up += v
		}
		if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok {
			down += v
		}
		tlist = append(tlist, map[string]any{
			"id":         t.ID,
			"tag":        t.Tag,
			"entry_port": t.EntryPort,
			"uplink":     up,
			"downlink":   down,
			"total":      up + down,
		})
		sumUp += up
		sumDown += down
	}
	out["tunnels"] = tlist
	out["total"] = map[string]any{"uplink": sumUp, "downlink": sumDown, "total": sumUp + sumDown}
	return out
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("/logs/stream", s.logs)
	mux.HandleFunc("/logs/access/stream", s.handleLogStream("access"))
	mux.HandleFunc("/logs/error/stream", s.handleLogStream("error"))
	// WebSocket: real-time rates
	if s.wsStats == nil {
		s.wsStats = shared.NewWSHub()
	}
	mux.Handle("/ws/stats", s.wsStats)

	// Tail N lines of logs
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		typ := r.URL.Query().Get("type")
		nStr := r.URL.Query().Get("tail")
		if nStr == "" {
			nStr = "200"
		}
		n, _ := strconv.Atoi(nStr)
		var p string
		switch typ {
		case "access":
			p = s.accessPath
		case "error":
			p = s.errorPath
		default:
			http.Error(w, "query type=access|error", 400)
			return
		}
		lines, err := shared.TailLastN(p, n, 2*1024*1024)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"type": typ, "path": p, "lines": lines})
	})

	// Optional: reality helper endpoints (mirror of XRPS for local tooling)
	mux.HandleFunc("/api/reality/x25519", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		curve := ecdh.X25519()
		priv, err := curve.GenerateKey(crand.Reader)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		pub := priv.PublicKey()
		writeJSON(w, map[string]string{
			"publicKey":  base64.RawURLEncoding.EncodeToString(pub.Bytes()),
			"privateKey": base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		})
	})
	// removed: /api/reality/mldsa65 (unused feature)

	if s.uiFS != nil {
		mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(s.uiFS)))
	}

	mux.HandleFunc("/api/profile/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		// accept raw base64 string or {"base64":"..."}
		var base64 string
		ct := r.Header.Get("Content-Type")
		if ct == "text/plain" || ct == "application/octet-stream" {
			buf := make([]byte, 0, 4096)
			tmp := make([]byte, 1024)
			for {
				n, err := r.Body.Read(tmp)
				if n > 0 {
					buf = append(buf, tmp[:n]...)
				}
				if err != nil {
					break
				}
			}
			base64 = string(buf)
		} else {
			var body struct {
				Base64 string `json:"base64"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			base64 = body.Base64
		}
		p, err := shared.DecodeParamsB64(stringsTrim(base64))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		// basic params validation
		if err := p.Validate(); err != nil {
			http.Error(w, "invalid profile: "+err.Error(), 400)
			return
		}
		// forward-proxy removed: no extra port conflict check
		if err := s.conn.ApplyParams(p); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// restart core to apply new active profile (best-effort)
		if err := s.restartCore(); err != nil {
			log.Printf("restart after profile apply failed: %v", err)
		}
        // reset monitors (stats/error)
        s.restartMonitors()
        // persist profile and current states
        if err := s.saveProfile(p); err != nil {
            log.Printf("persist profile failed: %v", err)
        }
        if err := s.saveTunnelStates(); err != nil {
            log.Printf("persist tunnel states failed: %v", err)
        }
        s.logs.Broadcast(fmt.Sprintf("{\"event\":\"profile_applied\",\"ts\":%d}", time.Now().Unix()))
        writeJSON(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/profile/active", func(w http.ResponseWriter, r *http.Request) {
		s.conn.mu.RLock()
		defer s.conn.mu.RUnlock()
		writeJSON(w, map[string]any{
			"hasProfile": s.conn.params != nil,
			"params":     s.conn.params,
		})
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"uptime": time.Since(s.start).String(),
			"status": s.conn.Status(),
		})
	})

	// stats snapshot: cumulative bytes per tunnel based on xray counters
	mux.HandleFunc("/api/stats/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		writeJSON(w, s.statsSnapshot())
	})

	// stats range: bytes/sec rates since timestamp; optional tunnel=id
	mux.HandleFunc("/api/stats/range", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		q := r.URL.Query()
		sinceStr := q.Get("since")
		if sinceStr == "" {
			http.Error(w, "query since=epochMillis required", 400)
			return
		}
		since, err := strconv.ParseInt(sinceStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid since", 400)
			return
		}
		tunnel := q.Get("tunnel")
		series, step := s.statsRange(since, tunnel)
		writeJSON(w, map[string]any{"series": series, "interval": step})
	})

	mux.HandleFunc("/api/core/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		s.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_restart\",\"ts\":%d}", time.Now().Unix()))
		if err := s.restartCore(); err != nil {
			http.Error(w, "core restart failed: "+err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "message": "restart ok"})
	})

	// tunnels: list/detail/patch/delete
	mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		writeJSON(w, s.conn.listTunnels())
	})
	mux.HandleFunc("/api/tunnels/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if st, ok := s.conn.getTunnel(id); ok {
				writeJSON(w, st)
				return
			}
			http.NotFound(w, r)
        case http.MethodPatch:
            var body struct {
                MapPort *int    `json:"map_port"`
                Active  *bool   `json:"active"`
                Target  *string `json:"target"`
            }
            if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                http.Error(w, err.Error(), 400)
                return
            }
            if st, ok := s.conn.patchTunnel(id, body.MapPort, body.Active, body.Target); ok {
                _ = s.saveTunnelStates()
                writeJSON(w, st)
                return
            }
            http.NotFound(w, r)
        case http.MethodDelete:
            if s.conn.deleteTunnel(id) {
                // apply change to embedded core so it is removed from effective config
                if err := s.restartCore(); err != nil {
                    http.Error(w, "core restart failed: "+err.Error(), 500)
                    return
                }
                // persist updated profile + states
                s.conn.mu.RLock()
                cur := s.conn.params
                s.conn.mu.RUnlock()
                if cur != nil {
                    _ = s.saveProfile(cur)
                }
                _ = s.saveTunnelStates()
                w.WriteHeader(http.StatusNoContent)
                return
            }
			http.NotFound(w, r)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>XRPC</title><h1>XRPC running</h1><p>Paste Base64 to /api/profile/apply. Logs: /api/logs?type=access|error&tail=N, SSE: /logs/access/stream /logs/error/stream</p>")
	})

	return withCORS(s.secure(mux))
}

// handleLogStream streams entire file first, then follows via hub SSE.
func (s *Server) handleLogStream(which string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		var path string
		var hub *shared.SSEHub
		switch which {
		case "access":
			path, hub = s.accessPath, s.access
		case "error":
			path, hub = s.errorPath, s.errors
		default:
			http.Error(w, "invalid log type", 400)
			return
		}

		lines, _ := shared.TailLastN(path, 0, 0)
		for _, ln := range lines {
			fmt.Fprintf(w, "data: %s\n\n", ln)
		}
		flusher.Flush()

		ch, unsub := hub.Subscribe()
		defer unsub()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fmt.Fprintf(w, ": ping %d\n\n", time.Now().Unix())
				flusher.Flush()
			case ln, ok := <-ch:
				if !ok {
					return
				}
				fmt.Fprintf(w, "data: %s\n\n", ln)
				flusher.Flush()
			}
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
    w.Header().Set("Content-Type", "application/json")
    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    _ = enc.Encode(v)
}

func stringsTrim(s string) string { return strings.TrimSpace(strings.Trim(s, "\n\r\t")) }

// === Persistence (profile + tunnel states) ===
func (s *Server) profileFile() string {
    if s.profilePath != "" {
        return s.profilePath
    }
    dir := getStateDir()
    _ = os.MkdirAll(dir, 0o755)
    s.profilePath = filepath.Join(dir, "profile.json")
    return s.profilePath
}

func (s *Server) statesFile() string {
    if s.statesPath != "" {
        return s.statesPath
    }
    dir := getStateDir()
    _ = os.MkdirAll(dir, 0o755)
    s.statesPath = filepath.Join(dir, "tunnel_states.json")
    return s.statesPath
}

func (s *Server) saveProfile(p *shared.ConnectionParams) error {
    b, err := json.MarshalIndent(p, "", "  ")
    if err != nil {
        return err
    }
    path := s.profileFile()
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, b, 0o600); err != nil {
        return err
    }
    return os.Rename(tmp, path)
}

func (s *Server) saveTunnelStates() error {
    s.conn.mu.RLock()
    arr := make([]TunnelState, 0, len(s.conn.tunnelStates))
    for _, st := range s.conn.tunnelStates {
        arr = append(arr, *st)
    }
    s.conn.mu.RUnlock()
    b, err := json.MarshalIndent(arr, "", "  ")
    if err != nil {
        return err
    }
    path := s.statesFile()
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, b, 0o600); err != nil {
        return err
    }
    return os.Rename(tmp, path)
}

func (s *Server) loadPersisted() {
    // Load profile
    if pb, err := os.ReadFile(s.profileFile()); err == nil {
        var p shared.ConnectionParams
        if err := json.Unmarshal(pb, &p); err == nil {
            if err := p.Validate(); err == nil {
                if err := s.conn.ApplyParams(&p); err != nil {
                    log.Printf("apply persisted profile failed: %v", err)
                }
            } else {
                log.Printf("persisted profile invalid: %v", err)
            }
        } else {
            log.Printf("read persisted profile failed: %v", err)
        }
    }
    // Load tunnel states and merge
    if sb, err := os.ReadFile(s.statesFile()); err == nil {
        var arr []TunnelState
        if err := json.Unmarshal(sb, &arr); err == nil {
            s.conn.mu.Lock()
            for _, st := range arr {
                if cur, ok := s.conn.tunnelStates[st.ID]; ok {
                    cur.MapPort = st.MapPort
                    cur.Target = st.Target
                    cur.Active = st.Active
                    cur.LastChange = time.Now()
                }
            }
            s.conn.mu.Unlock()
        } else {
            log.Printf("read persisted states failed: %v", err)
        }
    }
}

// secure wraps handlers with HTTP Basic Auth (admin/<password>), except for /healthz and OPTIONS.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if s.authUser == "" || s.authHash == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || !s.checkPassword(user, pass) {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"XRPC\"")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) checkPassword(user, pass string) bool {
	if user != s.authUser {
		return false
	}
	if s.authSalt == "" || s.authHash == "" {
		return false
	}
	h := hashPassword(s.authSalt, pass)
	if subtle.ConstantTimeCompare([]byte(h), []byte(s.authHash)) != 1 {
		return false
	}
	return true
}

func hashPassword(salt, pass string) string {
	sum := sha256.Sum256([]byte(salt + ":" + pass))
	return hex.EncodeToString(sum[:])
}

func randomBase64URL(n int) string {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}

// resetAdminCredentials generates a new admin password, stores it, and updates in-memory auth state.
func (s *Server) resetAdminCredentials(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	user := "admin"
	salt := randomHex(16)
	pass := randomBase64URL(24)
	hash := hashPassword(salt, pass)
	af := authFile{Username: user, Salt: salt, Hash: hash, CreatedAt: time.Now().Format(time.RFC3339)}
	b, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	s.authUser, s.authSalt, s.authHash = user, salt, hash
	s.authPath = path
	return pass, nil
}

// getStateDir returns the directory to store XRPC state (auth, etc.).
// Order: XRPC_STATE_DIR env -> /var/lib/xrpc
func getStateDir() string {
	if v := strings.TrimSpace(os.Getenv("XRPC_STATE_DIR")); v != "" {
		return v
	}
	return "/var/lib/xrpc"
}

// initAuth loads or creates admin credentials in getStateDir()/admin.auth.json
func (s *Server) initAuth() error {
	dir := getStateDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "admin.auth.json")
	s.authPath = path
	if _, err := os.Stat(path); os.IsNotExist(err) {
		pass, err := s.resetAdminCredentials(path)
		if err != nil {
			return err
		}
		log.Printf("==== XRPC 初次运行创建管理员账户 ====")
		log.Printf("用户名: admin  初始密码: %s", pass)
		log.Printf("凭据文件: %s", path)
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var af authFile
	if err := json.Unmarshal(b, &af); err != nil {
		return err
	}
	s.authUser, s.authSalt, s.authHash = af.Username, af.Salt, af.Hash
	return nil
}

// defaultTargetFromMapPort returns a 127.0.0.1:port target string.
func defaultTargetFromMapPort(port int) string {
	if port <= 0 {
		port = 80
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// splitHostPort parses host:port into (host, port, ok)
func splitHostPort(target string) (string, int, bool) {
	host, p, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, false
	}
	pi, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, false
	}
	return host, pi, true
}

// isLocalhostTarget returns true if target host is a loopback address
func isLocalhostTarget(target string) bool {
	host, _, ok := splitHostPort(target)
	if !ok {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func getenvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serverListenPort parses the HTTP server listen address and returns its port.
func serverListenPort(addr string) int {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0
	}
	if strings.HasPrefix(addr, ":") {
		if n, err := strconv.Atoi(strings.TrimPrefix(addr, ":")); err == nil {
			return n
		}
		return 0
	}
	if _, p, err := net.SplitHostPort(addr); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	return 0
}

// logStartupSummary prints a concise startup summary to the console.
func (s *Server) logStartupSummary() {
	log.Printf("==== XRPC startup ====")
	log.Printf("Addr: %s", s.addr)
	if s.uiFS != nil {
		log.Printf("UI: enabled at /ui/")
	} else {
		log.Printf("UI: disabled (XRPC_UI_DIR not set)")
	}
	if s.logDir != "" {
		log.Printf("LogDir: %s", s.logDir)
		log.Printf("  access: %s", s.accessPath)
		log.Printf("  error:  %s", s.errorPath)
	}
	log.Printf("APIs:")
	log.Printf("  /healthz  /status  /api/profile/*  /api/tunnels*")
	log.Printf("  /api/logs?type=access|error&tail=N  /api/core/restart")
	log.Printf("SSE:")
	log.Printf("  /logs/stream  /logs/access/stream  /logs/error/stream")
}

// startCore starts embedded xray-core and logs success/failure to console.
func (s *Server) startCore() error {
	log.Printf("xray-core: starting…")
	if s.orch == nil {
		s.orch = coreembed.New()
	}
	// Store config under home directory: ~/xrp
	var runDir string
	if home, err := os.UserHomeDir(); err == nil {
		runDir = filepath.Join(home, "xrp")
	} else {
		runDir = s.logDir
	}
	_ = os.MkdirAll(runDir, 0o755)
	// Build bridge config from applied profile; on failure, try to reuse existing config file
	cfgPath := os.Getenv("XRPC_XRAY_CFG_PATH")
	if cfgPath == "" {
		cfgPath = filepath.Join(runDir, "xray.bridge.json")
	}
	cfg, err := s.buildBridgeConfig()
	if err != nil {
		if b, rerr := os.ReadFile(cfgPath); rerr == nil {
			log.Printf("xray-core: build failed, reusing existing config at %s: %v", cfgPath, err)
			cfg = b
		} else {
			log.Printf("xray-core: build bridge config failed, using minimal: %v", err)
			cfg = []byte(fmt.Sprintf(`{
      "log": {"loglevel": "warning", "access": %q, "error": %q},
      "outbounds": [{"protocol": "blackhole", "tag":"blackhole"}],
      "routing": {"rules": []}
    }`, s.accessPath, s.errorPath))
		}
	}
	if p := os.Getenv("XRAY_CFG_BRIDGE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			cfg = b
		} else {
			log.Printf("xray-core: warn cannot read XRAY_CFG_BRIDGE=%s: %v", p, err)
		}
	}
	// Fixed config filename by default; can override with XRPC_XRAY_CFG_PATH
	// cfgPath computed above
	// Print effective config for debugging, then write debug copy and start embedded core
	log.Printf("xray-core: effective bridge config:\n%s", string(cfg))
	// Write debug copy then start embedded core
	_ = os.WriteFile(cfgPath, cfg, 0o644)
	if err := s.orch.StartJSON(cfg); err != nil {
		log.Printf("xray-core: start failed: %v", err)
		s.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_failed\",\"reason\":\"spawn\",\"ts\":%d}", time.Now().Unix()))
		return err
	}
	log.Printf("xray-core: started (cfg=%s)", cfgPath)
	s.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_started\",\"ts\":%d}", time.Now().Unix()))
	return nil
}

// restartCore simulates a restart and logs outcome.
func (s *Server) restartCore() error {
	log.Printf("xray-core: restarting…")
	if s.orch == nil {
		s.orch = coreembed.New()
	}
	// Store config under home directory: ~/xrp
	var runDir string
	if home, err := os.UserHomeDir(); err == nil {
		runDir = filepath.Join(home, "xrp")
	} else {
		runDir = s.logDir
	}
	_ = os.MkdirAll(runDir, 0o755)
	cfgPath := filepath.Join(runDir, "xray.bridge.json")
	cfg, err := s.buildBridgeConfig()
	if err != nil {
		if b, rerr := os.ReadFile(cfgPath); rerr == nil {
			log.Printf("xray-core: build failed, reusing existing config at %s: %v", cfgPath, err)
			cfg = b
		} else {
			log.Printf("xray-core: build bridge config failed, using minimal: %v", err)
			cfg = []byte(fmt.Sprintf(`{
      "log": {"loglevel": "warning", "access": %q, "error": %q},
      "outbounds": [{"protocol": "blackhole", "tag":"blackhole"}],
      "routing": {"rules": []}
    }`, s.accessPath, s.errorPath))
		}
	}
	if p := os.Getenv("XRAY_CFG_BRIDGE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			cfg = b
		} else {
			log.Printf("xray-core: warn cannot read XRAY_CFG_BRIDGE=%s: %v", p, err)
		}
	}
	// cfgPath computed above
	// Print effective config for debugging on restart
	log.Printf("xray-core: effective bridge config (restart):\n%s", string(cfg))
	_ = os.WriteFile(cfgPath, cfg, 0o644)
	if err := s.orch.RestartJSON(cfg); err != nil {
		log.Printf("xray-core: restart failed: %v", err)
		return err
	}
	log.Printf("xray-core: restart ok")
	return nil
}

// buildBridgeConfig constructs xray JSON from current applied profile and
// local tunnel states. It follows PRD: for each tunnel, create a rev-link
// VLESS+REALITY outbound with reverse.tag=r-inbound-{i}, and route that
// inbound tag to a local freedom redirect (target).
func (s *Server) buildBridgeConfig() ([]byte, error) {
	s.conn.mu.RLock()
	p := s.conn.params
	// Snapshot states to avoid holding lock during JSON building
	states := make(map[string]*TunnelState, len(s.conn.tunnelStates))
	for k, v := range s.conn.tunnelStates {
		states[k] = v
	}
	s.conn.mu.RUnlock()

	if p == nil || len(p.Tunnels) == 0 {
		return nil, fmt.Errorf("no active profile")
	}

	inbounds := make([]map[string]any, 0, 1)

	outbounds := make([]map[string]any, 0, 2+len(p.Tunnels)*2)
	// default direct outbound (freedom)
	outbounds = append(outbounds, map[string]any{"protocol": "freedom", "tag": "default"})

	rules := make([]map[string]any, 0, len(p.Tunnels)+1)

	// forward-proxy removed: no socks-in / proxy outbound

	// For each tunnel, create a reverse link + local redirect outbound + route
	for i, t := range p.Tunnels {
		idx := i
		st, ok := states[t.ID]
		if !ok {
			// default state
			st = &TunnelState{ID: t.ID, EntryPort: t.EntryPort, MapPort: t.MapPortHint, Active: true, Target: defaultTargetFromMapPort(t.MapPortHint)}
		}
		if !st.Active {
			continue
		}
		localTag := fmt.Sprintf("local-web-%d", idx)
		revTag := fmt.Sprintf("rev-link-%d", idx)
		inboundTag := fmt.Sprintf("r-inbound-%d", idx)
		target := st.Target
		if target == "" {
			target = defaultTargetFromMapPort(st.MapPort)
		}

		// local redirect outbound
		outbounds = append(outbounds, map[string]any{
			"protocol": "freedom",
			"tag":      localTag,
			"settings": map[string]any{"redirect": target},
		})
		// reverse link outbound to portal handshake
		enc := sanitizeVLESSEncryption(nonEmpty(p.Handshake.Encryption, "none"))
		// best-effort normalize REALITY public key for reverse link
		revPK := p.Handshake.PublicKey
		if pk, err := normalizeRealityKey32(p.Handshake.PublicKey); err == nil {
			revPK = pk
		}
		flow := nonEmpty(p.Handshake.Flow, "xtls-rprx-vision")
		outbounds = append(outbounds, map[string]any{
			"tag":      revTag,
			"protocol": "vless",
			"settings": map[string]any{
				// shape aligned with reference script
				"address":    p.PortalAddr,
				"port":       p.Handshake.Port,
				"id":         t.ID,
				"encryption": enc,
				"flow":       flow,
				"reverse":    map[string]any{"tag": inboundTag},
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"serverName":  p.Handshake.ServerName,
					"publicKey":   revPK,
					"shortId":     p.Handshake.ShortID,
					"fingerprint": "chrome",
					"spiderX":     "/",
				},
			},
			"mux": map[string]any{"enabled": false},
		})
		// route reverse inbound tag to local redirect outbound
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{inboundTag}, "outboundTag": localTag})
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning", "access": s.accessPath, "error": s.errorPath},
		// Enable Stats + Policy for in-process counters
		"api":   map[string]any{"tag": "api", "services": []string{"HandlerService", "LoggerService", "StatsService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true},
			},
			"system": map[string]any{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"rules": rules},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return b, nil
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// chooseFreePort tries preferred first; if busy, asks kernel for a free port.
func chooseFreePort(preferred int) int {
	if preferred > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", preferred))
		if err == nil {
			_ = ln.Close()
			return preferred
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return preferred
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func main() {
	addr := flag.String("addr", ":8081", "listen address")
	resetAdmin := flag.Bool("reset-admin", false, "reset admin password and exit")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	logs := shared.NewSSEHub()
	conn := NewConnector(logs)
	s := &Server{addr: *addr, conn: conn, logs: logs, access: shared.NewSSEHub(), errors: shared.NewSSEHub(), start: time.Now()}

	if *resetAdmin {
		authPath := filepath.Join(getStateDir(), "admin.auth.json")
		pass, err := s.resetAdminCredentials(authPath)
		if err != nil {
			log.Fatalf("reset admin password failed: %v", err)
		}
		fmt.Printf("XRPC admin password reset.\nUsername: admin\nPassword: %s\nFile: %s\n", pass, authPath)
		return
	}
	// Logging paths (dev default ./logs; override via XRPC_LOG_DIR)
	logDir := os.Getenv("XRPC_LOG_DIR")
	if logDir == "" {
		logDir = "./logs"
	}
	_ = os.MkdirAll(logDir, 0o755)
	s.logDir = logDir
	s.accessPath = filepath.Join(logDir, "access.log")
	s.errorPath = filepath.Join(logDir, "error.log")
	if _, err := os.Stat(s.accessPath); os.IsNotExist(err) {
		_ = os.WriteFile(s.accessPath, []byte(""), 0o644)
	}
	if _, err := os.Stat(s.errorPath); os.IsNotExist(err) {
		_ = os.WriteFile(s.errorPath, []byte(""), 0o644)
	}
	// Start tailers
	s.tailAccess = shared.NewFileTailer(s.accessPath, 1*time.Second)
	s.tailError = shared.NewFileTailer(s.errorPath, 1*time.Second)
	s.tailAccess.Start()
	s.tailError.Start()
	go func() {
		for line := range s.tailAccess.Out() {
			s.access.Broadcast(line)
		}
	}()
	go func() {
		for line := range s.tailError.Out() {
			// broadcast to UI
			s.errors.Broadcast(line)
			// parse error patterns -> connector lastErr
			if msg, ok := parseErrorLine(line); ok {
				s.conn.setConnected(false, msg)
			}
		}
	}()
	if dir := os.Getenv("XRPC_UI_DIR"); dir != "" {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			s.uiFS = http.Dir(dir)
			log.Printf("serving static UI at /ui/ from %s", dir)
		}
	} else {
		if efs := getEmbeddedUI(); efs != nil {
			s.uiFS = efs
			log.Printf("serving embedded UI at /ui/")
		}
	}

	s.logStartupSummary()
	// init admin auth
	if err := s.initAuth(); err != nil {
		log.Printf("auth init failed: %v; falling back to in-memory credentials", err)
		user := "admin"
		salt := randomHex(16)
		pass := randomBase64URL(24)
		h := hashPassword(salt, pass)
		s.authUser, s.authSalt, s.authHash = user, salt, h
		log.Printf("==== XRPC 内存凭据已启用（未持久化） ====")
		log.Printf("用户名: admin  初始密码: %s", pass)
		log.Printf("提示: 设置 XRPC_STATE_DIR 以持久化凭据，或在具备写权限的环境中执行 'xrpc -reset-admin'")
	}
	// Load persisted profile and tunnel states so the panel shows them after restart
	s.loadPersisted()
	// Attempt to start core with exponential backoff ensure loop
	go s.ensureCoreRunning()
	// start stats/error monitors
	s.restartMonitors()
	srv := &http.Server{Addr: s.addr, Handler: s.routes()}
	log.Printf("XRPC listening on %s", s.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
	_ = srv.Shutdown(context.Background())
}

// ensureCoreRunning tries to start xray-core with exponential backoff and jitter until success.
func (s *Server) ensureCoreRunning() {
	backoff := 1 * time.Second
	for {
		if s.orch == nil {
			s.orch = coreembed.New()
		}
		if s.orch.IsRunning() {
			return
		}
		if err := s.startCore(); err == nil {
			return
		}
		// backoff with jitter
		jitter := time.Duration(rand.Intn(500)) * time.Millisecond
		wait := backoff + jitter
		if wait > 60*time.Second {
			wait = 60 * time.Second
		}
		time.Sleep(wait)
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

// restartMonitors stops previous monitors and starts fresh ones based on current params.
func (s *Server) restartMonitors() {
	if s.monStop != nil {
		close(s.monStop)
	}
	s.monStop = make(chan struct{})
	go s.statsMonitor(s.monStop)
}

// statsMonitor polls xray stats counters to infer real connectivity per tunnel.
func (s *Server) statsMonitor(stop <-chan struct{}) {
	prev := make(map[string]int64)
	lastInc := make(map[string]time.Time)
	prevPer := make(map[string]struct{ up, down int64 })
	var prevTs int64
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ts := time.Now().UnixMilli()
			s.conn.mu.RLock()
			p := s.conn.params
			s.conn.mu.RUnlock()
			if p == nil {
				continue
			}
			// iterate tunnels in order for consistent index->tag mapping
			per := make(map[string]struct{ up, down int64 })
			for i, t := range p.Tunnels {
				revTag := fmt.Sprintf("rev-link-%d", i)
				inbTag := fmt.Sprintf("r-inbound-%d", i)
				// sum counters we care about
				sum := int64(0)
				up := int64(0)
				down := int64(0)
				if v, ok := s.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>uplink", revTag)); ok {
					sum += v
					up += v
				}
				if v, ok := s.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>downlink", revTag)); ok {
					sum += v
					down += v
				}
				if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok {
					sum += v
					up += v
				}
				if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok {
					sum += v
					down += v
				}
				per[t.ID] = struct{ up, down int64 }{up: up, down: down}

				pid := t.ID
				if last, ok := prev[pid]; ok {
					if sum > last {
						lastInc[pid] = time.Now()
						s.conn.SetTunnelConnected(pid, true)
					} else {
						// if no growth for 15s -> mark disconnected
						if ts, ok2 := lastInc[pid]; ok2 {
							if time.Since(ts) > 15*time.Second {
								s.conn.SetTunnelConnected(pid, false)
							}
						}
					}
				} else {
					// first observation
					lastInc[pid] = time.Now()
				}
				prev[pid] = sum
			}
			// store cumulative snapshot for history queries
			s.recordStats(ts, per)
			// Broadcast real-time rates via WS
			if s.wsStats != nil && prevTs > 0 {
				dt := ts - prevTs
				if dt > 0 {
					type item struct {
						ID, Tag                      string
						EntryPort                    int
						Up, Down, BytesUp, BytesDown int64
					}
					var items []item
					var sumUp, sumDown int64
					var cumUp, cumDown int64
					for _, t := range p.Tunnels {
						cur := per[t.ID]
						prev := prevPer[t.ID]
						up := cur.up - prev.up
						down := cur.down - prev.down
						if up < 0 {
							up = 0
						}
						if down < 0 {
							down = 0
						}
						// bytes/sec
						up = up * 1000 / dt
						down = down * 1000 / dt
						items = append(items, item{ID: t.ID, Tag: t.Tag, EntryPort: t.EntryPort, Up: up, Down: down, BytesUp: cur.up, BytesDown: cur.down})
						sumUp += up
						sumDown += down
						cumUp += cur.up
						cumDown += cur.down
					}
					msg := map[string]any{
						"ts":      ts,
						"total":   map[string]any{"up": sumUp, "down": sumDown},
						"bytes":   map[string]any{"up": cumUp, "down": cumDown},
						"tunnels": items,
					}
					s.wsStats.BroadcastJSON(msg)
				}
			}
			prevPer = per
			prevTs = ts
		}
	}
}

// parseErrorLine extracts a brief error reason from xray error.log lines.
func parseErrorLine(line string) (string, bool) {
	s := strings.ToLower(line)
	keys := []string{"failed", "error", "timeout", "refused", "invalid", "unreachable"}
	for _, k := range keys {
		if strings.Contains(s, k) {
			if len(line) > 160 {
				line = line[:160]
			}
			return line, true
		}
	}
	return "", false
}
