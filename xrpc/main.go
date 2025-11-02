package main

import (
    "context"
    "crypto/ecdh"
    crand "crypto/rand"
    "crypto/sha256"
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

    "xrp/internal/shared"
    "xrp/internal/coreembed"
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
    if c.lastActivity == nil { c.lastActivity = make(map[string]time.Time) }
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
    s = strings.TrimSpace(strings.ToLower(s))
    if s == "none" { return s }
    if strings.HasPrefix(s, "mlkem768x25519plus.") { return s }
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
        if st.Active && st.Status == "connected" { any = true; break }
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
            if c.connected && st.Active { status = "connected" }
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
        if c.connected && st.Active { status = "connected" }
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
	st, ok := c.tunnelStates[id]
	if !ok {
		return false
	}
	st.Active = false
	st.LastChange = time.Now()
	return true
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
    monStop    chan struct{}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.Handle("/logs/stream", s.logs)
	mux.HandleFunc("/logs/access/stream", s.handleLogStream("access"))
	mux.HandleFunc("/logs/error/stream", s.handleLogStream("error"))

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
	mux.HandleFunc("/api/reality/mldsa65", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		b := make([]byte, 32)
		_, _ = crand.Read(b)
		h := sha256.Sum256(b)
		writeJSON(w, map[string]string{
			"seed":      base64.StdEncoding.EncodeToString(b),
			"seedHex":   hex.EncodeToString(b),
			"verifyHex": hex.EncodeToString(h[:]),
		})
	})

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
				writeJSON(w, st)
				return
			}
			http.NotFound(w, r)
		case http.MethodDelete:
			if s.conn.deleteTunnel(id) {
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

	return withCORS(mux)
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

// startCore simulates starting embedded xray-core and logs success/failure to console.
// Set env XRPC_CORE_FAIL=true to simulate a启动失败 case.
func (s *Server) startCore() error {
	log.Printf("xray-core: starting…")
	fail := os.Getenv("XRPC_CORE_FAIL")
	if strings.EqualFold(fail, "1") || strings.EqualFold(fail, "true") || strings.EqualFold(fail, "yes") {
		err := fmt.Errorf("simulated failure (XRPC_CORE_FAIL=%s)", fail)
		log.Printf("xray-core: start failed: %v", err)
		s.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_failed\",\"reason\":\"startup\",\"ts\":%d}", time.Now().Unix()))
		return err
	}
	if s.orch == nil { s.orch = coreembed.New() }
	runDir := os.Getenv("XRPC_XRAY_RUN_DIR")
	if runDir == "" {
		runDir = s.logDir
	}
	// Choose free port to avoid conflicts
	apiPort := getenvInt("XRPC_XRAY_API_PORT", 10086)
	apiPort = chooseFreePort(apiPort)
	// Build bridge config from applied profile; fallback to minimal when absent
	cfg, err := s.buildBridgeConfig(apiPort)
	if err != nil {
		log.Printf("xray-core: build bridge config failed, using minimal: %v", err)
		cfg = []byte(fmt.Sprintf(`{
      "log": {"loglevel": "warning", "access": %q, "error": %q},
      "inbounds": [
        {"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":1}}
      ],
      "outbounds": [
        {"protocol": "blackhole", "tag":"blackhole"}
      ]
    }`, s.accessPath, s.errorPath, apiPort))
	}
	if p := os.Getenv("XRAY_CFG_BRIDGE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			cfg = b
		} else {
			log.Printf("xray-core: warn cannot read XRAY_CFG_BRIDGE=%s: %v", p, err)
		}
	}
    // Fixed config filename by default; can override with XRPC_XRAY_CFG_PATH
    cfgPath := os.Getenv("XRPC_XRAY_CFG_PATH")
    if cfgPath == "" { cfgPath = "xray.bridge.json" }
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
    if s.orch == nil { s.orch = coreembed.New() }
    runDir := os.Getenv("XRPC_XRAY_RUN_DIR")
    if runDir == "" { runDir = s.logDir }
    apiPort := getenvInt("XRPC_XRAY_API_PORT", 10086)
    apiPort = chooseFreePort(apiPort)
    cfg, err := s.buildBridgeConfig(apiPort)
    if err != nil {
        log.Printf("xray-core: build bridge config failed, using minimal: %v", err)
        cfg = []byte(fmt.Sprintf(`{
      "log": {"loglevel": "warning", "access": %q, "error": %q},
      "inbounds": [
        {"tag":"api","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":1}}
      ],
      "outbounds": [
        {"protocol": "blackhole", "tag":"blackhole"}
      ]
    }`, s.accessPath, s.errorPath, apiPort))
    }
    if p := os.Getenv("XRAY_CFG_BRIDGE"); p != "" {
        if b, err := os.ReadFile(p); err == nil { cfg = b } else { log.Printf("xray-core: warn cannot read XRAY_CFG_BRIDGE=%s: %v", p, err) }
    }
    cfgPath := os.Getenv("XRPC_XRAY_CFG_PATH")
    if cfgPath == "" { cfgPath = "xray.bridge.json" }
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
func (s *Server) buildBridgeConfig(apiPort int) ([]byte, error) {
    s.conn.mu.RLock()
    p := s.conn.params
    // Snapshot states to avoid holding lock during JSON building
    states := make(map[string]*TunnelState, len(s.conn.tunnelStates))
    for k, v := range s.conn.tunnelStates { states[k] = v }
    s.conn.mu.RUnlock()

    if p == nil || len(p.Tunnels) == 0 {
        return nil, fmt.Errorf("no active profile")
    }

    inbounds := make([]map[string]any, 0, 2)
    // Keep API inbound for diagnostics
    inbounds = append(inbounds, map[string]any{
        "tag":     "api",
        "listen":  "127.0.0.1",
        "port":    apiPort,
        "protocol": "dokodemo-door",
        "settings": map[string]any{"address": "127.0.0.1", "port": 1},
    })

    outbounds := make([]map[string]any, 0, 2+len(p.Tunnels)*2)
    // default direct outbound (freedom)
    outbounds = append(outbounds, map[string]any{"protocol": "freedom", "tag": "default"})

    rules := make([]map[string]any, 0, len(p.Tunnels)+1)

    // Optional forward proxy via portal
    if p.Forward.Enabled {
        // socks inbound on localhost
        port := p.Forward.Port
        if port <= 0 { port = 10808 }
        inbounds = append(inbounds, map[string]any{
            "tag": "socks-in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": map[string]any{"udp": true},
        })
        // vless outbound to portal forward port
        // normalize REALITY pubkey (accept std/url/hex; output url-no-pad)
        fwdPK, err := normalizeRealityKey32(p.Forward.PublicKey)
        if err != nil {
            return nil, fmt.Errorf("invalid forward.publicKey: %w", err)
        }
        outbounds = append(outbounds, map[string]any{
            "tag":      "proxy",
            "protocol": "vless",
            "settings": map[string]any{
                "vnext": []map[string]any{
                    {
                        "address": p.PortalAddr,
                        "port":    p.Forward.Port,
                        "users": []map[string]any{
                            {"id": p.Forward.ID, "encryption": "none", "flow": nonEmpty(p.Forward.Flow, "xtls-rprx-vision")},
                        },
                    },
                },
            },
            "streamSettings": map[string]any{
                "network":  "tcp",
                "security": "reality",
                "realitySettings": map[string]any{
                    "serverName": p.Forward.ServerName,
                    "publicKey":  fwdPK,
                    "shortId":    p.Forward.ShortID,
                    "fingerprint": "chrome",
                    "spiderX":     "/",
                },
            },
            "mux": map[string]any{"enabled": false},
        })
        rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{"socks-in"}, "outboundTag": "proxy"})
    }

    // For each tunnel, create a reverse link + local redirect outbound + route
    for i, t := range p.Tunnels {
        idx := i
        st, ok := states[t.ID]
        if !ok {
            // default state
            st = &TunnelState{ID: t.ID, EntryPort: t.EntryPort, MapPort: t.MapPortHint, Active: true, Target: defaultTargetFromMapPort(t.MapPortHint)}
        }
        if !st.Active { continue }
        localTag := fmt.Sprintf("local-web-%d", idx)
        revTag := fmt.Sprintf("rev-link-%d", idx)
        inboundTag := fmt.Sprintf("r-inbound-%d", idx)
        target := st.Target
        if target == "" { target = defaultTargetFromMapPort(st.MapPort) }

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
        if pk, err := normalizeRealityKey32(p.Handshake.PublicKey); err == nil { revPK = pk }
        flow := nonEmpty(p.Handshake.Flow, "xtls-rprx-vision")
        outbounds = append(outbounds, map[string]any{
            "tag":      revTag,
            "protocol": "vless",
            "settings": map[string]any{
                // shape aligned with reference script
                "address": p.PortalAddr,
                "port":    p.Handshake.Port,
                "id":      t.ID,
                "encryption": enc,
                "flow":    flow,
                "reverse": map[string]any{"tag": inboundTag},
            },
            "streamSettings": map[string]any{
                "network":  "tcp",
                "security": "reality",
                "realitySettings": map[string]any{
                    "serverName": p.Handshake.ServerName,
                    "publicKey":  revPK,
                    "shortId":    p.Handshake.ShortID,
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
        // Enable API + Stats + Policy to expose counters for connectivity probing
        "api": map[string]any{"tag": "api", "services": []string{"HandlerService", "LoggerService", "StatsService"}},
        "stats": map[string]any{},
        "policy": map[string]any{
            "levels": map[string]any{
                "0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true},
            },
            "system": map[string]any{
                "statsInboundUplink": true,
                "statsInboundDownlink": true,
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true,
            },
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": map[string]any{"rules": append([]map[string]any{{"ruleTag": "api", "inboundTag": []string{"api"}, "outboundTag": "api"}}, rules...)},
    }
    b, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil { return nil, err }
    return b, nil
}

func nonEmpty(s, def string) string { if s == "" { return def }; return s }

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
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	logs := shared.NewSSEHub()
	conn := NewConnector(logs)
	s := &Server{addr: *addr, conn: conn, logs: logs, access: shared.NewSSEHub(), errors: shared.NewSSEHub(), start: time.Now()}
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
	}

	s.logStartupSummary()
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
        if s.orch == nil { s.orch = coreembed.New() }
        if s.orch.IsRunning() {
            return
        }
        if err := s.startCore(); err == nil {
            return
        }
        // backoff with jitter
        jitter := time.Duration(rand.Intn(500)) * time.Millisecond
        wait := backoff + jitter
        if wait > 60*time.Second { wait = 60 * time.Second }
        time.Sleep(wait)
        if backoff < 60*time.Second { backoff *= 2 }
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
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-stop:
            return
        case <-ticker.C:
            s.conn.mu.RLock()
            p := s.conn.params
            s.conn.mu.RUnlock()
            if p == nil {
                continue
            }
            // iterate tunnels in order for consistent index->tag mapping
            for i, t := range p.Tunnels {
                revTag := fmt.Sprintf("rev-link-%d", i)
                inbTag := fmt.Sprintf("r-inbound-%d", i)
                // sum counters we care about
                sum := int64(0)
                if v, ok := s.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>uplink", revTag)); ok { sum += v }
                if v, ok := s.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>downlink", revTag)); ok { sum += v }
                if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok { sum += v }
                if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok { sum += v }

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
        }
    }
}

// parseErrorLine extracts a brief error reason from xray error.log lines.
func parseErrorLine(line string) (string, bool) {
    s := strings.ToLower(line)
    keys := []string{"failed", "error", "timeout", "refused", "invalid", "unreachable"}
    for _, k := range keys {
        if strings.Contains(s, k) {
            if len(line) > 160 { line = line[:160] }
            return line, true
        }
    }
    return "", false
}
