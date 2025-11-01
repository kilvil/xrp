package main

import (
    "context"
    crand "crypto/rand"
    "crypto/ecdh"
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
)

type Connector struct {
    mu             sync.RWMutex
    params         *shared.ConnectionParams
    connected      bool
    lastErr        string
    reconnects     int
    lastChange     time.Time
    logs           *shared.SSEHub
    stopCh         chan struct{}
    tunnelStates   map[string]*TunnelState
}

func NewConnector(logs *shared.SSEHub) *Connector { return &Connector{logs: logs} }

func (c *Connector) ApplyParams(p *shared.ConnectionParams) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.params = p
    c.lastChange = time.Now()
    c.lastErr = ""
    c.reconnects = 0
    if c.tunnelStates == nil { c.tunnelStates = make(map[string]*TunnelState) }
    // reconcile tunnel states with new params
    seen := make(map[string]struct{})
    for _, t := range p.Tunnels {
        st, ok := c.tunnelStates[t.ID]
        if !ok {
            st = &TunnelState{
                ID:        t.ID,
                Tag:       t.Tag,
                EntryPort: t.EntryPort,
                MapPort:   t.MapPortHint,
                Active:    true,
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
    }
    for id, st := range c.tunnelStates {
        if _, ok := seen[id]; !ok {
            // mark removed as inactive
            st.Active = false
            st.LastChange = time.Now()
        }
    }
    // restart the simulated connector
    if c.stopCh != nil {
        close(c.stopCh)
    }
    c.stopCh = make(chan struct{})
    go c.run(c.stopCh)
    return nil
}

func (c *Connector) run(stop <-chan struct{}) {
    // simulate connect
    c.setConnected(false, "initializing")
    time.Sleep(1 * time.Second)
    c.setConnected(true, "connected")
    c.logs.Broadcast(fmt.Sprintf("{\"event\":\"connected\",\"ts\":%d}", time.Now().Unix()))
    // simulate occasional reconnects
    ticker := time.NewTicker(45 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-stop:
            return
        case <-ticker.C:
            if rand.Intn(4) == 0 { // 25% chance
                c.setConnected(false, "transient network error")
                c.logs.Broadcast(fmt.Sprintf("{\"event\":\"reconnect\",\"reason\":\"transient\",\"ts\":%d}", time.Now().Unix()))
                c.reconnects++
                backoff := time.Duration(1+rand.Intn(3)) * time.Second
                time.Sleep(backoff)
                c.setConnected(true, "reconnected")
            }
        }
    }
}

func (c *Connector) setConnected(ok bool, reason string) {
    c.mu.Lock()
    c.connected = ok
    if ok { c.lastErr = "" } else { c.lastErr = reason }
    c.mu.Unlock()
}

func (c *Connector) Status() map[string]any {
    c.mu.RLock(); defer c.mu.RUnlock()
    return map[string]any{
        "connected": c.connected,
        "reconnects": c.reconnects,
        "lastError": c.lastErr,
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
    c.mu.RLock(); defer c.mu.RUnlock()
    out := make([]TunnelState, 0, len(c.tunnelStates))
    for _, st := range c.tunnelStates {
        status := "disconnected"
        if c.connected && st.Active { status = "connected" }
        out = append(out, TunnelState{
            ID: st.ID, Tag: st.Tag, EntryPort: st.EntryPort, MapPort: st.MapPort, Target: st.Target, Active: st.Active, Status: status, LastChange: st.LastChange,
        })
    }
    return out
}

func (c *Connector) getTunnel(id string) (TunnelState, bool) {
    c.mu.RLock(); defer c.mu.RUnlock()
    st, ok := c.tunnelStates[id]
    if !ok { return TunnelState{}, false }
    status := "disconnected"
    if c.connected && st.Active { status = "connected" }
    return TunnelState{ID: st.ID, Tag: st.Tag, EntryPort: st.EntryPort, MapPort: st.MapPort, Target: st.Target, Active: st.Active, Status: status, LastChange: st.LastChange}, true
}

func (c *Connector) patchTunnel(id string, mapPort *int, active *bool, target *string) (TunnelState, bool) {
    c.mu.Lock(); defer c.mu.Unlock()
    st, ok := c.tunnelStates[id]
    if !ok { return TunnelState{}, false }
    if mapPort != nil {
        st.MapPort = *mapPort
        if st.Target == "" || isLocalhostTarget(st.Target) {
            st.Target = defaultTargetFromMapPort(st.MapPort)
        }
    }
    if active != nil { st.Active = *active }
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
    if c.connected && st.Active { status = "connected" }
    return TunnelState{ID: st.ID, Tag: st.Tag, EntryPort: st.EntryPort, MapPort: st.MapPort, Target: st.Target, Active: st.Active, Status: status, LastChange: st.LastChange}, true
}

func (c *Connector) deleteTunnel(id string) bool {
    c.mu.Lock(); defer c.mu.Unlock()
    st, ok := c.tunnelStates[id]
    if !ok { return false }
    st.Active = false
    st.LastChange = time.Now()
    return true
}

type Server struct {
    addr   string
    conn   *Connector
    logs   *shared.SSEHub
    access *shared.SSEHub
    errors *shared.SSEHub
    uiFS   http.FileSystem
    start  time.Time
    logDir string
    accessPath string
    errorPath  string
    tailAccess *shared.FileTailer
    tailError  *shared.FileTailer
}

func (s *Server) routes() http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
    mux.Handle("/logs/stream", s.logs)
    mux.Handle("/logs/access/stream", s.access)
    mux.Handle("/logs/error/stream", s.errors)

    // Tail N lines of logs
    mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        typ := r.URL.Query().Get("type")
        nStr := r.URL.Query().Get("tail")
        if nStr == "" { nStr = "200" }
        n, _ := strconv.Atoi(nStr)
        var p string
        switch typ {
        case "access": p = s.accessPath
        case "error":  p = s.errorPath
        default:
            http.Error(w, "query type=access|error", 400); return
        }
        lines, err := shared.TailLastN(p, n, 2*1024*1024)
        if err != nil { http.Error(w, err.Error(), 500); return }
        writeJSON(w, map[string]any{"type": typ, "path": p, "lines": lines})
    })

    // Optional: reality helper endpoints (mirror of XRPS for local tooling)
    mux.HandleFunc("/api/reality/x25519", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        curve := ecdh.X25519()
        priv, err := curve.GenerateKey(crand.Reader)
        if err != nil { http.Error(w, err.Error(), 500); return }
        pub := priv.PublicKey()
        writeJSON(w, map[string]string{
            "publicKey":  base64.StdEncoding.EncodeToString(pub.Bytes()),
            "privateKey": base64.StdEncoding.EncodeToString(priv.Bytes()),
        })
    })
    mux.HandleFunc("/api/reality/mldsa65", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        b := make([]byte, 32)
        _, _ = crand.Read(b)
        h := sha256.Sum256(b)
        writeJSON(w, map[string]string{
            "seed":     base64.StdEncoding.EncodeToString(b),
            "seedHex":  hex.EncodeToString(b),
            "verifyHex": hex.EncodeToString(h[:]),
        })
    })

    if s.uiFS != nil {
      mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(s.uiFS)))
    }

    mux.HandleFunc("/api/profile/apply", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
        // accept raw base64 string or {"base64":"..."}
        var base64 string
        ct := r.Header.Get("Content-Type")
        if ct == "text/plain" || ct == "application/octet-stream" {
            buf := make([]byte, 0, 4096)
            tmp := make([]byte, 1024)
            for {
                n, err := r.Body.Read(tmp)
                if n > 0 { buf = append(buf, tmp[:n]...) }
                if err != nil { break }
            }
            base64 = string(buf)
        } else {
            var body struct{ Base64 string `json:"base64"` }
            if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, err.Error(), 400); return }
            base64 = body.Base64
        }
        p, err := shared.DecodeParamsB64(stringsTrim(base64))
        if err != nil { http.Error(w, err.Error(), 400); return }
        if err := s.conn.ApplyParams(p); err != nil { http.Error(w, err.Error(), 500); return }
        s.logs.Broadcast(fmt.Sprintf("{\"event\":\"profile_applied\",\"ts\":%d}", time.Now().Unix()))
        writeJSON(w, map[string]any{"ok": true})
    })

    mux.HandleFunc("/api/profile/active", func(w http.ResponseWriter, r *http.Request) {
        s.conn.mu.RLock(); defer s.conn.mu.RUnlock()
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

    // tunnels: list/detail/patch/delete
    mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        writeJSON(w, s.conn.listTunnels())
    })
    mux.HandleFunc("/api/tunnels/", func(w http.ResponseWriter, r *http.Request) {
        id := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
        if id == "" { http.NotFound(w, r); return }
        switch r.Method {
        case http.MethodGet:
            if st, ok := s.conn.getTunnel(id); ok { writeJSON(w, st); return }
            http.NotFound(w, r)
        case http.MethodPatch:
            var body struct { MapPort *int `json:"map_port"`; Active *bool `json:"active"`; Target *string `json:"target"` }
            if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, err.Error(), 400); return }
            if st, ok := s.conn.patchTunnel(id, body.MapPort, body.Active, body.Target); ok { writeJSON(w, st); return }
            http.NotFound(w, r)
        case http.MethodDelete:
            if s.conn.deleteTunnel(id) { w.WriteHeader(http.StatusNoContent); return }
            http.NotFound(w, r)
        default:
            http.Error(w, "method not allowed", 405)
        }
    })

    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" { http.NotFound(w, r); return }
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, "<!doctype html><title>XRPC</title><h1>XRPC running</h1><p>Paste Base64 to /api/profile/apply. Logs: /api/logs?type=access|error&tail=N, SSE: /logs/access/stream /logs/error/stream</p>")
    })

    return withCORS(mux)
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
    if port <= 0 { port = 80 }
    return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// splitHostPort parses host:port into (host, port, ok)
func splitHostPort(target string) (string, int, bool) {
    host, p, err := net.SplitHostPort(target)
    if err != nil { return "", 0, false }
    pi, err := strconv.Atoi(p)
    if err != nil { return "", 0, false }
    return host, pi, true
}

// isLocalhostTarget returns true if target host is a loopback address
func isLocalhostTarget(target string) bool {
    host, _, ok := splitHostPort(target)
    if !ok { return false }
    if host == "localhost" { return true }
    ip := net.ParseIP(host)
    return ip != nil && ip.IsLoopback()
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

func main() {
    addr := flag.String("addr", ":8081", "listen address")
    flag.Parse()
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)

    logs := shared.NewSSEHub()
    conn := NewConnector(logs)
    s := &Server{addr: *addr, conn: conn, logs: logs, access: shared.NewSSEHub(), errors: shared.NewSSEHub(), start: time.Now()}
    // Logging paths (dev default ./logs; override via XRPC_LOG_DIR)
    logDir := os.Getenv("XRPC_LOG_DIR")
    if logDir == "" { logDir = "./logs" }
    _ = os.MkdirAll(logDir, 0o755)
    s.logDir = logDir
    s.accessPath = filepath.Join(logDir, "access.log")
    s.errorPath = filepath.Join(logDir, "error.log")
    if _, err := os.Stat(s.accessPath); os.IsNotExist(err) { _ = os.WriteFile(s.accessPath, []byte(""), 0o644) }
    if _, err := os.Stat(s.errorPath); os.IsNotExist(err) { _ = os.WriteFile(s.errorPath, []byte(""), 0o644) }
    // Start tailers
    s.tailAccess = shared.NewFileTailer(s.accessPath, 1*time.Second)
    s.tailError  = shared.NewFileTailer(s.errorPath, 1*time.Second)
    s.tailAccess.Start()
    s.tailError.Start()
    go func() { for line := range s.tailAccess.Out() { s.access.Broadcast(line) } }()
    go func() { for line := range s.tailError.Out()  { s.errors.Broadcast(line) } }()
    if dir := os.Getenv("XRPC_UI_DIR"); dir != "" {
        if st, err := os.Stat(dir); err == nil && st.IsDir() {
            s.uiFS = http.Dir(dir)
            log.Printf("serving static UI at /ui/ from %s", dir)
        }
    }

    srv := &http.Server{Addr: s.addr, Handler: s.routes()}
    log.Printf("XRPC listening on %s", s.addr)
    if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        log.Printf("server error: %v", err)
        os.Exit(1)
    }
    _ = srv.Shutdown(context.Background())
}
