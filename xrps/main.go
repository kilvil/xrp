package main

import (
    "context"
    crand "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "encoding/base64"
    "crypto/ecdh"
    mrand "math/rand"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"

    "xrp/internal/shared"
)

// Tunnel model in XRPS storage
type Tunnel struct {
    ID        string                 `json:"id"`
    Name      string                 `json:"name"`
    Portal    string                 `json:"portal_addr"`
    Handshake shared.HandshakeConfig `json:"handshake"`
    Entries   []shared.TunnelEntry   `json:"entries"`
    Forward   shared.ForwardConfig   `json:"forward"`
    CreatedAt time.Time              `json:"createdAt"`
    UpdatedAt time.Time              `json:"updatedAt"`
}

// In-memory store (v1)
type Store struct {
    mu      sync.RWMutex
    tunnels map[string]*Tunnel
}

func NewStore() *Store { return &Store{tunnels: map[string]*Tunnel{}} }

func (s *Store) Add(t *Tunnel) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.tunnels[t.ID] = t
}
func (s *Store) Get(id string) (*Tunnel, bool) {
    s.mu.RLock(); defer s.mu.RUnlock(); t, ok := s.tunnels[id]; return t, ok
}
func (s *Store) All() []*Tunnel {
    s.mu.RLock(); defer s.mu.RUnlock()
    out := make([]*Tunnel, 0, len(s.tunnels))
    for _, t := range s.tunnels { out = append(out, t) }
    return out
}

func (s *Store) Delete(id string) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    if _, ok := s.tunnels[id]; ok {
        delete(s.tunnels, id)
        return true
    }
    return false
}

// API payloads
type createTunnelReq struct {
    Name          string `json:"name"`
    PortalAddr    string `json:"portal_addr"`
    HandshakePort int    `json:"handshake_port"`
    ServerName    string `json:"server_name"`
    Encryption    string `json:"encryption"` // pq|x25519|none
    EntryPorts    []int  `json:"entry_ports"`
    EnableForward bool   `json:"enable_forward"`
    ForwardPort   int    `json:"forward_port"`
    // Optional REALITY advanced inputs (if empty, server will randomize)
    PublicKey     string `json:"public_key,omitempty"`
    ShortID       string `json:"short_id,omitempty"`
}

type connectionParamsResp struct {
    JSON string `json:"json"`
    B64  string `json:"base64"`
}

type Server struct {
    addr   string
    store  *Store
    logs   *shared.SSEHub
    access *shared.SSEHub
    errors *shared.SSEHub
    uiFS   http.FileSystem
    srv    *http.Server
    start  time.Time
    logDir string
    accessPath string
    errorPath  string
    tailAccess *shared.FileTailer
    tailError  *shared.FileTailer
}

func randomHex(n int) string { b := make([]byte, n); _, _ = crand.Read(b); return hex.EncodeToString(b) }

func randomUUID() string {
    // simple uuid v4
    b := make([]byte, 16)
    _, _ = crand.Read(b)
    b[6] = (b[6] & 0x0f) | 0x40
    b[8] = (b[8] & 0x3f) | 0x80
    return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// genX25519 returns base64-encoded public and private keys
func genX25519() (string, string, error) {
    c := ecdh.X25519()
    priv, err := c.GenerateKey(crand.Reader)
    if err != nil { return "", "", err }
    pub := priv.PublicKey()
    pb := pub.Bytes()
    pr := priv.Bytes()
    return base64.StdEncoding.EncodeToString(pb), base64.StdEncoding.EncodeToString(pr), nil
}

// genMLDSA65 returns pseudo seed/verify (placeholder without PQ crypto)
func genMLDSA65() (seed string, verify string) {
    b := make([]byte, 32)
    _, _ = crand.Read(b)
    seed = hex.EncodeToString(b)
    h := sha256.Sum256(b)
    verify = hex.EncodeToString(h[:])
    return
}

func (s *Server) routes() http.Handler {
    mux := http.NewServeMux()

    // health
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

    // logs stream (SSE)
    mux.Handle("/logs/stream", s.logs)
    mux.Handle("/logs/access/stream", s.access)
    mux.Handle("/logs/error/stream", s.errors)

    // tail last N lines of access/error
    mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        typ := r.URL.Query().Get("type")
        nStr := r.URL.Query().Get("tail")
        if nStr == "" { nStr = "200" }
        n, _ := strconv.Atoi(nStr)
        var p string
        switch typ {
        case "access": p = s.accessPath
        case "error": p = s.errorPath
        default:
            http.Error(w, "query type=access|error", 400); return
        }
        lines, err := shared.TailLastN(p, n, 2*1024*1024)
        if err != nil { http.Error(w, err.Error(), 500); return }
        writeJSON(w, map[string]any{"type": typ, "path": p, "lines": lines})
    })

    // reality helpers
    mux.HandleFunc("/api/reality/x25519", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        pub, priv, err := genX25519()
        if err != nil { http.Error(w, err.Error(), 500); return }
        writeJSON(w, map[string]string{"publicKey": pub, "privateKey": priv})
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

    // optional static UI under /ui/
    if s.uiFS != nil {
        mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(s.uiFS)))
    }

    // list tunnels
    mux.HandleFunc("/api/tunnels", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case http.MethodGet:
            writeJSON(w, s.store.All())
        case http.MethodPost:
            var req createTunnelReq
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, err.Error(), 400); return }
            if req.HandshakePort <= 0 || req.ServerName == "" || len(req.EntryPorts) == 0 {
                http.Error(w, "invalid payload", 400); return
            }
            id := randomHex(6)
            // generate REALITY keys (public only in params); privateKey kept server-side (placeholder)
            // For v1 skeleton, use random hex as publicKey/shortId
            h := shared.HandshakeConfig{
                Port:       req.HandshakePort,
                ServerName: req.ServerName,
                PublicKey:  req.PublicKey,
                ShortID:    req.ShortID,
                Encryption: req.Encryption,
                Flow:       "xtls-rprx-vision",
            }
            if h.PublicKey == "" { h.PublicKey = randomHex(32) }
            if h.ShortID == "" { h.ShortID = randomHex(8) }
            entries := make([]shared.TunnelEntry, 0, len(req.EntryPorts))
            for i, ep := range req.EntryPorts {
                entries = append(entries, shared.TunnelEntry{
                    EntryPort:   ep,
                    ID:          randomUUID(),
                    Tag:         fmt.Sprintf("t%d", i+1),
                    MapPortHint: 80 + i,
                })
            }
            fwd := shared.ForwardConfig{}
            if req.EnableForward {
                fwd = shared.ForwardConfig{
                    Enabled:    true,
                    Port:       req.ForwardPort,
                    ID:         randomUUID(),
                    ServerName: req.ServerName,
                    PublicKey:  randomHex(32),
                    ShortID:    randomHex(8),
                    Flow:       "xtls-rprx-vision",
                }
            }
            t := &Tunnel{ID: id, Name: req.Name, Portal: req.PortalAddr, Handshake: h, Entries: entries, Forward: fwd, CreatedAt: time.Now(), UpdatedAt: time.Now()}
            s.store.Add(t)
            s.logs.Broadcast(fmt.Sprintf("{\"event\":\"tunnel_created\",\"id\":\"%s\",\"ts\":%d}", id, time.Now().Unix()))
            writeJSON(w, t)
        default:
            http.Error(w, "method not allowed", 405)
        }
    })

    // get tunnel, generate connection params
    mux.HandleFunc("/api/tunnels/", func(w http.ResponseWriter, r *http.Request) {
        path := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
        segs := strings.Split(path, "/")
        if len(segs) < 1 || segs[0] == "" { http.NotFound(w, r); return }
        id := segs[0]
        t, ok := s.store.Get(id)
        if !ok { http.Error(w, "not found", 404); return }
        if len(segs) == 1 {
            switch r.Method {
            case http.MethodGet:
                writeJSON(w, t)
                return
            case http.MethodDelete:
                if s.store.Delete(id) {
                    w.WriteHeader(http.StatusNoContent)
                    return
                }
                http.Error(w, "not found", 404)
                return
            case http.MethodPatch:
                type patchTunnelReq struct {
                    Name          *string `json:"name,omitempty"`
                    PortalAddr    *string `json:"portal_addr,omitempty"`
                    HandshakePort *int    `json:"handshake_port,omitempty"`
                    ServerName    *string `json:"server_name,omitempty"`
                    Encryption    *string `json:"encryption,omitempty"`
                    EntryPorts    *[]int  `json:"entry_ports,omitempty"`
                    EnableForward *bool   `json:"enable_forward,omitempty"`
                    ForwardPort   *int    `json:"forward_port,omitempty"`
                }
                var req patchTunnelReq
                if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, err.Error(), 400); return }
                // apply changes
                if req.Name != nil { t.Name = *req.Name }
                if req.PortalAddr != nil { t.Portal = *req.PortalAddr }
                if req.HandshakePort != nil { t.Handshake.Port = *req.HandshakePort }
                if req.ServerName != nil {
                    t.Handshake.ServerName = *req.ServerName
                    // optionally align forward SNI if enabled
                    if t.Forward.Enabled {
                        t.Forward.ServerName = *req.ServerName
                    }
                }
                if req.Encryption != nil { t.Handshake.Encryption = *req.Encryption }
                if req.EntryPorts != nil {
                    // rebuild entries from provided ports
                    ports := *req.EntryPorts
                    entries := make([]shared.TunnelEntry, 0, len(ports))
                    for i, ep := range ports {
                        entries = append(entries, shared.TunnelEntry{
                            EntryPort:   ep,
                            ID:          randomUUID(),
                            Tag:         fmt.Sprintf("t%d", i+1),
                            MapPortHint: 80 + i,
                        })
                    }
                    t.Entries = entries
                }
                if req.EnableForward != nil {
                    if *req.EnableForward {
                        if !t.Forward.Enabled {
                            t.Forward.Enabled = true
                            if t.Forward.ID == "" { t.Forward.ID = randomUUID() }
                            if t.Forward.ServerName == "" { t.Forward.ServerName = t.Handshake.ServerName }
                            if t.Forward.PublicKey == "" { t.Forward.PublicKey = randomHex(32) }
                            if t.Forward.ShortID == "" { t.Forward.ShortID = randomHex(8) }
                            if t.Forward.Flow == "" { t.Forward.Flow = "xtls-rprx-vision" }
                        }
                    } else {
                        t.Forward.Enabled = false
                    }
                }
                if req.ForwardPort != nil { t.Forward.Port = *req.ForwardPort }
                t.UpdatedAt = time.Now()
                writeJSON(w, t)
                return
            default:
                http.Error(w, "method not allowed", 405)
                return
            }
        }
        if len(segs) == 2 && segs[1] == "connection-params" && r.Method == http.MethodPost {
            params := shared.ConnectionParams{
                Version:    1,
                PortalAddr: t.Portal,
                Handshake:  t.Handshake,
                Tunnels:    t.Entries,
                Forward:    t.Forward,
                Meta:       map[string]any{"tunnelId": t.ID, "name": t.Name, "createdAt": t.CreatedAt},
            }
            if err := params.Validate(); err != nil { http.Error(w, err.Error(), 400); return }
            js, b64, err := shared.EncodeParamsB64(&params)
            if err != nil { http.Error(w, err.Error(), 500); return }
            writeJSON(w, connectionParamsResp{JSON: js, B64: b64})
            return
        }
        http.NotFound(w, r)
    })

    // simple status
    mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, map[string]any{
            "uptime":   time.Since(s.start).String(),
            "tunnels":  len(s.store.All()),
            "now":      time.Now().Format(time.RFC3339),
        })
    })

    // UI root placeholder
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" { http.NotFound(w, r); return }
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        fmt.Fprintf(w, "<!doctype html><title>XRPS</title><h1>XRPS running</h1><p>APIs: /healthz, /api/tunnels, /logs/stream, /api/logs?type=access|error&tail=N, /logs/access/stream, /logs/error/stream</p>")
    })

    return withCORS(mux)
}

func writeJSON(w http.ResponseWriter, v any) {
    w.Header().Set("Content-Type", "application/json")
    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    _ = enc.Encode(v)
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
    addr := flag.String("addr", ":8080", "listen address")
    flag.Parse()
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)

    s := &Server{addr: *addr, store: NewStore(), logs: shared.NewSSEHub(), access: shared.NewSSEHub(), errors: shared.NewSSEHub(), start: time.Now()}
    // configure log paths (dev default ./logs; prod can set XRPS_LOG_DIR)
    logDir := os.Getenv("XRPS_LOG_DIR")
    if logDir == "" { logDir = "./logs" }
    _ = os.MkdirAll(logDir, 0o755)
    s.logDir = logDir
    s.accessPath = filepath.Join(logDir, "access.log")
    s.errorPath = filepath.Join(logDir, "error.log")
    if _, err := os.Stat(s.accessPath); os.IsNotExist(err) { _ = os.WriteFile(s.accessPath, []byte(""), 0o644) }
    if _, err := os.Stat(s.errorPath); os.IsNotExist(err) { _ = os.WriteFile(s.errorPath, []byte(""), 0o644) }
    // start tailers to feed SSE
    s.tailAccess = shared.NewFileTailer(s.accessPath, 1*time.Second)
    s.tailError = shared.NewFileTailer(s.errorPath, 1*time.Second)
    s.tailAccess.Start()
    s.tailError.Start()
    go func() { for line := range s.tailAccess.Out() { s.access.Broadcast(line) } }()
    go func() { for line := range s.tailError.Out() { s.errors.Broadcast(line) } }()
    if dir := os.Getenv("XRPS_UI_DIR"); dir != "" {
        if st, err := os.Stat(dir); err == nil && st.IsDir() {
            s.uiFS = http.Dir(dir)
            log.Printf("serving static UI at /ui/ from %s", dir)
        }
    }

    // background: demo events
    go func() {
        for {
            time.Sleep(time.Duration(10+mrand.Intn(10)) * time.Second)
            s.logs.Broadcast(fmt.Sprintf("{\"event\":\"tick\",\"ts\":%d}", time.Now().Unix()))
        }
    }()

    srv := &http.Server{Addr: s.addr, Handler: s.routes()}
    s.srv = srv
    log.Printf("XRPS listening on %s", s.addr)
    if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        log.Printf("server error: %v", err)
        os.Exit(1)
    }

    // graceful (unreached in this minimal main)
    _ = srv.Shutdown(context.Background())
}
