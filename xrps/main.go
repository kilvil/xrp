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

// Tunnel model in XRPS storage
type Tunnel struct {
    ID        string                 `json:"id"`
    Name      string                 `json:"name"`
    Portal    string                 `json:"portal_addr"`
    Handshake shared.HandshakeConfig `json:"handshake"`
    Entries   []shared.TunnelEntry   `json:"entries"`
    Forward   shared.ForwardConfig   `json:"forward"`
    // PrivKey: REALITY private key (base64url, 32 bytes). Not exposed.
    PrivKey   string                 `json:"-"`
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
    // Optional: allow client to return private key generated via /api/reality/x25519
    // Must be base64url (no padding) 32 bytes. When provided, server will store
    // it and derive/override the corresponding public key.
    PrivateKey    string `json:"private_key,omitempty"`
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
    orch  *coreembed.Orchestrator
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
// genX25519 returns base64url (no padding) encoded public and private keys
func genX25519() (string, string, error) {
    c := ecdh.X25519()
    priv, err := c.GenerateKey(crand.Reader)
    if err != nil { return "", "", err }
    pub := priv.PublicKey()
    pb := pub.Bytes()
    pr := priv.Bytes()
    return base64.RawURLEncoding.EncodeToString(pb), base64.RawURLEncoding.EncodeToString(pr), nil
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

// normalizeRealityKey32 ensures the REALITY key is base64url (no padding) of 32 bytes.
func normalizeRealityKey32(s string) (string, error) {
    s = strings.TrimSpace(s)
    if s == "" { return "", fmt.Errorf("empty REALITY key") }
    if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 {
        return base64.RawURLEncoding.EncodeToString(b), nil
    }
    if b, err := base64.URLEncoding.DecodeString(s); err == nil && len(b) == 32 {
        return base64.RawURLEncoding.EncodeToString(b), nil
    }
    if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
        return base64.RawURLEncoding.EncodeToString(b), nil
    }
    if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
        return base64.RawURLEncoding.EncodeToString(b), nil
    }
    return "", fmt.Errorf("invalid REALITY key: expect 32-byte base64url")
}

// sanitizeVLESSEncryption ensures it matches xray-core expectations.
// Allowed simple: "none"; advanced PQ: strings starting with "mlkem768x25519plus.".
func sanitizeVLESSEncryption(s string) string {
    s = strings.TrimSpace(strings.ToLower(s))
    if s == "none" { return s }
    if strings.HasPrefix(s, "mlkem768x25519plus.") { return s }
    return "none"
}

func (s *Server) routes() http.Handler {
    mux := http.NewServeMux()

    // health
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

    // logs stream (SSE)
    mux.Handle("/logs/stream", s.logs)
    mux.HandleFunc("/logs/access/stream", s.handleLogStream("access"))
    mux.HandleFunc("/logs/error/stream", s.handleLogStream("error"))

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

    // core control
    mux.HandleFunc("/api/core/restart", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
        s.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_restart\",\"ts\":%d}", time.Now().Unix()))
        if err := s.restartCore(); err != nil {
            http.Error(w, "core restart failed: "+err.Error(), 500); return
        }
        writeJSON(w, map[string]any{"ok": true, "message": "restart ok"})
    })

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
            if strings.EqualFold(req.Encryption, "pq") {
                http.Error(w, "encryption 'pq' is not supported; use 'none' or 'mlkem768x25519plus.*'", 400); return
            }
            id := randomHex(6)
            // Prepare handshake; derive publicKey from server privateKey if set, else normalize input or generate one
            h := shared.HandshakeConfig{
                Port:       req.HandshakePort,
                ServerName: req.ServerName,
                PublicKey:  req.PublicKey,
                ShortID:    req.ShortID,
                Encryption: sanitizeVLESSEncryption(req.Encryption),
                Flow:       "xtls-rprx-vision",
            }
            var privKey string
            // If client provided a private key (preferred flow when FE fetched from BE),
            // normalize and derive publicKey from it to ensure consistency.
            if pk := strings.TrimSpace(req.PrivateKey); pk != "" {
                norm, err := normalizeRealityKey32(pk)
                if err != nil {
                    http.Error(w, "invalid private_key: expect base64url 32 bytes", 400); return
                }
                privKey = norm
                if b, err := base64.RawURLEncoding.DecodeString(norm); err == nil && len(b) == 32 {
                    if sk, err := ecdh.X25519().NewPrivateKey(b); err == nil {
                        pub := sk.PublicKey().Bytes()
                        h.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
                    }
                }
            }
            // Derive from env private key if available
            if privKey == "" && (strings.TrimSpace(os.Getenv("XRPS_REALITY_PRIVATE_KEY")) != "" || strings.TrimSpace(os.Getenv("XRAY_REALITY_PRIVATE_KEY")) != "") {
                priv := strings.TrimSpace(os.Getenv("XRPS_REALITY_PRIVATE_KEY"))
                if priv == "" { priv = os.Getenv("XRAY_REALITY_PRIVATE_KEY") }
                if norm, err := normalizeRealityKey32(priv); err == nil {
                    privKey = norm
                    if b, err := base64.RawURLEncoding.DecodeString(norm); err == nil && len(b) == 32 {
                        if pk, err := ecdh.X25519().NewPrivateKey(b); err == nil {
                            pub := pk.PublicKey().Bytes()
                            h.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
                        }
                    }
                }
            }
            if h.PublicKey == "" {
                // If request provided, try to normalize; else generate a new pair (for preview; won't match server unless env set)
                if req.PublicKey != "" {
                    if norm, err := normalizeRealityKey32(req.PublicKey); err == nil { h.PublicKey = norm }
                }
            }
            if h.PublicKey == "" {
                pub, priv, _ := genX25519()
                h.PublicKey = pub
                privKey = priv
            }
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
                    PublicKey:  h.PublicKey,
                    ShortID:    randomHex(8),
                    Flow:       "xtls-rprx-vision",
                }
            }
            t := &Tunnel{ID: id, Name: req.Name, Portal: req.PortalAddr, Handshake: h, Entries: entries, Forward: fwd, PrivKey: privKey, CreatedAt: time.Now(), UpdatedAt: time.Now()}
            s.store.Add(t)
            // restart core to apply updated portal config (best-effort)
            if err := s.restartCore(); err != nil {
                log.Printf("restart after tunnel create failed: %v", err)
            }
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
                    PrivateKey    *string `json:"private_key,omitempty"`
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
                if req.Encryption != nil {
                    if strings.EqualFold(*req.Encryption, "pq") {
                        http.Error(w, "encryption 'pq' is not supported; use 'none' or 'mlkem768x25519plus.*'", 400); return
                    }
                    t.Handshake.Encryption = sanitizeVLESSEncryption(*req.Encryption)
                }
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
                if req.PrivateKey != nil {
                    pk := strings.TrimSpace(*req.PrivateKey)
                    if pk == "" {
                        t.PrivKey = ""
                    } else {
                        norm, err := normalizeRealityKey32(pk)
                        if err != nil { http.Error(w, "invalid private_key: expect base64url 32 bytes", 400); return }
                        t.PrivKey = norm
                        if b, err := base64.RawURLEncoding.DecodeString(norm); err == nil && len(b) == 32 {
                            if sk, err := ecdh.X25519().NewPrivateKey(b); err == nil {
                                pub := sk.PublicKey().Bytes()
                                t.Handshake.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
                            }
                        }
                    }
                }
                t.UpdatedAt = time.Now()
                if err := s.restartCore(); err != nil {
                    log.Printf("restart after tunnel patch failed: %v", err)
                }
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

// handleLogStream streams the full file from the beginning, then follows new lines via SSEHub.
func (s *Server) handleLogStream(which string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/event-stream")
        w.Header().Set("Cache-Control", "no-cache")
        w.Header().Set("Connection", "keep-alive")
        flusher, ok := w.(http.Flusher)
        if !ok { http.Error(w, "streaming unsupported", http.StatusInternalServerError); return }

        // initial replay of entire file
        var path string
        var hub *shared.SSEHub
        switch which {
        case "access": path, hub = s.accessPath, s.access
        case "error": path, hub = s.errorPath, s.errors
        default:
            http.Error(w, "invalid log type", 400); return
        }
        lines, _ := shared.TailLastN(path, 0, 0)
        for _, ln := range lines {
            fmt.Fprintf(w, "data: %s\n\n", ln)
        }
        flusher.Flush()

        // subscribe to future lines
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
                if !ok { return }
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
    log.Printf("==== XRPS startup ====")
    log.Printf("Addr: %s", s.addr)
    if s.uiFS != nil {
        log.Printf("UI: enabled at /ui/")
    } else {
        log.Printf("UI: disabled (XRPS_UI_DIR not set)")
    }
    if s.logDir != "" {
        log.Printf("LogDir: %s", s.logDir)
        log.Printf("  access: %s", s.accessPath)
        log.Printf("  error:  %s", s.errorPath)
    }
    log.Printf("APIs:")
    log.Printf("  /healthz  /status")
    log.Printf("  /api/tunnels  /api/tunnels/:id  /api/tunnels/:id/connection-params")
    log.Printf("  /api/logs?type=access|error&tail=N")
    log.Printf("SSE:")
    log.Printf("  /logs/stream  /logs/access/stream  /logs/error/stream")
}

// startCore starts embedded xray-core with the current generated config.
// Set env XRPS_CORE_FAIL=true to simulate失败路径用于验证。
func (s *Server) startCore() error {
    log.Printf("xray-core: starting…")
    fail := os.Getenv("XRPS_CORE_FAIL")
    if strings.EqualFold(fail, "1") || strings.EqualFold(fail, "true") || strings.EqualFold(fail, "yes") {
        err := fmt.Errorf("simulated failure (XRPS_CORE_FAIL=%s)", fail)
        log.Printf("xray-core: start failed: %v", err)
        s.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_failed\",\"reason\":\"startup\",\"ts\":%d}", time.Now().Unix()))
        return err
    }
    if s.orch == nil { s.orch = coreembed.New() }
    runDir := os.Getenv("XRPS_XRAY_RUN_DIR")
    if runDir == "" { runDir = s.logDir }
    // Choose a free API port to avoid conflicts with user's xray
    apiPort := getenvInt("XRPS_XRAY_API_PORT", 10085)
    apiPort = chooseFreePort(apiPort)
    // Build portal config from current tunnels; fallback to minimal when none/invalid
    cfg, err := s.buildPortalConfig(apiPort)
    if err != nil {
        log.Printf("xray-core: build portal config failed, using minimal: %v", err)
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
    if p := os.Getenv("XRAY_CFG_PORTAL"); p != "" {
        if b, err := os.ReadFile(p); err == nil { cfg = b } else { log.Printf("xray-core: warn cannot read XRAY_CFG_PORTAL=%s: %v", p, err) }
    }
    // Print effective config for debugging
    log.Printf("xray-core: effective portal config:\n%s", string(cfg))
    // Write debug copy
    cfgPath := os.Getenv("XRPS_XRAY_CFG_PATH")
    if cfgPath == "" { cfgPath = filepath.Join(runDir, "xray.portal.json") }
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
    runDir := os.Getenv("XRPS_XRAY_RUN_DIR")
    if runDir == "" { runDir = s.logDir }
    apiPort := getenvInt("XRPS_XRAY_API_PORT", 10085)
    apiPort = chooseFreePort(apiPort)
    // Build portal config from current tunnels; fallback to minimal when none/invalid
    cfg, err := s.buildPortalConfig(apiPort)
    if err != nil {
        log.Printf("xray-core: build portal config failed, using minimal: %v", err)
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
    if p := os.Getenv("XRAY_CFG_PORTAL"); p != "" {
        if b, err := os.ReadFile(p); err == nil { cfg = b } else { log.Printf("xray-core: warn cannot read XRAY_CFG_PORTAL=%s: %v", p, err) }
    }
    // Print effective config for debugging on restart
    log.Printf("xray-core: effective portal config (restart):\n%s", string(cfg))
    cfgPath := filepath.Join(runDir, "xray.portal.json")
    _ = os.WriteFile(cfgPath, cfg, 0o644)
    if err := s.orch.RestartJSON(cfg); err != nil {
        log.Printf("xray-core: restart failed: %v", err)
        return err
    }
    log.Printf("xray-core: restart ok")
    return nil
}

// buildPortalConfig constructs an xray JSON config reflecting current tunnels.
// It follows PRD: VLESS+REALITY handshake inbound + per-entry tunnel inbounds
// routed to dynamic reverse outbounds exposed via clients[].reverse.tag.
func (s *Server) buildPortalConfig(apiPort int) ([]byte, error) {
    // pick the most recently updated tunnel as the active profile
    tunnels := s.store.All()
    if len(tunnels) == 0 {
        return nil, fmt.Errorf("no tunnels")
    }
    active := tunnels[0]
    for _, t := range tunnels {
        if t.UpdatedAt.After(active.UpdatedAt) {
            active = t
        }
    }

    // Prepare inbound: external-vless (handshake)
    clients := make([]map[string]any, 0, len(active.Entries))
    rules := make([]map[string]any, 0, len(active.Entries))
    inbounds := make([]map[string]any, 0, 2+len(active.Entries))

    // api inbound for local diagnostics (kept for parity with current behavior)
    inbounds = append(inbounds, map[string]any{
        "tag":     "api",
        "listen":  "127.0.0.1",
        "port":    apiPort,
        "protocol": "dokodemo-door",
        "settings": map[string]any{"address": "127.0.0.1", "port": 1},
    })

    for i, e := range active.Entries {
        idx := i + 1
        // Each entry exposes a reverse outbound tag r-outbound-{i}
        clients = append(clients, map[string]any{
            "email":   fmt.Sprintf("bridge-rev-%d", idx),
            "id":      e.ID,
            "flow":    nonEmpty(active.Handshake.Flow, "xtls-rprx-vision"),
            "level":   0,
            "reverse": map[string]any{"tag": fmt.Sprintf("r-outbound-%d", idx)},
        })
        // Tunnel inbound on entry port
        inbounds = append(inbounds, map[string]any{
            "listen":   "0.0.0.0",
            "port":     e.EntryPort,
            "protocol": "tunnel",
            "tag":      fmt.Sprintf("t-inbound-%d", idx),
        })
        // Route tunnel inbound directly to dynamic reverse outbound tag; before client connects this tag doesn't exist, so requests will be dropped with a warning.
        rules = append(rules, map[string]any{
            "type":        "field",
            "inboundTag":  []string{fmt.Sprintf("t-inbound-%d", idx)},
            "outboundTag": fmt.Sprintf("r-outbound-%d", idx),
        })
    }

    // external-vless REALITY handshake inbound
    vless := map[string]any{
        "tag":      "external-vless",
        "listen":   "0.0.0.0",
        "port":     active.Handshake.Port,
        "protocol": "vless",
        "settings": map[string]any{
            "clients":    clients,
            "decryption": "none",
        },
    }

    // Attach REALITY settings: prefer stored per-tunnel private key, fallback to env overrides
    priv := active.PrivKey
    if priv == "" {
        priv = os.Getenv("XRPS_REALITY_PRIVATE_KEY")
        if priv == "" { priv = os.Getenv("XRAY_REALITY_PRIVATE_KEY") }
    }
    if priv != "" {
        normPriv, err := normalizeRealityKey32(priv)
        if err != nil { return nil, fmt.Errorf("invalid REALITY privateKey: %w", err) }
        vless["streamSettings"] = map[string]any{
            "network":  "tcp",
            "security": "reality",
            "realitySettings": map[string]any{
                "show":        false,
                "dest":        fmt.Sprintf("%s:443", active.Handshake.ServerName),
                "serverNames": []string{active.Handshake.ServerName},
                "privateKey":  normPriv,
                "shortIds":    []string{active.Handshake.ShortID},
            },
        }
    }
    inbounds = append(inbounds, vless)

    cfg := map[string]any{
        "log": map[string]any{"loglevel": "warning", "access": s.accessPath, "error": s.errorPath},
        "inbounds": inbounds,
        "outbounds": []map[string]any{
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blackhole", "protocol": "blackhole"},
        },
        "routing": map[string]any{
            "rules": rules,
        },
    }
    b, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil {
        return nil, err
    }
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
    if err != nil { return preferred }
    defer ln.Close()
    return ln.Addr().(*net.TCPAddr).Port
}

func getenvInt(key string, def int) int {
    v := os.Getenv(key)
    if v == "" { return def }
    if n, err := strconv.Atoi(v); err == nil { return n }
    return def
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

    s.logStartupSummary()
    // Attempt to start (placeholder) core; log success/failure to console
    if err := s.startCore(); err != nil {
        log.Printf("warning: xray-core not running: %v", err)
    }
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
