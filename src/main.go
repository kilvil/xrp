package main

import (
    "context"
    "crypto/ecdh"
    "crypto/mlkem"
    crand "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    // "math/rand"
    // "net"
    "net/http"
    neturl "net/url"
    "path"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"

    "xrp/internal/coreembed"
    "xrp/internal/shared"
)

// ===== Unified models =====

// PortalTunnel stored in server state (private fields not exposed in list)
type PortalTunnel struct {
    ID        string                 `json:"id"`
    Name      string                 `json:"name"`
    Portal    string                 `json:"portal_addr"`
    Handshake shared.HandshakeConfig `json:"handshake"`
    Entries   []shared.TunnelEntry   `json:"entries"`
    PrivKey   string                 `json:"-"`           // REALITY private key (base64url, 32 bytes)
    VLESSDec  string                 `json:"-"`           // optional decryption string for inbound
    CreatedAt time.Time              `json:"createdAt"`
    UpdatedAt time.Time              `json:"updatedAt"`
}

type portalStore struct {
    mu      sync.RWMutex
    tunnels map[string]*PortalTunnel
}

func newPortalStore() *portalStore { return &portalStore{tunnels: map[string]*PortalTunnel{}} }

func (s *portalStore) add(t *PortalTunnel) { s.mu.Lock(); s.tunnels[t.ID] = t; s.mu.Unlock() }
func (s *portalStore) get(id string) (*PortalTunnel, bool) { s.mu.RLock(); defer s.mu.RUnlock(); t, ok := s.tunnels[id]; return t, ok }
func (s *portalStore) del(id string) bool { s.mu.Lock(); defer s.mu.Unlock(); if _, ok := s.tunnels[id]; ok { delete(s.tunnels, id); return true }; return false }
func (s *portalStore) all() []*PortalTunnel { s.mu.RLock(); defer s.mu.RUnlock(); out := make([]*PortalTunnel,0,len(s.tunnels)); for _, t := range s.tunnels { out = append(out, t) }; return out }

// Bridge runtime state
type TunnelState struct {
    ID        string    `json:"id"`
    Tag       string    `json:"tag"`
    EntryPort int       `json:"entry_port"`
    MapPort   int       `json:"map_port"`
    Target    string    `json:"target"`
    Active    bool      `json:"active"`
    Status    string    `json:"status"`
    Changed   time.Time `json:"last_change"`
}

// Bridge store
type bridgeState struct {
    mu      sync.RWMutex
    params  *shared.ConnectionParams
    tunnels map[string]*TunnelState
}

func newBridgeState() *bridgeState { return &bridgeState{tunnels: map[string]*TunnelState{}} }

// ===== Utilities =====

func must[T any](v T, err error) T { if err != nil { panic(err) }; return v }

func randomBytes(n int) []byte { b := make([]byte, n); _, _ = crand.Read(b); return b }

func b64url32(s string) (string, error) {
    s = strings.TrimSpace(s)
    if s == "" { return "", errors.New("empty key") }
    if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 { return base64.RawURLEncoding.EncodeToString(b), nil }
    if b, err := base64.URLEncoding.DecodeString(s); err == nil && len(b) == 32 { return base64.RawURLEncoding.EncodeToString(b), nil }
    if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 { return base64.RawURLEncoding.EncodeToString(b), nil }
    return "", errors.New("expect 32-byte base64url")
}

// unified state dir: always under /var/lib/xrp/{portal,bridge}
func stateDir(role string) string {
    return filepath.Join("/", "var", "lib", "xrp", role)
}

// ===== Persistence =====

func loadJSON[T any](path string, out *T) error {
    b, err := os.ReadFile(path)
    if err != nil { return err }
    return json.Unmarshal(b, out)
}

func saveJSON(path string, v any) error {
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return err }
    b, err := json.MarshalIndent(v, "", "  ")
    if err != nil { return err }
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, b, 0o600); err != nil { return err }
    return os.Rename(tmp, path)
}

// ===== Server =====

type app struct {
    addr   string
    mux    *http.ServeMux
    portal *portalStore
    bridge *bridgeState
    cfgPath string
    // logs and stats
    logs   *shared.SSEHub
    access *shared.SSEHub
    errors *shared.SSEHub
    wsStats *shared.WSHub
    start  time.Time
    logDir string
    accessPath string
    errorPath  string
    tailAccess *shared.FileTailer
    tailError  *shared.FileTailer
    // auth (unified)
    authUser string
    authSalt string
    authHash string
    authPath string
    // embedded xray-core
    orch   *coreembed.Orchestrator
    // stats buffers (portal)
    pStatsMu       sync.Mutex
    pStatsTotal    []statsPoint
    pStatsPerEntry map[string][]statsPoint
    // stats buffers (bridge)
    bStatsMu        sync.Mutex
    bStatsTotal     []statsPoint
    bStatsPerTunnel map[string][]statsPoint
    // monitors stop chans
    pMonStop chan struct{}
    bMonStop chan struct{}
}

func newApp(addr string) *app {
    a := &app{addr: addr, mux: http.NewServeMux(), portal: newPortalStore(), bridge: newBridgeState(), logs: shared.NewSSEHub(), access: shared.NewSSEHub(), errors: shared.NewSSEHub(), start: time.Now()}
    // initialize logs directory and tailers
    a.ensureLogDir()
    // auth
    if err := a.initAuth(); err != nil {
        log.Printf("auth init failed: %v; using in-memory creds", err)
        salt := randomHex(16)
        pass := randomBase64URL(24)
        a.authUser = "admin"; a.authSalt = salt; a.authHash = hashPassword(salt, pass)
        log.Printf("==== XRP 内存凭据已启用（未持久化） ====")
        log.Printf("用户名: admin  初始密码: %s", pass)
    }
    // stats ws
    a.wsStats = shared.NewWSHub()
    a.routes()
    a.loadPersisted()
    // try start core once (best-effort)
    if err := a.startCore(); err != nil {
        log.Printf("warning: xray-core not started: %v", err)
    }
    // start monitors
    a.restartPortalMonitor()
    a.restartBridgeMonitor()
    return a
}

// ensureLogDir sets up the log directory and file tailers.
// Location is fixed to /var/lib/xrp; files: access.log and error.log.
func (a *app) ensureLogDir() {
    dir := filepath.Join("/var/lib", "xrp")
    // Always target /var/lib/xrp; best-effort create
    if err := os.MkdirAll(dir, 0o755); err != nil {
        log.Printf("warn: cannot create %s: %v", dir, err)
    }
    a.logDir = dir
    a.accessPath = filepath.Join(dir, "access.log")
    a.errorPath = filepath.Join(dir, "error.log")
    // ensure files exist
    if _, err := os.Stat(a.accessPath); os.IsNotExist(err) { _ = os.WriteFile(a.accessPath, []byte(""), 0o644) }
    if _, err := os.Stat(a.errorPath); os.IsNotExist(err) { _ = os.WriteFile(a.errorPath, []byte(""), 0o644) }
    // start tailers
    a.tailAccess = shared.NewFileTailer(a.accessPath, 1*time.Second)
    a.tailError = shared.NewFileTailer(a.errorPath, 1*time.Second)
    a.tailAccess.Start()
    a.tailError.Start()
    go func() { for line := range a.tailAccess.Out() { a.access.Broadcast(line) } }()
    go func() { for line := range a.tailError.Out() { a.errors.Broadcast(line) } }()
}

func (a *app) loadPersisted() {
    // portal
    var pt []*PortalTunnel
    _ = loadJSON(filepath.Join(stateDir("portal"), "tunnels.json"), &pt)
    for _, t := range pt { a.portal.add(t) }
    // bridge
    var prof shared.ConnectionParams
    if err := loadJSON(filepath.Join(stateDir("bridge"), "profile.json"), &prof); err == nil {
        if err := prof.Validate(); err == nil {
            a.bridge.params = &prof
            // derive default states
            for _, t := range prof.Tunnels {
                st := &TunnelState{ID: t.ID, Tag: t.Tag, EntryPort: t.EntryPort, MapPort: t.MapPortHint, Active: true, Changed: time.Now()}
                if st.MapPort > 0 { st.Target = fmt.Sprintf("127.0.0.1:%d", st.MapPort) } else { st.Target = "127.0.0.1:80" }
                a.bridge.tunnels[t.ID] = st
            }
        }
    }
    var states []TunnelState
    if err := loadJSON(filepath.Join(stateDir("bridge"), "tunnel_states.json"), &states); err == nil {
        for _, st := range states {
            if cur, ok := a.bridge.tunnels[st.ID]; ok {
                cur.MapPort = st.MapPort
                cur.Target = st.Target
                cur.Active = st.Active
                cur.Changed = time.Now()
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

// ===== Routes =====

func (a *app) routes() {
    mux := http.NewServeMux()

    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
    mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
        uptime := time.Since(a.start).String()
        writeJSON(w, map[string]any{
            "uptime": uptime,
            "tunnels": len(a.portal.all()),
            "hasProfile": a.bridge.params != nil,
        })
    })

    // UI: serve embedded assets when built with -tags ui_embed.
    if hfs := getEmbeddedUI(); hfs != nil {
        h := spaFileServer(hfs)
        mux.Handle("/", h)
    } else {
        // No embedded UI; expose a minimal root for clarity
        mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            w.WriteHeader(200)
            _, _ = w.Write([]byte("XRP API is running. Build with -tags ui_embed to serve UI."))
        })
    }

    // Logs + SSE + WS
    mux.Handle("/logs/stream", a.logs)
    mux.HandleFunc("/logs/access/stream", func(w http.ResponseWriter, r *http.Request) { a.handleLogStream("access")(w,r) })
    mux.HandleFunc("/logs/error/stream", func(w http.ResponseWriter, r *http.Request) { a.handleLogStream("error")(w,r) })
    mux.Handle("/ws/stats", a.wsStats)
    mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        typ := r.URL.Query().Get("type")
        nStr := r.URL.Query().Get("tail"); if nStr == "" { nStr = "200" }
        n, _ := strconv.Atoi(nStr)
        var p string
        switch typ { case "access": p = a.accessPath; case "error": p = a.errorPath; default: http.Error(w, "query type=access|error", 400); return }
        lines, err := shared.TailLastN(p, n, 2*1024*1024)
        if err != nil { http.Error(w, err.Error(), 500); return }
        writeJSON(w, map[string]any{"type": typ, "path": p, "lines": lines})
    })

    // Reality helpers
    mux.HandleFunc("/api/reality/x25519", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        pub, priv, err := genX25519()
        if err != nil { http.Error(w, err.Error(), 500); return }
        writeJSON(w, map[string]string{"publicKey": pub, "privateKey": priv})
    })

    // Config file API: return full unified config file content from disk
    mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        p := a.ensureCfgPath()
        b, err := os.ReadFile(p)
        if err != nil {
            http.Error(w, fmt.Sprintf("read config failed: %v", err), 500)
            return
        }
        writeJSON(w, map[string]any{"path": p, "content": string(b)})
    })

    // Core control: restart xray-core on demand
    mux.HandleFunc("/api/core/restart", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
        if err := a.restartCore(); err != nil {
            http.Error(w, fmt.Sprintf("restart failed: %v", err), 500)
            return
        }
        writeJSON(w, map[string]any{"ok": true, "ts": time.Now().UnixMilli()})
    })
    // generate VLESS encryption/decryption pair
    mux.HandleFunc("/api/vlessenc", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        q := r.URL.Query()
        algo := strings.ToLower(strings.TrimSpace(q.Get("algo")))
        if algo == "" { algo = "pq" }
        _ = q.Get("mode")
        sec := strings.TrimSpace(q.Get("seconds")); if sec == "" { sec = "600" }
        const algHeader = "mlkem768x25519plus"
        mode := "native"
        var decryption, encryption string
        switch algo {
        case "x25519":
            pub, priv, err := genX25519(); if err != nil { http.Error(w, err.Error(), 500); return }
            decryption = algHeader + "." + mode + "." + sec + "s." + priv
            encryption = algHeader + "." + mode + ".0rtt." + pub
        case "pq", "mlkem768", "ml-kem-768", "ml_kem_768":
            // Proper ML-KEM-768 generation: derive decapsulation key from 64-byte seed
            var seed [64]byte; _, _ = crand.Read(seed[:])
            dkey, err := mlkem.NewDecapsulationKey768(seed[:])
            if err != nil { http.Error(w, "mlkem768 keygen failed: "+err.Error(), 500); return }
            client := dkey.EncapsulationKey().Bytes() // 1184 bytes
            serverKey := base64.RawURLEncoding.EncodeToString(seed[:])
            clientKey := base64.RawURLEncoding.EncodeToString(client)
            decryption = algHeader + "." + mode + "." + sec + "s." + serverKey
            encryption = algHeader + "." + mode + ".0rtt." + clientKey
        default:
            http.Error(w, "unknown algo: use pq|x25519", 400); return
        }
        writeJSON(w, map[string]any{"algorithm": algHeader, "mode": mode, "decryption": decryption, "encryption": encryption})
    })

    // ---- Inbound (Portal) APIs ----
    mux.HandleFunc("/api/inbound/tunnels", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case http.MethodGet:
            writeJSON(w, a.portal.all())
        case http.MethodPost:
            var req struct {
                Name          string `json:"name"`
                PortalAddr    string `json:"portal_addr"`
                HandshakePort int    `json:"handshake_port"`
                ServerName    string `json:"server_name"`
                Encryption    string `json:"encryption"`
                Decryption    string `json:"decryption"`
                EntryPorts    []int  `json:"entry_ports"`
                PublicKey     string `json:"public_key"`
                ShortID       string `json:"short_id"`
                PrivateKey    string `json:"private_key"`
            }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, err.Error(), 400); return }
            if req.HandshakePort <= 0 || req.ServerName == "" || len(req.EntryPorts) == 0 { http.Error(w, "invalid payload", 400); return }
            // normalize REALITY privateKey if provided
            pk := strings.TrimSpace(req.PrivateKey)
            if pk == "" { http.Error(w, "private_key is required", 400); return }
            normPK, err := b64url32(pk); if err != nil { http.Error(w, "invalid private_key", 400); return }

            // build handshake config
            h := shared.HandshakeConfig{
                Port:       req.HandshakePort,
                ServerName: req.ServerName,
                PublicKey:  req.PublicKey, // client-side used
                ShortID:    req.ShortID,
                Encryption: strings.TrimSpace(req.Encryption),
                Flow:       "xtls-rprx-vision",
            }
            // entries
            entries := make([]shared.TunnelEntry, 0, len(req.EntryPorts))
            for i, ep := range req.EntryPorts {
                entries = append(entries, shared.TunnelEntry{EntryPort: ep, ID: fmt.Sprintf("%d-%d", req.HandshakePort, i+1), Tag: fmt.Sprintf("t%d", i+1)})
            }
            id := fmt.Sprintf("p-%d", time.Now().UnixNano())
            // derive public key from private_key if not provided
            if strings.TrimSpace(h.PublicKey) == "" {
                if b, err := base64.RawURLEncoding.DecodeString(normPK); err == nil && len(b) == 32 {
                    if sk, err := ecdh.X25519().NewPrivateKey(b); err == nil { h.PublicKey = base64.RawURLEncoding.EncodeToString(sk.PublicKey().Bytes()) }
                }
            }
            t := &PortalTunnel{ID: id, Name: req.Name, Portal: req.PortalAddr, Handshake: h, Entries: entries, PrivKey: normPK, VLESSDec: strings.TrimSpace(req.Decryption), CreatedAt: time.Now(), UpdatedAt: time.Now()}
            a.portal.add(t)
            _ = saveJSON(filepath.Join(stateDir("portal"), "tunnels.json"), a.portal.all())
            _ = a.restartCore()
            writeJSON(w, t)
        default:
            http.Error(w, "method not allowed", 405)
        }
    })

    mux.HandleFunc("/api/inbound/tunnels/", func(w http.ResponseWriter, r *http.Request) {
        rest := strings.TrimPrefix(r.URL.Path, "/api/inbound/tunnels/")
        segs := strings.Split(rest, "/")
        if len(segs) == 0 || segs[0] == "" { http.NotFound(w,r); return }
        id := segs[0]
        t, ok := a.portal.get(id); if !ok { http.Error(w, "not found", 404); return }
        if len(segs) == 1 {
            switch r.Method {
            case http.MethodGet:
                writeJSON(w, t)
            case http.MethodDelete:
                if a.portal.del(id) { _ = saveJSON(filepath.Join(stateDir("portal"), "tunnels.json"), a.portal.all()); w.WriteHeader(204); return }
                http.Error(w, "not found", 404)
            case http.MethodPatch:
                var p map[string]any
                if err := json.NewDecoder(r.Body).Decode(&p); err != nil { http.Error(w, err.Error(), 400); return }
                if v, ok := p["name"].(string); ok { t.Name = v }
                if v, ok := p["portal_addr"].(string); ok { t.Portal = v }
                if v, ok := p["server_name"].(string); ok { t.Handshake.ServerName = v }
                if v, ok := p["handshake_port"].(float64); ok { t.Handshake.Port = int(v) }
                t.UpdatedAt = time.Now()
                _ = saveJSON(filepath.Join(stateDir("portal"), "tunnels.json"), a.portal.all())
                writeJSON(w, t)
            default:
                http.Error(w, "method not allowed", 405)
            }
            return
        }
        if len(segs) == 2 && segs[1] == "connection-params" && r.Method == http.MethodPost {
            cp := shared.ConnectionParams{Version: 1, PortalAddr: t.Portal, Handshake: t.Handshake, Tunnels: t.Entries, Meta: map[string]any{"tunnelId": t.ID, "name": t.Name, "createdAt": t.CreatedAt}}
            if err := cp.Validate(); err != nil { http.Error(w, err.Error(), 400); return }
            js, b64, err := shared.EncodeParamsB64(&cp); if err != nil { http.Error(w, err.Error(), 500); return }
            writeJSON(w, map[string]string{"json": js, "base64": b64})
            return
        }
        http.NotFound(w, r)
    })

    

    // ---- Outbound (Bridge) APIs ----
    mux.HandleFunc("/api/outbound/profile/apply", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost { http.Error(w, "method not allowed", 405); return }
        var b64 string
        ct := r.Header.Get("Content-Type")
        if strings.HasPrefix(ct, "text/") || ct == "application/octet-stream" {
            var sb strings.Builder
            _, _ = io.Copy(&sb, r.Body)
            b64 = sb.String()
        } else {
            var body struct{ Base64 string `json:"base64"` }
            if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, err.Error(), 400); return }
            b64 = body.Base64
        }
        p, err := shared.DecodeParamsB64(strings.TrimSpace(b64)); if err != nil { http.Error(w, err.Error(), 400); return }
        a.bridge.mu.Lock()
        a.bridge.params = p
        // reconcile states
        seen := map[string]struct{}{}
        if a.bridge.tunnels == nil { a.bridge.tunnels = map[string]*TunnelState{} }
        for _, t := range p.Tunnels {
            st, ok := a.bridge.tunnels[t.ID]
            if !ok { st = &TunnelState{ID: t.ID, Tag: t.Tag, EntryPort: t.EntryPort, MapPort: t.MapPortHint, Active: true, Changed: time.Now()} }
            if st.Target == "" {
                if st.MapPort > 0 { st.Target = fmt.Sprintf("127.0.0.1:%d", st.MapPort) } else { st.Target = "127.0.0.1:80" }
            }
            st.Tag, st.EntryPort = t.Tag, t.EntryPort
            a.bridge.tunnels[t.ID] = st
            seen[t.ID] = struct{}{}
        }
        for id := range a.bridge.tunnels { if _, ok := seen[id]; !ok { a.bridge.tunnels[id].Active = false } }
        a.bridge.mu.Unlock()
        _ = saveJSON(filepath.Join(stateDir("bridge"), "profile.json"), p)
        _ = saveJSON(filepath.Join(stateDir("bridge"), "tunnel_states.json"), a.bridge.listStates())
        _ = a.restartCore()
        writeJSON(w, map[string]any{"ok": true})
    })

    mux.HandleFunc("/api/outbound/tunnels", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        writeJSON(w, a.bridge.listStates())
    })
    mux.HandleFunc("/api/outbound/tunnels/", func(w http.ResponseWriter, r *http.Request) {
        id := strings.TrimPrefix(r.URL.Path, "/api/outbound/tunnels/")
        if id == "" { http.NotFound(w, r); return }
        switch r.Method {
        case http.MethodGet:
            if st, ok := a.bridge.getState(id); ok { writeJSON(w, st); return }
            http.NotFound(w, r)
        case http.MethodPatch:
            var body struct{ MapPort *int `json:"map_port"`; Active *bool `json:"active"`; Target *string `json:"target"` }
            if err := json.NewDecoder(r.Body).Decode(&body); err != nil { http.Error(w, err.Error(), 400); return }
            if st, ok := a.bridge.patchState(id, body.MapPort, body.Active, body.Target); ok {
                _ = saveJSON(filepath.Join(stateDir("bridge"), "tunnel_states.json"), a.bridge.listStates())
                _ = a.restartCore()
                writeJSON(w, st)
                return
            }
            http.NotFound(w, r)
        case http.MethodDelete:
            if a.bridge.deleteState(id) {
                // also update profile
                a.bridge.mu.Lock()
                if a.bridge.params != nil {
                    dst := a.bridge.params.Tunnels[:0]
                    for _, t := range a.bridge.params.Tunnels { if t.ID != id { dst = append(dst, t) } }
                    a.bridge.params.Tunnels = dst
                    _ = saveJSON(filepath.Join(stateDir("bridge"), "profile.json"), a.bridge.params)
                }
                a.bridge.mu.Unlock()
                _ = saveJSON(filepath.Join(stateDir("bridge"), "tunnel_states.json"), a.bridge.listStates())
                _ = a.restartCore()
                w.WriteHeader(204)
                return
            }
            http.NotFound(w, r)
        default:
            http.Error(w, "method not allowed", 405)
        }
    })

    

    // Stats endpoints (namespaced)
    mux.HandleFunc("/api/inbound/stats/snapshot", func(w http.ResponseWriter, r *http.Request) { if r.Method!=http.MethodGet { http.Error(w, "method not allowed", 405); return }; writeJSON(w, a.portalStatsSnapshot()) })
    mux.HandleFunc("/api/inbound/stats/range", func(w http.ResponseWriter, r *http.Request) {
        if r.Method!=http.MethodGet { http.Error(w, "method not allowed", 405); return }
        sinceStr := r.URL.Query().Get("since"); if sinceStr == "" { http.Error(w, "query since=epochMillis required", 400); return }
        since, err := strconv.ParseInt(sinceStr, 10, 64); if err != nil { http.Error(w, "invalid since", 400); return }
        entry := r.URL.Query().Get("entry")
        series, step := a.portalStatsRange(since, entry)
        writeJSON(w, map[string]any{"series": series, "step": step})
    })
    mux.HandleFunc("/api/outbound/stats/snapshot", func(w http.ResponseWriter, r *http.Request) { if r.Method!=http.MethodGet { http.Error(w, "method not allowed", 405); return }; writeJSON(w, a.bridgeStatsSnapshot()) })
    mux.HandleFunc("/api/outbound/stats/range", func(w http.ResponseWriter, r *http.Request) {
        if r.Method!=http.MethodGet { http.Error(w, "method not allowed", 405); return }
        sinceStr := r.URL.Query().Get("since"); if sinceStr == "" { http.Error(w, "query since=epochMillis required", 400); return }
        since, err := strconv.ParseInt(sinceStr, 10, 64); if err != nil { http.Error(w, "invalid since", 400); return }
        tunnel := r.URL.Query().Get("tunnel")
        series, step := a.bridgeStatsRange(since, tunnel)
        writeJSON(w, map[string]any{"series": series, "step": step})
    })

    // Wrap with CORS + BasicAuth
    a.mux = http.NewServeMux()
    a.mux.Handle("/", withCORS(a.secure(mux)))
}

// bridge helpers
func (b *bridgeState) listStates() []TunnelState { b.mu.RLock(); defer b.mu.RUnlock(); out := make([]TunnelState,0,len(b.tunnels)); for _, st := range b.tunnels { out = append(out, *st) }; return out }
func (b *bridgeState) getState(id string) (TunnelState, bool) { b.mu.RLock(); defer b.mu.RUnlock(); st, ok := b.tunnels[id]; if !ok { return TunnelState{}, false }; return *st, true }
func (b *bridgeState) patchState(id string, mapPort *int, active *bool, target *string) (TunnelState, bool) {
    b.mu.Lock(); defer b.mu.Unlock()
    st, ok := b.tunnels[id]; if !ok { return TunnelState{}, false }
    if mapPort != nil { st.MapPort = *mapPort; if st.Target == "" || strings.HasPrefix(st.Target, "127.0.0.1:") { st.Target = fmt.Sprintf("127.0.0.1:%d", st.MapPort) } }
    if active != nil { st.Active = *active }
    if target != nil {
        t := strings.TrimSpace(*target)
        if p, err := strconv.Atoi(t); err == nil && p > 0 { st.MapPort = p; st.Target = fmt.Sprintf("127.0.0.1:%d", p) } else { st.Target = t }
    }
    st.Changed = time.Now()
    return *st, true
}
func (b *bridgeState) deleteState(id string) bool { b.mu.Lock(); defer b.mu.Unlock(); if _, ok := b.tunnels[id]; ok { delete(b.tunnels, id); return true }; return false }

// ===== main =====

func main() {
    addr := flag.String("addr", ":8080", "listen address")
    resetAdmin := flag.Bool("reset-admin", false, "reset admin password and exit")
    flag.Parse()
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)

    if *resetAdmin {
        a := &app{}
        pass, err := a.resetAdminCredentials(a.ensureCredsPath())
        if err != nil { log.Fatalf("reset admin failed: %v", err) }
        fmt.Printf("XRP admin password reset.\nUsername: admin\nPassword: %s\nFile: %s\n", pass, a.authPath)
        return
    }

    app := newApp(*addr)
    srv := &http.Server{Addr: *addr, Handler: app.mux}
    log.Printf("xrp unified server listening on %s", *addr)
    if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
        log.Fatalf("server error: %v", err)
    }
    _ = srv.Shutdown(context.Background())
}

// ===== Logs helpers =====

func (a *app) handleLogStream(typ string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/event-stream")
        w.Header().Set("Cache-Control", "no-cache")
        w.Header().Set("Connection", "keep-alive")
        flusher, ok := w.(http.Flusher); if !ok { http.Error(w, "streaming unsupported", 500); return }
        var ch <-chan string
        var unsubscribe func()
        switch typ {
        case "access":
            c, u := a.access.Subscribe(); ch = c; unsubscribe = u
        case "error":
            c, u := a.errors.Subscribe(); ch = c; unsubscribe = u
        default:
            http.Error(w, "bad type", 400); return
        }
        defer func(){ if unsubscribe != nil { unsubscribe() } }()
        ctx := r.Context()
        fmt.Fprintf(w, ":ok\n\n"); flusher.Flush()
        ticker := time.NewTicker(30*time.Second); defer ticker.Stop()
        for {
            select {
            case <-ctx.Done(): return
            case <-ticker.C: fmt.Fprintf(w, ": ping %d\n\n", time.Now().Unix()); flusher.Flush()
            case ln, ok := <-ch: if !ok { return }; fmt.Fprintf(w, "data: %s\n\n", ln); flusher.Flush()
            }
        }
    }
}

// spaFileServer serves files from a FileSystem and falls back to index.html for unknown routes (SPA).
func spaFileServer(root http.FileSystem) http.Handler {
    fileServer := http.FileServer(root)
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        upath := r.URL.Path
        if upath == "/" || upath == "" {
            // serve index.html
            r2 := new(http.Request)
            *r2 = *r
            r2.URL = newCopyURL(r.URL)
            r2.URL.Path = "/index.html"
            fileServer.ServeHTTP(w, r2)
            return
        }
        // Try to open the requested file; if it fails, serve index.html
        f, err := root.Open(strings.TrimPrefix(upath, "/"))
        if err != nil {
            r2 := new(http.Request)
            *r2 = *r
            r2.URL = newCopyURL(r.URL)
            r2.URL.Path = "/index.html"
            fileServer.ServeHTTP(w, r2)
            return
        }
        defer f.Close()
        if info, _ := f.Stat(); info != nil && info.IsDir() {
            // check for index.html in dir
            if idx, err := root.Open(path.Join(strings.TrimPrefix(upath, "/"), "index.html")); err == nil {
                idx.Close()
                r2 := new(http.Request)
                *r2 = *r
                r2.URL = newCopyURL(r.URL)
                r2.URL.Path = path.Join(upath, "index.html")
                fileServer.ServeHTTP(w, r2)
                return
            }
        }
        // serve the file as is
        fileServer.ServeHTTP(w, r)
    })
}

func newCopyURL(u *neturl.URL) *neturl.URL {
    v := *u
    if u.User != nil {
        user := *u.User
        v.User = &user
    }
    return &v
}

// ===== Auth (unified admin) =====

type authFile struct { Username, Salt, Hash, CreatedAt string `json:"username"` }

func (a *app) secure(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodOptions || r.URL.Path == "/healthz" { next.ServeHTTP(w, r); return }
        if a.authUser == "" || a.authHash == "" { next.ServeHTTP(w, r); return }
        user, pass, ok := r.BasicAuth()
        if !ok || !a.checkPassword(user, pass) {
            w.Header().Set("WWW-Authenticate", "Basic realm=\"XRP\"")
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func (a *app) checkPassword(user, pass string) bool {
    if user != a.authUser { return false }
    if a.authSalt == "" || a.authHash == "" { return false }
    h := hashPassword(a.authSalt, pass)
    return subtle.ConstantTimeCompare([]byte(h), []byte(a.authHash)) == 1
}

func hashPassword(salt, pass string) string { sum := sha256.Sum256([]byte(salt+":"+pass)); return hex.EncodeToString(sum[:]) }
func randomBase64URL(n int) string { b := make([]byte, n); _, _ = crand.Read(b); return base64.RawURLEncoding.EncodeToString(b) }
func randomHex(n int) string { b := make([]byte, n); _, _ = crand.Read(b); return hex.EncodeToString(b) }

func (a *app) resetAdminCredentials(path string) (string, error) {
    if path == "" { path = a.ensureCredsPath() }
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return "", err }
    user := "admin"; salt := randomHex(16); pass := randomBase64URL(24); hash := hashPassword(salt, pass)
    af := map[string]string{"username": user, "salt": salt, "hash": hash, "createdAt": time.Now().Format(time.RFC3339)}
    b, _ := json.MarshalIndent(af, "", "  ")
    if err := os.WriteFile(path, b, 0o600); err != nil { return "", err }
    a.authUser, a.authSalt, a.authHash, a.authPath = user, salt, hash, path
    return pass, nil
}

func (a *app) initAuth() error {
    path := a.ensureCredsPath()
    a.authPath = path
    if _, err := os.Stat(path); os.IsNotExist(err) {
        pass, err := a.resetAdminCredentials(path); if err != nil { return err }
        log.Printf("==== 初次运行创建管理员账户 ====")
        log.Printf("用户名: admin  初始密码: %s", pass)
        log.Printf("凭据文件: %s", path)
        return nil
    }
    b, err := os.ReadFile(path); if err != nil { return err }
    var af struct{ Username, Salt, Hash string }
    if err := json.Unmarshal(b, &af); err != nil { return err }
    a.authUser, a.authSalt, a.authHash = af.Username, af.Salt, af.Hash
    return nil
}

// ensureCredsPath returns the fixed admin credentials path under /etc/lib/xrp.
// This follows the requirement that credentials must always persist under /etc/lib.
func (a *app) ensureCredsPath() string {
    p := filepath.Join("/","etc","lib","xrp","admin.auth.json")
    // best-effort create parent dir; errors handled by callers when writing
    _ = os.MkdirAll(filepath.Dir(p), 0o755)
    return p
}

func withCORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
        if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
        next.ServeHTTP(w, r)
    })
}

// ===== Orchestrator and config builders =====

// startCore builds unified config and starts embedded xray-core
func (a *app) startCore() error {
    if a.orch == nil { a.orch = coreembed.New() }
    // prefer existing config file if any
    var cfg []byte
    cfgFile := a.ensureCfgPath()
    if b, err := os.ReadFile(cfgFile); err == nil && len(b) > 0 {
        cfg = b
    }
    if built, err := a.buildUnifiedConfig(); err == nil && len(built) > 0 {
        cfg = built
    }
    if len(cfg) == 0 {
        cfg = []byte(fmt.Sprintf(`{ "log": {"loglevel":"warning","access": %q, "error": %q}, "outbounds":[{"protocol":"blackhole","tag":"blackhole"}] }`, a.accessPath, a.errorPath))
    }
    if err := os.WriteFile(cfgFile, cfg, 0o644); err != nil {
        log.Printf("warn: write cfg to %s failed: %v", cfgFile, err)
    }
    if err := a.orch.StartJSON(cfg); err != nil { return err }
    // kick monitors
    a.restartPortalMonitor(); a.restartBridgeMonitor()
    // broadcast event to system SSE hub (best-effort)
    a.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_started\",\"ts\":%d}", time.Now().UnixMilli()))
    return nil
}

func (a *app) restartCore() error {
    if a.orch == nil { a.orch = coreembed.New() }
    var cfg []byte
    if built, err := a.buildUnifiedConfig(); err == nil && len(built) > 0 {
        cfg = built
    } else {
        // reuse previous file
        p := a.ensureCfgPath()
        if b, err2 := os.ReadFile(p); err2 == nil {
            cfg = b
        }
        if len(cfg) == 0 {
            cfg = []byte(fmt.Sprintf(`{ "log": {"loglevel":"warning","access": %q, "error": %q}, "outbounds":[{"protocol":"blackhole","tag":"blackhole"}] }`, a.accessPath, a.errorPath))
        }
    }
    if err := os.WriteFile(a.ensureCfgPath(), cfg, 0o644); err != nil {
        log.Printf("warn: write cfg failed: %v", err)
    }
    if err := a.orch.RestartJSON(cfg); err != nil { return err }
    a.restartPortalMonitor(); a.restartBridgeMonitor()
    a.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_restarted\",\"ts\":%d}", time.Now().UnixMilli()))
    return nil
}

// buildUnifiedConfig merges portal and bridge configs
func (a *app) buildUnifiedConfig() ([]byte, error) {
    // base with api/stats/policy
    cfg := map[string]any{
        "log": map[string]any{"loglevel": "warning", "access": a.accessPath, "error": a.errorPath},
        "api":   map[string]any{"tag": "api", "services": []string{"HandlerService", "LoggerService", "StatsService"}},
        "stats": map[string]any{},
        "policy": map[string]any{
            "levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}},
            "system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true},
        },
        "inbounds":  []any{},
        "outbounds": []any{},
        "routing":   map[string]any{"rules": []any{}},
    }
    // portal part
    if pInb, pOut, pRules, err := a.portalConfigParts(); err == nil {
        cfg["inbounds"] = append(cfg["inbounds"].([]any), pInb...)
        cfg["outbounds"] = append(cfg["outbounds"].([]any), pOut...)
        r := cfg["routing"].(map[string]any)["rules"].([]any)
        cfg["routing"].(map[string]any)["rules"] = append(r, pRules...)
    }
    // bridge part
    if bInb, bOut, bRules, err := a.bridgeConfigParts(); err == nil {
        cfg["inbounds"] = append(cfg["inbounds"].([]any), bInb...)
        cfg["outbounds"] = append(cfg["outbounds"].([]any), bOut...)
        r := cfg["routing"].(map[string]any)["rules"].([]any)
        cfg["routing"].(map[string]any)["rules"] = append(r, bRules...)
    }
    // ensure a default freedom outbound exists
    cfg["outbounds"] = append(cfg["outbounds"].([]any), map[string]any{"tag": "direct", "protocol": "freedom"})
    // one blackhole as well
    cfg["outbounds"] = append(cfg["outbounds"].([]any), map[string]any{"tag": "blackhole", "protocol": "blackhole"})
    return json.MarshalIndent(cfg, "", "  ")
}

// ensureCfgPath determines the config file path, creates parent directory if needed, and remembers it.
func (a *app) ensureCfgPath() string {
    if a.cfgPath != "" { return a.cfgPath }
    p := filepath.Join("/var/lib", "xrp", "xray.unified.json")
    _ = os.MkdirAll(filepath.Dir(p), 0o755)
    a.cfgPath = p
    return a.cfgPath
}

// portalConfigParts returns inbounds/outbounds/rules from current portal store
func (a *app) portalConfigParts() (inbounds []any, outbounds []any, rules []any, err error) {
    tunnels := a.portal.all()
    if len(tunnels) == 0 { return nil, nil, nil, fmt.Errorf("no portal tunnels") }
    // pick most recently updated
    active := tunnels[0]
    for _, t := range tunnels { if t.UpdatedAt.After(active.UpdatedAt) { active = t } }
    // entries
    clients := make([]map[string]any, 0, len(active.Entries))
    for i, e := range active.Entries {
        idx := i+1
        clients = append(clients, map[string]any{
            "email": fmt.Sprintf("bridge-rev-%d", idx),
            "id": e.ID,
            "flow": nonEmpty(active.Handshake.Flow, "xtls-rprx-vision"),
            "level": 0,
            "reverse": map[string]any{"tag": fmt.Sprintf("r-outbound-%d", idx)},
        })
        inbounds = append(inbounds, map[string]any{"listen": "0.0.0.0", "port": e.EntryPort, "protocol": "tunnel", "tag": fmt.Sprintf("t-inbound-%d", idx)})
        rules = append(rules, map[string]any{"type":"field", "inboundTag": []string{fmt.Sprintf("t-inbound-%d", idx)}, "outboundTag": fmt.Sprintf("r-outbound-%d", idx)})
    }
    // reality inbound
    if strings.TrimSpace(active.PrivKey) == "" { return nil, nil, nil, fmt.Errorf("missing REALITY private key") }
    normPriv, err2 := b64url32(active.PrivKey); if err2 != nil { return nil, nil, nil, fmt.Errorf("invalid private_key") }
    vless := map[string]any{
        "tag": "external-vless", "listen":"0.0.0.0", "port": active.Handshake.Port, "protocol":"vless",
        "settings": map[string]any{"clients": clients, "decryption": func() string { if strings.TrimSpace(active.VLESSDec) != "" && !strings.EqualFold(active.VLESSDec, "none") { return active.VLESSDec }; return "none" }()},
        "streamSettings": map[string]any{"network":"tcp", "security":"reality", "realitySettings": map[string]any{
            "show": false, "dest": fmt.Sprintf("%s:443", active.Handshake.ServerName), "serverNames": []string{active.Handshake.ServerName}, "privateKey": normPriv, "shortIds": []string{active.Handshake.ShortID},
        }},
    }
    inbounds = append(inbounds, vless)
    return inbounds, outbounds, rules, nil
}

// bridgeConfigParts returns inbounds/outbounds/rules from current applied bridge profile
func (a *app) bridgeConfigParts() (inbounds []any, outbounds []any, rules []any, err error) {
    a.bridge.mu.RLock(); p := a.bridge.params; states := make(map[string]*TunnelState, len(a.bridge.tunnels)); for k,v := range a.bridge.tunnels { states[k] = v }; a.bridge.mu.RUnlock()
    if p == nil || len(p.Tunnels) == 0 { return nil, nil, nil, fmt.Errorf("no bridge profile") }
    outbounds = append(outbounds, map[string]any{"protocol": "freedom", "tag": "default"})
    for i, t := range p.Tunnels {
        idx := i
        st, ok := states[t.ID]; if !ok { st = &TunnelState{ID: t.ID, EntryPort: t.EntryPort, MapPort: t.MapPortHint, Active: true, Target: fmt.Sprintf("127.0.0.1:%d", nonzero(t.MapPortHint, 80))} }
        if !st.Active { continue }
        localTag := fmt.Sprintf("local-web-%d", idx)
        revTag   := fmt.Sprintf("rev-link-%d", idx)
        inboundTag := fmt.Sprintf("r-inbound-%d", idx)
        target := st.Target; if target == "" { target = fmt.Sprintf("127.0.0.1:%d", nonzero(st.MapPort, 80)) }
        outbounds = append(outbounds, map[string]any{"protocol":"freedom", "tag": localTag, "settings": map[string]any{"redirect": target}})
        enc := sanitizeVLESSEncryption(nonEmpty(p.Handshake.Encryption, "none"))
        revPK := p.Handshake.PublicKey; if pk, err := b64url32(p.Handshake.PublicKey); err == nil { revPK = pk }
        flow := nonEmpty(p.Handshake.Flow, "xtls-rprx-vision")
        outbounds = append(outbounds, map[string]any{
            "tag": revTag, "protocol": "vless",
            "settings": map[string]any{"address": p.PortalAddr, "port": p.Handshake.Port, "id": t.ID, "encryption": enc, "flow": flow, "reverse": map[string]any{"tag": inboundTag}},
            "streamSettings": map[string]any{"network":"tcp", "security":"reality", "realitySettings": map[string]any{"serverName": p.Handshake.ServerName, "publicKey": revPK, "shortId": p.Handshake.ShortID, "fingerprint":"chrome", "spiderX":"/"}},
            "mux": map[string]any{"enabled": false},
        })
        rules = append(rules, map[string]any{"type":"field", "inboundTag": []string{inboundTag}, "outboundTag": localTag})
    }
    return inbounds, outbounds, rules, nil
}

func nonzero(v, def int) int { if v == 0 { return def }; return v }
func nonEmpty(s, def string) string { if strings.TrimSpace(s) == "" { return def }; return s }

// sanitizeVLESSEncryption: allowed "none" or mlkem768x25519plus.*
func sanitizeVLESSEncryption(s string) string { s = strings.TrimSpace(s); if strings.EqualFold(s, "none") { return "none" }; if strings.HasPrefix(strings.ToLower(s), "mlkem768x25519plus.") { return s }; return "none" }

// ===== Stats (portal) =====
type statsPoint struct { TS int64 `json:"ts"`; Up int64 `json:"uplink"`; Down int64 `json:"downlink"` }
const statsCap = 1800

func (a *app) recordPortalStats(ts int64, per map[string]struct{up,down int64}) {
    a.pStatsMu.Lock(); defer a.pStatsMu.Unlock()
    var totUp, totDown int64
    if a.pStatsPerEntry == nil { a.pStatsPerEntry = make(map[string][]statsPoint) }
    for id, v := range per {
        totUp += v.up; totDown += v.down
        arr := a.pStatsPerEntry[id]; arr = append(arr, statsPoint{TS: ts, Up: v.up, Down: v.down}); if len(arr) > statsCap { arr = arr[len(arr)-statsCap:] }
        a.pStatsPerEntry[id] = arr
    }
    a.pStatsTotal = append(a.pStatsTotal, statsPoint{TS: ts, Up: totUp, Down: totDown}); if len(a.pStatsTotal) > statsCap { a.pStatsTotal = a.pStatsTotal[len(a.pStatsTotal)-statsCap:] }
}

func (a *app) portalStatsRange(since int64, entryID string) (series []statsPoint, intervalMs int64) {
    a.pStatsMu.Lock(); defer a.pStatsMu.Unlock()
    var arr []statsPoint
    if entryID == "" { arr = append(arr, a.pStatsTotal...) } else { arr = append(arr, a.pStatsPerEntry[entryID]...) }
    start := 0
    for i, p := range arr { if p.TS >= since { start = i; break } }
    arr = arr[start:]
    if len(arr) < 2 { return nil, 0 }
    for i := 1; i < len(arr); i++ {
        dt := arr[i].TS - arr[i-1].TS; if dt <= 0 { continue }
        up := arr[i].Up - arr[i-1].Up; down := arr[i].Down - arr[i-1].Down
        if up < 0 { up = 0 }; if down < 0 { down = 0 }
        series = append(series, statsPoint{TS: arr[i].TS, Up: up*1000/dt, Down: down*1000/dt})
    }
    intervalMs = arr[len(arr)-1].TS - arr[len(arr)-2].TS; if intervalMs <= 0 { intervalMs = 2000 }
    return
}

func (a *app) portalStatsSnapshot() map[string]any {
    now := time.Now().UnixMilli(); out := map[string]any{"ts": now, "tunnels": []map[string]any{}, "total": map[string]any{"uplink": int64(0), "downlink": int64(0), "total": int64(0)}}
    if a.orch == nil { return out }
    tunnels := a.portal.all(); if len(tunnels) == 0 { return out }
    active := tunnels[0]; for _, t := range tunnels { if t.UpdatedAt.After(active.UpdatedAt) { active = t } }
    var list []map[string]any; var sumUp, sumDown int64
    for i, e := range active.Entries {
        inbTag := fmt.Sprintf("t-inbound-%d", i+1)
        var up, down int64
        if v, ok := a.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok { up += v }
        if v, ok := a.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok { down += v }
        list = append(list, map[string]any{"id": e.ID, "tag": e.Tag, "entry_port": e.EntryPort, "uplink": up, "downlink": down, "total": up+down})
        sumUp += up; sumDown += down
    }
    out["tunnels"] = list; out["total"] = map[string]any{"uplink": sumUp, "downlink": sumDown, "total": sumUp+sumDown}
    return out
}

func (a *app) restartPortalMonitor() {
    if a.pMonStop != nil { close(a.pMonStop) }
    stop := make(chan struct{}); a.pMonStop = stop
    go func() {
        ticker := time.NewTicker(2*time.Second); defer ticker.Stop()
        var prev map[string]struct{up,down int64}; var prevTs int64
        for {
            select { case <-stop: return; case <-ticker.C:
                if a.orch == nil { continue }
                ts := time.Now().UnixMilli()
                tunnels := a.portal.all(); if len(tunnels) == 0 { continue }
                active := tunnels[0]; for _, t := range tunnels { if t.UpdatedAt.After(active.UpdatedAt) { active = t } }
                per := make(map[string]struct{up,down int64})
                for i, e := range active.Entries {
                    inbTag := fmt.Sprintf("t-inbound-%d", i+1)
                    up, down := int64(0), int64(0)
                    if v, ok := a.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok { up += v }
                    if v, ok := a.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok { down += v }
                    per[e.ID] = struct{up,down int64}{up: up, down: down}
                }
                a.recordPortalStats(ts, per)
                // WS broadcast of rates (portal)
                if a.wsStats != nil && prevTs > 0 {
                    dt := ts - prevTs; if dt > 0 {
                        type item struct { ID, Tag string; EntryPort int; Up, Down, BytesUp, BytesDown int64 }
                        var items []item; var sumUp, sumDown, cumUp, cumDown int64
                        for _, e := range active.Entries {
                            cur := per[e.ID]; pre := prev[e.ID]
                            up := cur.up - pre.up; down := cur.down - pre.down
                            if up < 0 { up = 0 }; if down < 0 { down = 0 }
                            up = up * 1000 / dt; down = down * 1000 / dt
                            items = append(items, item{ID: e.ID, Tag: e.Tag, EntryPort: e.EntryPort, Up: up, Down: down, BytesUp: cur.up, BytesDown: cur.down})
                            sumUp += up; sumDown += down; cumUp += cur.up; cumDown += cur.down
                        }
                        msg := map[string]any{"role":"portal", "ts": ts, "total": map[string]any{"up": sumUp, "down": sumDown}, "bytes": map[string]any{"up": cumUp, "down": cumDown}, "tunnels": items}
                        a.wsStats.BroadcastJSON(msg)
                    }
                }
                prev = per; prevTs = ts
            }
        }
    }()
}

// ===== Stats (bridge) =====
func (a *app) recordBridgeStats(ts int64, per map[string]struct{up,down int64}) {
    a.bStatsMu.Lock(); defer a.bStatsMu.Unlock()
    var totUp, totDown int64
    if a.bStatsPerTunnel == nil { a.bStatsPerTunnel = make(map[string][]statsPoint) }
    for id, v := range per { totUp += v.up; totDown += v.down; arr := a.bStatsPerTunnel[id]; arr = append(arr, statsPoint{TS: ts, Up:v.up, Down:v.down}); if len(arr) > statsCap { arr = arr[len(arr)-statsCap:] }; a.bStatsPerTunnel[id] = arr }
    a.bStatsTotal = append(a.bStatsTotal, statsPoint{TS: ts, Up: totUp, Down: totDown}); if len(a.bStatsTotal) > statsCap { a.bStatsTotal = a.bStatsTotal[len(a.bStatsTotal)-statsCap:] }
}

func (a *app) bridgeStatsRange(since int64, tunnelID string) (series []statsPoint, intervalMs int64) {
    a.bStatsMu.Lock(); defer a.bStatsMu.Unlock()
    var arr []statsPoint
    if tunnelID == "" { arr = append(arr, a.bStatsTotal...) } else { arr = append(arr, a.bStatsPerTunnel[tunnelID]...) }
    start := 0; for i,p := range arr { if p.TS >= since { start = i; break } }; arr = arr[start:]
    if len(arr) < 2 { return nil, 0 }
    for i := 1; i < len(arr); i++ { dt := arr[i].TS - arr[i-1].TS; if dt <= 0 { continue }; up := arr[i].Up - arr[i-1].Up; down := arr[i].Down - arr[i-1].Down; if up<0 { up=0 }; if down<0 { down=0 }; series = append(series, statsPoint{TS: arr[i].TS, Up: up*1000/dt, Down: down*1000/dt}) }
    intervalMs = arr[len(arr)-1].TS - arr[len(arr)-2].TS; if intervalMs <= 0 { intervalMs = 2000 }
    return
}

func (a *app) bridgeStatsSnapshot() map[string]any {
    now := time.Now().UnixMilli(); out := map[string]any{"ts": now, "tunnels": []map[string]any{}, "total": map[string]any{"uplink": int64(0), "downlink": int64(0), "total": int64(0)}}
    if a.orch == nil { return out }
    a.bridge.mu.RLock(); p := a.bridge.params; a.bridge.mu.RUnlock(); if p == nil || len(p.Tunnels) == 0 { return out }
    var list []map[string]any; var sumUp, sumDown int64
    for i, t := range p.Tunnels {
        revTag := fmt.Sprintf("rev-link-%d", i); inbTag := fmt.Sprintf("r-inbound-%d", i)
        var up, down int64
        if v, ok := a.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>uplink", revTag)); ok { up += v }
        if v, ok := a.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>downlink", revTag)); ok { down += v }
        if v, ok := a.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok { up += v }
        if v, ok := a.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok { down += v }
        list = append(list, map[string]any{"id": t.ID, "tag": t.Tag, "entry_port": t.EntryPort, "uplink": up, "downlink": down, "total": up+down})
        sumUp += up; sumDown += down
    }
    out["tunnels"] = list; out["total"] = map[string]any{"uplink": sumUp, "downlink": sumDown, "total": sumUp+sumDown}
    return out
}

func (a *app) restartBridgeMonitor() {
    if a.bMonStop != nil { close(a.bMonStop) }
    stop := make(chan struct{}); a.bMonStop = stop
    go func() {
        prevPer := make(map[string]struct{up,down int64}); var prevTs int64
        ticker := time.NewTicker(2*time.Second); defer ticker.Stop()
        for {
            select { case <-stop: return; case <-ticker.C:
                if a.orch == nil { continue }
                a.bridge.mu.RLock(); p := a.bridge.params; a.bridge.mu.RUnlock(); if p == nil { continue }
                ts := time.Now().UnixMilli(); per := make(map[string]struct{up,down int64})
                for i, t := range p.Tunnels {
                    revTag := fmt.Sprintf("rev-link-%d", i); inbTag := fmt.Sprintf("r-inbound-%d", i)
                    up, down := int64(0), int64(0)
                    if v, ok := a.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>uplink", revTag)); ok { up += v }
                    if v, ok := a.orch.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>downlink", revTag)); ok { down += v }
                    if v, ok := a.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok { up += v }
                    if v, ok := a.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok { down += v }
                    per[t.ID] = struct{up,down int64}{up: up, down: down}
                }
                a.recordBridgeStats(ts, per)
                if a.wsStats != nil && prevTs > 0 {
                    dt := ts - prevTs; if dt > 0 {
                        type item struct { ID, Tag string; EntryPort int; Up, Down, BytesUp, BytesDown int64 }
                        var items []item; var sumUp, sumDown, cumUp, cumDown int64
                        for _, t := range p.Tunnels {
                            cur := per[t.ID]; pre := prevPer[t.ID]
                            up := cur.up - pre.up; down := cur.down - pre.down
                            if up < 0 { up = 0 }; if down < 0 { down = 0 }
                            up = up * 1000 / dt; down = down * 1000 / dt
                            items = append(items, item{ID: t.ID, Tag: t.Tag, EntryPort: t.EntryPort, Up: up, Down: down, BytesUp: cur.up, BytesDown: cur.down})
                            sumUp += up; sumDown += down; cumUp += cur.up; cumDown += cur.down
                        }
                        msg := map[string]any{"role":"bridge", "ts": ts, "total": map[string]any{"up": sumUp, "down": sumDown}, "bytes": map[string]any{"up": cumUp, "down": cumDown}, "tunnels": items}
                        a.wsStats.BroadcastJSON(msg)
                    }
                }
                prevPer = per; prevTs = ts
            }
        }
    }()
}

// ===== Reality helpers =====
// genX25519 returns base64url (no padding) encoded public and private keys
func genX25519() (string, string, error) {
    c := ecdh.X25519()
    priv, err := c.GenerateKey(crand.Reader); if err != nil { return "", "", err }
    pub := priv.PublicKey(); return base64.RawURLEncoding.EncodeToString(pub.Bytes()), base64.RawURLEncoding.EncodeToString(priv.Bytes()), nil
}
