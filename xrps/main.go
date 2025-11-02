package main

import (
    "context"
    crand "crypto/rand"
    "crypto/mlkem"
    "crypto/sha256"
    "crypto/subtle"
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
    // PrivKey: REALITY private key (base64url, 32 bytes). Not exposed.
    PrivKey   string                 `json:"-"`
    // VLESSDec stores server-side decryption string for ML-KEM/X25519+ (not exposed in APIs)
    VLESSDec  string                 `json:"-"`
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
    Decryption    string `json:"decryption,omitempty"`
    EntryPorts    []int  `json:"entry_ports"`
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
    // auth
    authPath  string
    authUser  string
    authSalt  string
    authHash  string
    // stats store & monitor
    statsMu        sync.Mutex
    statsTotal     []statsPoint
    statsPerEntry  map[string][]statsPoint
    statsStop      chan struct{}
    // WS stats hub
    wsStats        *shared.WSHub
}

type statsPoint struct {
    TS   int64 `json:"ts"`
    Up   int64 `json:"uplink"`
    Down int64 `json:"downlink"`
}

const statsCap = 1800

func (s *Server) recordStats(ts int64, per map[string]struct{ up, down int64 }) {
    s.statsMu.Lock(); defer s.statsMu.Unlock()
    var totUp, totDown int64
    if s.statsPerEntry == nil { s.statsPerEntry = make(map[string][]statsPoint) }
    for id, v := range per {
        totUp += v.up; totDown += v.down
        arr := s.statsPerEntry[id]
        arr = append(arr, statsPoint{TS: ts, Up: v.up, Down: v.down})
        if len(arr) > statsCap { arr = arr[len(arr)-statsCap:] }
        s.statsPerEntry[id] = arr
    }
    s.statsTotal = append(s.statsTotal, statsPoint{TS: ts, Up: totUp, Down: totDown})
    if len(s.statsTotal) > statsCap { s.statsTotal = s.statsTotal[len(s.statsTotal)-statsCap:] }
}

func (s *Server) statsRange(since int64, entryID string) (series []statsPoint, intervalMs int64) {
    s.statsMu.Lock(); defer s.statsMu.Unlock()
    var arr []statsPoint
    if entryID == "" { arr = append(arr, s.statsTotal...) } else { arr = append(arr, s.statsPerEntry[entryID]...) }
    // filter by since
    start := 0
    for i, p := range arr { if p.TS >= since { start = i; break } }
    arr = arr[start:]
    if len(arr) < 2 { return nil, 0 }
    for i := 1; i < len(arr); i++ {
        dt := arr[i].TS - arr[i-1].TS
        if dt <= 0 { continue }
        up := arr[i].Up - arr[i-1].Up
        down := arr[i].Down - arr[i-1].Down
        if up < 0 { up = 0 }
        if down < 0 { down = 0 }
        series = append(series, statsPoint{TS: arr[i].TS, Up: up*1000/dt, Down: down*1000/dt})
    }
    intervalMs = arr[len(arr)-1].TS - arr[len(arr)-2].TS
    if intervalMs <= 0 { intervalMs = 2000 }
    return
}

// startStatsMonitor polls xray counters periodically and feeds in-memory buffers
func (s *Server) startStatsMonitor() {
    if s.statsStop != nil { close(s.statsStop) }
    stop := make(chan struct{})
    s.statsStop = stop
    go func() {
        ticker := time.NewTicker(2 * time.Second)
        defer ticker.Stop()
        var prev map[string]struct{ up, down int64 }
        var prevTs int64
        for {
            select {
            case <-stop:
                return
            case <-ticker.C:
                if s.orch == nil { continue }
                ts := time.Now().UnixMilli()
                // pick active tunnel (same logic as buildPortalConfig)
                tunnels := s.store.All()
                if len(tunnels) == 0 { continue }
                active := tunnels[0]
                for _, t := range tunnels { if t.UpdatedAt.After(active.UpdatedAt) { active = t } }
                per := make(map[string]struct{ up, down int64 })
                for i, e := range active.Entries {
                    inbTag := fmt.Sprintf("t-inbound-%d", i+1)
                    up, down := int64(0), int64(0)
                    if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok { up += v }
                    if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok { down += v }
                    per[e.ID] = struct{ up, down int64 }{up: up, down: down}
                }
                s.recordStats(ts, per)
                // WS broadcast of rates
                if s.wsStats != nil && prevTs > 0 {
                    dt := ts - prevTs
                    if dt > 0 {
                        type item struct{ ID, Tag string; EntryPort int; Up, Down, BytesUp, BytesDown int64 }
                        var items []item
                        var sumUp, sumDown int64
                        var cumUp, cumDown int64
                        for _, e := range active.Entries {
                            cur := per[e.ID]
                            pre := prev[e.ID]
                            up := cur.up - pre.up
                            down := cur.down - pre.down
                            if up < 0 { up = 0 }
                            if down < 0 { down = 0 }
                            up = up * 1000 / dt
                            down = down * 1000 / dt
                            items = append(items, item{ID: e.ID, Tag: e.Tag, EntryPort: e.EntryPort, Up: up, Down: down, BytesUp: cur.up, BytesDown: cur.down})
                            sumUp += up
                            sumDown += down
                            cumUp += cur.up
                            cumDown += cur.down
                        }
                        msg := map[string]any{"ts": ts, "total": map[string]any{"up": sumUp, "down": sumDown}, "bytes": map[string]any{"up": cumUp, "down": cumDown}, "tunnels": items}
                        s.wsStats.BroadcastJSON(msg)
                    }
                }
                prev = per
                prevTs = ts
            }
        }
    }()
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
    // Preserve case for base64url payload; only trim and validate prefix.
    s = strings.TrimSpace(s)
    if strings.EqualFold(s, "none") { return "none" }
    if strings.HasPrefix(strings.ToLower(s), "mlkem768x25519plus.") { return s }
    return "none"
}

// sanitizeVLESSDecryption mirrors encryption sanitation for inbound usage.
// Allowed: "none" or strings starting with "mlkem768x25519plus.".
func sanitizeVLESSDecryption(s string) string {
    s = strings.TrimSpace(s)
    if strings.EqualFold(s, "none") || s == "" { return "none" }
    if strings.HasPrefix(strings.ToLower(s), "mlkem768x25519plus.") { return s }
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
    // WebSocket: real-time rates
    if s.wsStats == nil { s.wsStats = shared.NewWSHub() }
    mux.Handle("/ws/stats", s.wsStats)

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
    // removed: /api/reality/mldsa65 (unused feature)

    // generate VLESS Encryption decryption/encryption pair
    // query: algo = pq|mlkem768|x25519 (default pq), mode=native (reserved), seconds=600
    mux.HandleFunc("/api/vlessenc", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        q := r.URL.Query()
        algo := strings.ToLower(strings.TrimSpace(q.Get("algo")))
        if algo == "" { algo = "pq" }
        // Only one mode supported currently
        _ = q.Get("mode")
        sec := strings.TrimSpace(q.Get("seconds"))
        if sec == "" { sec = "600" }
        // header prefix
        const algHeader = "mlkem768x25519plus"
        mode := "native"
        var decryption, encryption string
        switch algo {
        case "x25519":
            // Use X25519: decryption carries 32-byte private key; encryption carries 32-byte public key
            pub, priv, err := genX25519()
            if err != nil { http.Error(w, err.Error(), 500); return }
            decryption = algHeader + "." + mode + "." + sec + "s." + priv
            encryption = algHeader + "." + mode + ".0rtt." + pub
        case "pq", "mlkem768", "ml-kem-768", "ml_kem_768":
            // Generate ML-KEM-768 decapsulation seed (64 bytes) and encapsulation key (1184 bytes)
            var seed [64]byte
            _, _ = crand.Read(seed[:])
            dkey, err := mlkem.NewDecapsulationKey768(seed[:])
            if err != nil { http.Error(w, "mlkem768 keygen failed: "+err.Error(), 500); return }
            client := dkey.EncapsulationKey().Bytes()
            serverKey := base64.RawURLEncoding.EncodeToString(seed[:])
            clientKey := base64.RawURLEncoding.EncodeToString(client)
            decryption = algHeader + "." + mode + "." + sec + "s." + serverKey
            encryption = algHeader + "." + mode + ".0rtt." + clientKey
        default:
            http.Error(w, "unknown algo: use pq|x25519", 400); return
        }
        writeJSON(w, map[string]any{
            "algorithm":  algHeader,
            "mode":       mode,
            "decryption": decryption,
            "encryption": encryption,
            "note":       "Choose one authentication; do not mix X25519 and ML-KEM-768.",
        })
    })

    // optional static UI under /ui/
    if s.uiFS != nil {
        mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(s.uiFS)))
    }

    // stats snapshot: cumulative bytes by entry for active tunnel
    mux.HandleFunc("/api/stats/snapshot", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        writeJSON(w, s.statsSnapshot())
    })

    // stats range: bytes/sec since timestamp; optional entry=id
    mux.HandleFunc("/api/stats/range", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet { http.Error(w, "method not allowed", 405); return }
        q := r.URL.Query()
        sinceStr := q.Get("since")
        if sinceStr == "" { http.Error(w, "query since=epochMillis required", 400); return }
        since, err := strconv.ParseInt(sinceStr, 10, 64)
        if err != nil { http.Error(w, "invalid since", 400); return }
        entry := q.Get("entry")
        series, step := s.statsRange(since, entry)
        writeJSON(w, map[string]any{"series": series, "interval": step})
    })

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
            // Optional PQ decryption for portal inbound
            vlessDec := sanitizeVLESSDecryption(req.Decryption)
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
            // Require private key to be provided; derive public key from it.
            if strings.TrimSpace(privKey) == "" {
                http.Error(w, "private_key is required", 400); return
            }
            if h.ShortID == "" { h.ShortID = randomHex(8) }
            entries := make([]shared.TunnelEntry, 0, len(req.EntryPorts))
            for i, ep := range req.EntryPorts {
                entries = append(entries, shared.TunnelEntry{
                    EntryPort:   ep,
                    ID:          randomUUID(),
                    Tag:         fmt.Sprintf("t%d", i+1),
                    // Remove default map port hint; XRPC will ask user for target.
                    MapPortHint: 0,
                })
            }
            t := &Tunnel{ID: id, Name: req.Name, Portal: req.PortalAddr, Handshake: h, Entries: entries, PrivKey: privKey, VLESSDec: vlessDec, CreatedAt: time.Now(), UpdatedAt: time.Now()}
            // server-side configuration validation + port conflict detection
            if err := s.validateTunnelConfig(t); err != nil {
                http.Error(w, err.Error(), 400); return
            }
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
                    Decryption    *string `json:"decryption,omitempty"`
                    EntryPorts    *[]int  `json:"entry_ports,omitempty"`
                    PrivateKey    *string `json:"private_key,omitempty"`
                }
                var req patchTunnelReq
                if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, err.Error(), 400); return }
                // apply changes
                if req.Name != nil { t.Name = *req.Name }
                if req.PortalAddr != nil { t.Portal = *req.PortalAddr }
                if req.HandshakePort != nil { t.Handshake.Port = *req.HandshakePort }
                if req.ServerName != nil { t.Handshake.ServerName = *req.ServerName }
                if req.Encryption != nil {
                    if strings.EqualFold(*req.Encryption, "pq") {
                        http.Error(w, "encryption 'pq' is not supported; use 'none' or 'mlkem768x25519plus.*'", 400); return
                    }
                    t.Handshake.Encryption = sanitizeVLESSEncryption(*req.Encryption)
                }
                if req.Decryption != nil {
                    t.VLESSDec = sanitizeVLESSDecryption(*req.Decryption)
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
                            // Remove default map port hint; XRPC will ask user for target.
                            MapPortHint: 0,
                        })
                    }
                    t.Entries = entries
                }
                // forward-proxy removed
                if req.PrivateKey != nil {
                    pk := strings.TrimSpace(*req.PrivateKey)
                    if pk == "" { http.Error(w, "private_key cannot be empty", 400); return }
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
                // validate config after patch before applying
                if err := s.validateTunnelConfig(t); err != nil { http.Error(w, err.Error(), 400); return }
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

    return withCORS(s.secure(mux))
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

// statsSnapshot returns cumulative inbound traffic per entry for active tunnel.
func (s *Server) statsSnapshot() map[string]any {
    now := time.Now().UnixMilli()
    out := map[string]any{
        "ts": now,
        "tunnels": []map[string]any{},
        "total": map[string]any{"uplink": int64(0), "downlink": int64(0), "total": int64(0)},
    }
    if s.orch == nil {
        return out
    }
    tunnels := s.store.All()
    if len(tunnels) == 0 {
        return out
    }
    active := tunnels[0]
    for _, t := range tunnels {
        if t.UpdatedAt.After(active.UpdatedAt) { active = t }
    }
    var list []map[string]any
    var sumUp, sumDown int64
    for i, e := range active.Entries {
        inbTag := fmt.Sprintf("t-inbound-%d", i+1)
        var up, down int64
        if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", inbTag)); ok { up += v }
        if v, ok := s.orch.GetCounter(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", inbTag)); ok { down += v }
        list = append(list, map[string]any{
            "id": e.ID,
            "tag": e.Tag,
            "entry_port": e.EntryPort,
            "uplink": up,
            "downlink": down,
            "total": up + down,
        })
        sumUp += up
        sumDown += down
    }
    out["tunnels"] = list
    out["total"] = map[string]any{"uplink": sumUp, "downlink": sumDown, "total": sumUp + sumDown}
    return out
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

// secure wraps handlers with HTTP Basic Auth (admin/<password>), except for /healthz and OPTIONS.
func (s *Server) secure(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodOptions || r.URL.Path == "/healthz" {
            next.ServeHTTP(w, r)
            return
        }
        // If no auth configured yet, allow (should not happen after init)
        if s.authUser == "" || s.authHash == "" {
            next.ServeHTTP(w, r)
            return
        }
        user, pass, ok := r.BasicAuth()
        if !ok || !s.checkPassword(user, pass) {
            w.Header().Set("WWW-Authenticate", "Basic realm=\"XRPS\"")
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func (s *Server) checkPassword(user, pass string) bool {
    if user != s.authUser { return false }
    if s.authSalt == "" || s.authHash == "" { return false }
    h := hashPassword(s.authSalt, pass)
    if subtle.ConstantTimeCompare([]byte(h), []byte(s.authHash)) != 1 { return false }
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

// getStateDir returns the directory to store XRPS state (auth, etc.).
// Order: XRPS_STATE_DIR env -> /var/lib/xrps
func getStateDir() string {
    if v := strings.TrimSpace(os.Getenv("XRPS_STATE_DIR")); v != "" {
        return v
    }
    return "/var/lib/xrps"
}

// initAuth loads or creates admin credentials in getStateDir()/admin.auth.json
func (s *Server) initAuth() error {
    dir := getStateDir()
    if err := os.MkdirAll(dir, 0o755); err != nil { return err }
    path := filepath.Join(dir, "admin.auth.json")
    s.authPath = path
    type authFile struct {
        Username  string `json:"username"`
        Salt      string `json:"salt"`
        Hash      string `json:"hash"`
        CreatedAt string `json:"createdAt"`
    }
    if _, err := os.Stat(path); os.IsNotExist(err) {
        // first run: generate strong password and persist hash
        user := "admin"
        salt := randomHex(16)
        pass := randomBase64URL(24)
        h := hashPassword(salt, pass)
        af := authFile{Username: user, Salt: salt, Hash: h, CreatedAt: time.Now().Format(time.RFC3339)}
        b, _ := json.MarshalIndent(af, "", "  ")
        _ = os.WriteFile(path, b, 0o600)
        s.authUser, s.authSalt, s.authHash = user, salt, h
        log.Printf("==== XRPS 初次运行创建管理员账户 ====")
        log.Printf("用户名: admin  初始密码: %s", pass)
        log.Printf("凭据文件: %s", path)
        return nil
    }
    // load existing
    b, err := os.ReadFile(path)
    if err != nil { return err }
    var af authFile
    if err := json.Unmarshal(b, &af); err != nil { return err }
    s.authUser, s.authSalt, s.authHash = af.Username, af.Salt, af.Hash
    return nil
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
func (s *Server) startCore() error {
    log.Printf("xray-core: starting…")
    if s.orch == nil { s.orch = coreembed.New() }
    // Store config under home directory: ~/xrp
    var runDir string
    if home, err := os.UserHomeDir(); err == nil {
        runDir = filepath.Join(home, "xrp")
    } else {
        runDir = s.logDir
    }
    _ = os.MkdirAll(runDir, 0o755)
    // Default config path
    cfgPath := os.Getenv("XRPS_XRAY_CFG_PATH")
    if cfgPath == "" { cfgPath = filepath.Join(runDir, "xray.portal.json") }
    // Build portal config from current tunnels; on failure, try to reuse existing config file
    cfg, err := s.buildPortalConfig()
    if err != nil {
        // If there is an existing config file, reuse it
        if b, rerr := os.ReadFile(cfgPath); rerr == nil {
            log.Printf("xray-core: build failed, reusing existing config at %s: %v", cfgPath, err)
            cfg = b
        } else {
            log.Printf("xray-core: build portal config failed, using minimal: %v", err)
            cfg = []byte(fmt.Sprintf(`{
      "log": {"loglevel": "warning", "access": %q, "error": %q},
      "outbounds": [{"protocol": "blackhole", "tag":"blackhole"}],
      "routing": {"rules": []}
    }`, s.accessPath, s.errorPath))
        }
    }
    if p := os.Getenv("XRAY_CFG_PORTAL"); p != "" {
        if b, err := os.ReadFile(p); err == nil { cfg = b } else { log.Printf("xray-core: warn cannot read XRAY_CFG_PORTAL=%s: %v", p, err) }
    }
    // Print effective config for debugging
    log.Printf("xray-core: effective portal config:\n%s", string(cfg))
    // Write debug copy
    _ = os.WriteFile(cfgPath, cfg, 0o644)
    if err := s.orch.StartJSON(cfg); err != nil {
        log.Printf("xray-core: start failed: %v", err)
        s.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_failed\",\"reason\":\"spawn\",\"ts\":%d}", time.Now().Unix()))
        return err
    }
    log.Printf("xray-core: started (cfg=%s)", cfgPath)
    s.logs.Broadcast(fmt.Sprintf("{\"event\":\"core_started\",\"ts\":%d}", time.Now().Unix()))
    s.startStatsMonitor()
    return nil
}

// restartCore simulates a restart and logs outcome.
func (s *Server) restartCore() error {
    log.Printf("xray-core: restarting…")
    if s.orch == nil { s.orch = coreembed.New() }
    // Store config under home directory: ~/xrp
    var runDir string
    if home, err := os.UserHomeDir(); err == nil { runDir = filepath.Join(home, "xrp") } else { runDir = s.logDir }
    _ = os.MkdirAll(runDir, 0o755)
    cfgPath := filepath.Join(runDir, "xray.portal.json")
    // Build portal config from current tunnels; on failure, try to reuse existing config file
    cfg, err := s.buildPortalConfig()
    if err != nil {
        if b, rerr := os.ReadFile(cfgPath); rerr == nil {
            log.Printf("xray-core: build failed, reusing existing config at %s: %v", cfgPath, err)
            cfg = b
        } else {
            log.Printf("xray-core: build portal config failed, using minimal: %v", err)
            cfg = []byte(fmt.Sprintf(`{
      "log": {"loglevel": "warning", "access": %q, "error": %q},
      "outbounds": [{"protocol": "blackhole", "tag":"blackhole"}],
      "routing": {"rules": []}
    }`, s.accessPath, s.errorPath))
        }
    }
    if p := os.Getenv("XRAY_CFG_PORTAL"); p != "" {
        if b, err := os.ReadFile(p); err == nil { cfg = b } else { log.Printf("xray-core: warn cannot read XRAY_CFG_PORTAL=%s: %v", p, err) }
    }
    // Print effective config for debugging on restart
    log.Printf("xray-core: effective portal config (restart):\n%s", string(cfg))
    _ = os.WriteFile(cfgPath, cfg, 0o644)
    if err := s.orch.RestartJSON(cfg); err != nil {
        log.Printf("xray-core: restart failed: %v", err)
        return err
    }
    log.Printf("xray-core: restart ok")
    s.startStatsMonitor()
    return nil
}

// buildPortalConfig constructs an xray JSON config reflecting current tunnels.
// It follows PRD: VLESS+REALITY handshake inbound + per-entry tunnel inbounds
// routed to dynamic reverse outbounds exposed via clients[].reverse.tag.
func (s *Server) buildPortalConfig() ([]byte, error) {
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
    inbounds := make([]map[string]any, 0, len(active.Entries)+1)

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
            // If PQ is configured, use stored decryption string; otherwise none
            "decryption": func() string { if active.VLESSDec != "" && !strings.EqualFold(active.VLESSDec, "none") { return active.VLESSDec }; return "none" }(),
        },
    }

    // Attach REALITY settings: require stored per-tunnel private key
    priv := active.PrivKey
    if strings.TrimSpace(priv) == "" { return nil, fmt.Errorf("missing REALITY private_key") }
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

    // Add api/stats/policy so that counters are exposed.
    cfg := map[string]any{
        "log": map[string]any{"loglevel": "warning", "access": s.accessPath, "error": s.errorPath},
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
        "outbounds": []map[string]any{
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blackhole", "protocol": "blackhole"},
        },
        "routing": map[string]any{"rules": rules},
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

// serverListenPort parses the HTTP server listen address and returns its port.
func serverListenPort(addr string) int {
    addr = strings.TrimSpace(addr)
    if addr == "" { return 0 }
    if strings.HasPrefix(addr, ":") {
        if n, err := strconv.Atoi(strings.TrimPrefix(addr, ":")); err == nil { return n }
        return 0
    }
    if _, p, err := net.SplitHostPort(addr); err == nil {
        if n, err := strconv.Atoi(p); err == nil { return n }
    }
    return 0
}

func hasDupInt(vals []int) (bool, int) {
    seen := make(map[int]struct{}, len(vals))
    for _, v := range vals {
        if _, ok := seen[v]; ok { return true, v }
        seen[v] = struct{}{}
    }
    return false, 0
}

// validateTunnelConfig performs config validation and local port conflict checks.
func (s *Server) validateTunnelConfig(t *Tunnel) error {
    if t == nil { return fmt.Errorf("nil tunnel") }
    // basic fields
    if strings.TrimSpace(t.Portal) == "" { return fmt.Errorf("portal_addr is required") }
    if t.Handshake.Port <= 0 || t.Handshake.Port > 65535 { return fmt.Errorf("handshake_port must be 1-65535") }
    if strings.TrimSpace(t.Handshake.ServerName) == "" { return fmt.Errorf("server_name is required") }
    // require REALITY private key persisted per tunnel
    if strings.TrimSpace(t.PrivKey) == "" { return fmt.Errorf("private_key is required") }
    // encryption is sanitized elsewhere; ensure "pq" is not used
    if strings.EqualFold(t.Handshake.Encryption, "pq") { return fmt.Errorf("encryption 'pq' is not supported") }
    // shortId simple check (hex 8-32)
    if sid := strings.TrimSpace(t.Handshake.ShortID); sid != "" {
        if len(sid) < 8 || len(sid) > 32 { return fmt.Errorf("shortId length must be 8-32 hex digits") }
        if _, err := hex.DecodeString(sid); err != nil { return fmt.Errorf("shortId must be hex") }
    }
    // validate private key format
    if _, err := normalizeRealityKey32(t.PrivKey); err != nil { return fmt.Errorf("invalid private_key: %v", err) }
    // publicKey is used by clients; if present ensure format
    if strings.TrimSpace(t.Handshake.PublicKey) != "" {
        if _, err := normalizeRealityKey32(t.Handshake.PublicKey); err != nil { return fmt.Errorf("invalid public_key: %v", err) }
    }
    if len(t.Entries) == 0 { return fmt.Errorf("at least one entry port is required") }
    // gather ports
    httpPort := serverListenPort(s.addr)
    ports := make([]int, 0, 1+len(t.Entries))
    ports = append(ports, t.Handshake.Port)
    for _, e := range t.Entries {
        if e.EntryPort <= 0 || e.EntryPort > 65535 { return fmt.Errorf("entry_port %d must be 1-65535", e.EntryPort) }
        ports = append(ports, e.EntryPort)
    }
    if dup, v := hasDupInt(ports); dup {
        return fmt.Errorf("port conflict: port %d appears multiple times (handshake/entries)", v)
    }
    // ensure none equals the HTTP server port
    if httpPort > 0 {
        for _, p := range ports {
            if p == httpPort { return fmt.Errorf("port %d conflicts with XRPS HTTP server port", p) }
        }
    }
    // forward-proxy removed
    return nil
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
    } else {
        if efs := getEmbeddedUI(); efs != nil {
            s.uiFS = efs
            log.Printf("serving embedded UI at /ui/")
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
    // init admin auth
    if err := s.initAuth(); err != nil {
        log.Printf("auth init failed: %v; falling back to in-memory credentials", err)
        user := "admin"
        salt := randomHex(16)
        pass := randomBase64URL(24)
        h := hashPassword(salt, pass)
        s.authUser, s.authSalt, s.authHash = user, salt, h
        log.Printf("==== XRPS 内存凭据已启用（未持久化） ====")
        log.Printf("用户名: admin  初始密码: %s", pass)
        log.Printf("提示: 设置 XRPS_STATE_DIR 或确保 HOME 可用以持久化凭据")
    }
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
