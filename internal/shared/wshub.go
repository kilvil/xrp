package shared

import (
    "crypto/sha1"
    "encoding/base64"
    "encoding/json"
    "io"
    "net"
    "net/http"
    "strings"
    "sync"
)

// WSHub is a minimal WebSocket broadcaster that implements the HTTP upgrade
// by hand (no external deps). It writes text frames to all connected clients.
// It does not read from clients; writes failing connections are removed.
type WSHub struct {
    mu    sync.Mutex
    conns map[net.Conn]struct{}
}

func NewWSHub() *WSHub { return &WSHub{conns: make(map[net.Conn]struct{})} }

// ServeHTTP upgrades the connection to a WebSocket and registers the client.
func (h *WSHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if !isUpgradeRequest(r) {
        http.Error(w, "upgrade required", http.StatusUpgradeRequired)
        return
    }
    key := r.Header.Get("Sec-WebSocket-Key")
    if key == "" {
        http.Error(w, "bad websocket key", 400)
        return
    }
    // Compute accept key
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    sum := sha1.Sum([]byte(key + magic))
    accept := base64.StdEncoding.EncodeToString(sum[:])

    hj, ok := w.(http.Hijacker)
    if !ok {
        http.Error(w, "hijacking not supported", 500)
        return
    }
    conn, buf, err := hj.Hijack()
    if err != nil { return }
    // Complete handshake
    resp := "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
    if _, err := io.WriteString(conn, resp); err != nil {
        _ = conn.Close()
        return
    }
    // Drain any buffered reader content (unlikely) to keep stream clean
    if buf.Reader.Buffered() > 0 { _, _ = buf.Reader.Discard(buf.Reader.Buffered()) }
    // Register connection
    h.mu.Lock()
    h.conns[conn] = struct{}{}
    h.mu.Unlock()
}

// isUpgradeRequest checks presence of proper upgrade headers more permissively.
func isUpgradeRequest(r *http.Request) bool {
    conn := r.Header.Get("Connection")
    if conn == "" { return false }
    hasUpgrade := false
    for _, tok := range strings.Split(conn, ",") {
        if strings.EqualFold(strings.TrimSpace(tok), "upgrade") { hasUpgrade = true; break }
    }
    if !hasUpgrade { return false }
    if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") { return false }
    if r.Header.Get("Sec-WebSocket-Key") == "" { return false }
    return true
}

// BroadcastText writes a WS text frame to all clients.
func (h *WSHub) BroadcastText(msg string) {
    h.mu.Lock()
    defer h.mu.Unlock()
    for c := range h.conns {
        if err := writeWSTextFrame(c, []byte(msg)); err != nil {
            _ = c.Close()
            delete(h.conns, c)
        }
    }
}

// BroadcastJSON marshals v and broadcasts as text frame.
func (h *WSHub) BroadcastJSON(v any) {
    b, err := json.Marshal(v)
    if err != nil { return }
    h.BroadcastText(string(b))
}

// Minimal text frame writer (server-to-client; no masking required).
func writeWSTextFrame(w io.Writer, payload []byte) error {
    // FIN=1, opcode=1 (text)
    header := []byte{0x81}
    n := len(payload)
    switch {
    case n <= 125:
        header = append(header, byte(n))
    case n < 65536:
        header = append(header, 126, byte(n>>8), byte(n))
    default:
        header = append(header, 127,
            byte(uint64(n)>>56), byte(uint64(n)>>48), byte(uint64(n)>>40), byte(uint64(n)>>32),
            byte(uint64(n)>>24), byte(uint64(n)>>16), byte(uint64(n)>>8), byte(uint64(n)))
    }
    if _, err := w.Write(header); err != nil { return err }
    _, err := w.Write(payload)
    return err
}
