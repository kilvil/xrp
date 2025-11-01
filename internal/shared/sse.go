package shared

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"
)

// SSEHub is a minimal Server-Sent Events broadcaster
type SSEHub struct {
    mu    sync.Mutex
    conns map[chan string]struct{}
}

func NewSSEHub() *SSEHub {
    return &SSEHub{conns: make(map[chan string]struct{})}
}

func (h *SSEHub) Broadcast(msg string) {
    h.mu.Lock()
    defer h.mu.Unlock()
    for ch := range h.conns {
        select {
        case ch <- msg:
        default:
            // drop if slow
        }
    }
}

// ServeHTTP handles /logs/stream style endpoints
func (h *SSEHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")

    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "streaming unsupported", http.StatusInternalServerError)
        return
    }

    ctx := r.Context()
    ch := make(chan string, 64)
    h.mu.Lock()
    h.conns[ch] = struct{}{}
    h.mu.Unlock()
    defer func() {
        h.mu.Lock()
        delete(h.conns, ch)
        close(ch)
        h.mu.Unlock()
    }()

    // initial ping
    fmt.Fprintf(w, ":ok\n\n")
    flusher.Flush()

    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            // keepalive comment
            if _, err := fmt.Fprintf(w, ": ping %d\n\n", time.Now().Unix()); err != nil {
                log.Printf("sse write err: %v", err)
                return
            }
            flusher.Flush()
        case msg := <-ch:
            if _, err := fmt.Fprintf(w, "data: %s\n\n", msg); err != nil {
                log.Printf("sse write err: %v", err)
                return
            }
            flusher.Flush()
        }
    }
}

// Stream helper: send a message with a context timeout
func (h *SSEHub) Stream(ctx context.Context, msg string) {
    done := make(chan struct{}, 1)
    go func() { h.Broadcast(msg); done <- struct{}{} }()
    select {
    case <-ctx.Done():
    case <-done:
    }
}

