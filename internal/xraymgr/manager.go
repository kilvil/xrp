package xraymgr

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "io"
    "log"
    "os"
    "os/exec"
    "path/filepath"
    "sync"
    "syscall"
    "time"
)

// Manager supervises an external xray-core process.
type Manager struct {
    bin   string
    mu    sync.Mutex
    cmd   *exec.Cmd
    cancel context.CancelFunc
}

func New(bin string) *Manager {
    if bin == "" { bin = "xray" }
    return &Manager{bin: bin}
}

// Start launches xray-core with the provided config JSON bytes. It writes the
// JSON to `cfgPath` for visibility. STDOUT is appended to accessLog; STDERR
// appended to errorLog.
func (m *Manager) Start(cfg []byte, cfgPath, accessLog, errorLog string) error {
    return m.StartWithOpts(cfg, cfgPath, accessLog, errorLog, "", nil)
}

// StartWithOpts launches xray-core with extra options like workdir and env.
func (m *Manager) StartWithOpts(cfg []byte, cfgPath, accessLog, errorLog, workdir string, env []string) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.cmd != nil {
        return errors.New("xray already running; call Restart or Stop first")
    }
    // Resolve config path to an absolute path to avoid CWD confusion when workdir is set.
    cfgFull := cfgPath
    if !filepath.IsAbs(cfgFull) {
        if workdir != "" {
            cfgFull = filepath.Join(workdir, cfgFull)
        }
        if abs, err := filepath.Abs(cfgFull); err == nil { cfgFull = abs }
    }
    if err := os.MkdirAll(filepath.Dir(cfgFull), 0o755); err != nil { return err }
    if err := os.WriteFile(cfgFull, cfg, 0o644); err != nil { return err }

    ctx, cancel := context.WithCancel(context.Background())
    cmd := exec.CommandContext(ctx, m.bin, "run", "-c", cfgFull)
    if workdir != "" { cmd.Dir = workdir }
    if len(env) > 0 { cmd.Env = append(os.Environ(), env...) }
    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()

    if err := cmd.Start(); err != nil {
        cancel()
        return err
    }
    m.cmd = cmd
    m.cancel = cancel

    go teeLines(stdout, accessLog, "[xray] ")
    go teeLines(stderr, errorLog, "[xray] ")

    go func() {
        err := cmd.Wait()
        if err != nil {
            log.Printf("xray-core exited: %v", err)
        } else {
            log.Printf("xray-core exited")
        }
        m.mu.Lock()
        if m.cancel != nil { m.cancel() }
        m.cmd = nil
        m.cancel = nil
        m.mu.Unlock()
    }()
    return nil
}

// Restart stops the process if running and starts a new one with cfg.
func (m *Manager) Restart(cfg []byte, cfgPath, accessLog, errorLog string) error {
    return m.RestartWithOpts(cfg, cfgPath, accessLog, errorLog, "", nil)
}

// RestartWithOpts stops then starts with the given options.
func (m *Manager) RestartWithOpts(cfg []byte, cfgPath, accessLog, errorLog, workdir string, env []string) error {
    if err := m.Stop(5 * time.Second); err != nil { return err }
    return m.StartWithOpts(cfg, cfgPath, accessLog, errorLog, workdir, env)
}

// Stop attempts a graceful stop, then SIGKILL after timeout.
func (m *Manager) Stop(timeout time.Duration) error {
    m.mu.Lock()
    cmd := m.cmd
    cancel := m.cancel
    m.mu.Unlock()
    if cmd == nil { return nil }
    // try SIGTERM
    _ = cmd.Process.Signal(syscall.SIGTERM)
    done := make(chan struct{})
    go func() { _ = cmd.Wait(); close(done) }()
    select {
    case <-done:
    case <-time.After(timeout):
        _ = cmd.Process.Kill()
    }
    if cancel != nil { cancel() }
    m.mu.Lock()
    m.cmd = nil
    m.cancel = nil
    m.mu.Unlock()
    return nil
}

func teeLines(r io.Reader, path string, prefix string) {
    if path == "" { path = filepath.Join("./logs", "xray.log") }
    _ = os.MkdirAll(filepath.Dir(path), 0o755)
    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
    if err != nil { log.Printf("teeLines open %s err: %v", path, err); return }
    defer f.Close()
    w := bufio.NewWriterSize(f, 64*1024)
    defer w.Flush()
    s := bufio.NewScanner(r)
    for s.Scan() {
        line := s.Text()
        fmt.Fprintln(w, prefix+line)
        w.Flush()
    }
}
