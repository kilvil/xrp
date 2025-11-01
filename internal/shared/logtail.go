package shared

import (
    "bufio"
    "errors"
    "io"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

// FileTailer polls a file and emits newly appended lines.
type FileTailer struct {
    path     string
    interval time.Duration
    out      chan string
    stopCh   chan struct{}
    wg       sync.WaitGroup
}

func NewFileTailer(path string, interval time.Duration) *FileTailer {
    return &FileTailer{path: path, interval: interval, out: make(chan string, 256), stopCh: make(chan struct{})}
}

// Out returns a receive-only channel of lines.
func (t *FileTailer) Out() <-chan string { return t.out }

func (t *FileTailer) Start() {
    t.wg.Add(1)
    go func() {
        defer t.wg.Done()
        var offset int64 = 0
        var leftover string
        for {
            select {
            case <-t.stopCh:
                return
            default:
            }

            st, err := os.Stat(t.path)
            if err != nil {
                // if missing, create parent dir and sleep
                _ = os.MkdirAll(filepath.Dir(t.path), 0o755)
                time.Sleep(t.interval)
                continue
            }
            // rotated/truncated
            if st.Size() < offset {
                offset = 0
                leftover = ""
            }
            if st.Size() > offset {
                f, err := os.Open(t.path)
                if err != nil {
                    time.Sleep(t.interval)
                    continue
                }
                // read from last offset
                if _, err := f.Seek(offset, io.SeekStart); err != nil {
                    _ = f.Close()
                    time.Sleep(t.interval)
                    continue
                }
                r := bufio.NewReaderSize(f, 64*1024)
                for {
                    chunk, err := r.ReadString('\n')
                    if len(chunk) > 0 {
                        s := leftover + chunk
                        // split preserves trailing newline boundary
                        lines := strings.Split(s, "\n")
                        // all but last are complete
                        for i := 0; i < len(lines)-1; i++ {
                            line := strings.TrimRight(lines[i], "\r")
                            if line != "" {
                                select { case t.out <- line: default: }
                            }
                        }
                        leftover = lines[len(lines)-1]
                        offset += int64(len(chunk))
                    }
                    if err != nil {
                        if errors.Is(err, io.EOF) {
                            break
                        }
                        break
                    }
                }
                _ = f.Close()
            }
            time.Sleep(t.interval)
        }
    }()
}

func (t *FileTailer) Stop() {
    close(t.stopCh)
    t.wg.Wait()
    close(t.out)
}

// TailLastN reads the last N lines from a file.
// It reads at most maxBytes from the end for efficiency.
func TailLastN(path string, n int, maxBytes int64) ([]string, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    st, err := f.Stat()
    if err != nil {
        return nil, err
    }
    size := st.Size()
    var start int64 = 0
    if maxBytes > 0 && size > maxBytes {
        start = size - maxBytes
    }
    if start > 0 {
        if _, err := f.Seek(start, io.SeekStart); err != nil { return nil, err }
    }
    data, err := io.ReadAll(f)
    if err != nil { return nil, err }
    lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
    // drop possible empty last element
    if len(lines) > 0 && lines[len(lines)-1] == "" { lines = lines[:len(lines)-1] }
    if n <= 0 || len(lines) <= n { return lines, nil }
    return lines[len(lines)-n:], nil
}

