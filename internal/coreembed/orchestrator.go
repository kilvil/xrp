package coreembed

import (
    "encoding/json"
    "fmt"
    "sync"

    "github.com/xtls/xray-core/core"
    xinconf "github.com/xtls/xray-core/infra/conf"
    // Register all features and JSON/TOML/YAML config loaders
    _ "github.com/xtls/xray-core/main/distro/all"
    fstats "github.com/xtls/xray-core/features/stats"
)

// Orchestrator runs an embedded xray-core instance from JSON configs.
// It accepts standard Xray JSON (same as external binary), parses it via
// infra/conf and starts a core.Instance in-process.
type Orchestrator struct {
    mu   sync.Mutex
    inst *core.Instance
}

func New() *Orchestrator { return &Orchestrator{} }

// StartJSON starts xray-core with the provided JSON config. It fails if an
// instance is already running. Use RestartJSON for seamless reconfiguration.
func (o *Orchestrator) StartJSON(cfg []byte) error {
    o.mu.Lock()
    defer o.mu.Unlock()
    if o.inst != nil {
        return fmt.Errorf("xray already running")
    }
    c, err := buildCoreConfig(cfg)
    if err != nil {
        return err
    }
    inst, err := core.New(c)
    if err != nil {
        return err
    }
    if err := inst.Start(); err != nil {
        _ = inst.Close()
        return err
    }
    o.inst = inst
    return nil
}

// RestartJSON stops current instance (if any) and starts a new one.
func (o *Orchestrator) RestartJSON(cfg []byte) error {
    o.mu.Lock()
    old := o.inst
    o.inst = nil
    o.mu.Unlock()
    if old != nil {
        _ = old.Close()
    }
    return o.StartJSON(cfg)
}

// Stop shuts down the embedded instance if running.
func (o *Orchestrator) Stop() error {
    o.mu.Lock()
    inst := o.inst
    o.inst = nil
    o.mu.Unlock()
    if inst == nil {
        return nil
    }
    return inst.Close()
}

// buildCoreConfig parses JSON into a *core.Config using xray's infra/conf.
func buildCoreConfig(raw []byte) (*core.Config, error) {
    var cfg xinconf.Config
    if err := json.Unmarshal(raw, &cfg); err != nil {
        return nil, fmt.Errorf("xray config parse: %w", err)
    }
    c, err := cfg.Build()
    if err != nil {
        return nil, fmt.Errorf("xray config build: %w", err)
    }
    return c, nil
}

// WithInstance allows callers to safely access the underlying *core.Instance.
// The provided callback is executed under lock to ensure instance stability.
// Callback should avoid long blocking operations.
func (o *Orchestrator) WithInstance(cb func(*core.Instance)) {
    o.mu.Lock()
    inst := o.inst
    o.mu.Unlock()
    if inst != nil {
        cb(inst)
    }
}

// GetCounter returns the current value of a stats counter if available.
// Counter names follow xray convention, e.g.,
//  - inbound>>>r-inbound-0>>>traffic>>>downlink
//  - outbound>>>rev-link-0>>>traffic>>>uplink
func (o *Orchestrator) GetCounter(name string) (val int64, ok bool) {
    var out int64
    var found bool
    o.WithInstance(func(inst *core.Instance) {
        // Access stats.Manager feature from the instance.
        if inst == nil { return }
        // RequireFeatures ensures feature is available when started; fallback to GetFeature.
        _ = inst.RequireFeatures(func(m fstats.Manager) error {
            if m == nil { return nil }
            c := m.GetCounter(name)
            if c != nil {
                out = c.Value()
                found = true
            }
            return nil
        }, true)
        if !found {
            if f := inst.GetFeature(fstats.ManagerType()); f != nil {
                if m, ok2 := f.(fstats.Manager); ok2 {
                    if c := m.GetCounter(name); c != nil {
                        out = c.Value()
                        found = true
                    }
                }
            }
        }
    })
    return out, found
}

// IsRunning reports whether the underlying xray-core instance is started.
func (o *Orchestrator) IsRunning() bool {
    o.mu.Lock()
    defer o.mu.Unlock()
    return o.inst != nil && o.inst.IsRunning()
}

// RequireFeature allows caller to execute a callback with desired feature when available.
// Example: Orchestrator.RequireFeature(stats.ManagerType(), func(f features.Feature){...})
func (o *Orchestrator) RequireFeature(cb interface{}) error {
    var err error
    o.WithInstance(func(inst *core.Instance) {
        if inst == nil { return }
        // optional resolution
        err = inst.RequireFeatures(cb, true)
    })
    return err
}
