package shared

import (
    "encoding/json"
    "errors"
)

// HandshakeConfig represents the portal handshake (VLESS+REALITY) parameters
type HandshakeConfig struct {
    Port       int    `json:"port"`
    ServerName string `json:"serverName"`
    PublicKey  string `json:"publicKey"`
    ShortID    string `json:"shortId"`
    Encryption string `json:"encryption"` // allowed: "none" or "mlkem768x25519plus.*" (PQ advanced). "pq" is rejected.
    Flow       string `json:"flow"`       // xtls-rprx-vision
}

// TunnelEntry describes a single tunnel entry port and its reverse id
type TunnelEntry struct {
    EntryPort   int    `json:"entry_port"`
    ID          string `json:"id"`           // UUID used by reverse client
    Tag         string `json:"tag"`          // t1/t2 etc.
    MapPortHint int    `json:"map_port_hint"` // suggested mapping on client
}

// ForwardConfig is optional forward proxy over portal (e.g., local socks → portal:443)
type ForwardConfig struct {
    Enabled    bool   `json:"enabled"`
    Port       int    `json:"port"`
    ID         string `json:"id"`
    ServerName string `json:"serverName"`
    PublicKey  string `json:"publicKey"`
    ShortID    string `json:"shortId"`
    Flow       string `json:"flow"`
}

// ConnectionParams is the portable profile copied from XRPS to XRPC (Base64(JSON))
type ConnectionParams struct {
    Version    int              `json:"version"`
    PortalAddr string           `json:"portal_addr"`
    Handshake  HandshakeConfig  `json:"handshake"`
    Tunnels    []TunnelEntry    `json:"tunnels"`
    Forward    ForwardConfig    `json:"forward"`
    Meta       map[string]any   `json:"meta,omitempty"`
}

// Validate basic invariants for params
func (c *ConnectionParams) Validate() error {
    if c.Version <= 0 {
        return errors.New("version must be > 0")
    }
    if c.PortalAddr == "" {
        return errors.New("portal_addr is required")
    }
    if c.Handshake.Port <= 0 || c.Handshake.ServerName == "" || c.Handshake.PublicKey == "" {
        return errors.New("invalid handshake config")
    }
    if len(c.Tunnels) == 0 {
        return errors.New("at least one tunnel required")
    }
    return nil
}

func (c *ConnectionParams) Clone() (*ConnectionParams, error) {
    b, err := json.Marshal(c)
    if err != nil {
        return nil, err
    }
    var out ConnectionParams
    if err := json.Unmarshal(b, &out); err != nil {
        return nil, err
    }
    return &out, nil
}
