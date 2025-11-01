package shared

import (
    "encoding/base64"
    "encoding/json"
)

// EncodeParamsB64 encodes params JSON as base64url (no padding)
func EncodeParamsB64(p *ConnectionParams) (jsonStr, b64 string, err error) {
    raw, err := json.MarshalIndent(p, "", "  ")
    if err != nil {
        return "", "", err
    }
    enc := base64.RawURLEncoding.EncodeToString(raw)
    return string(raw), enc, nil
}

// DecodeParamsB64 decodes base64url into params
func DecodeParamsB64(b64 string) (*ConnectionParams, error) {
    raw, err := base64.RawURLEncoding.DecodeString(b64)
    if err != nil {
        return nil, err
    }
    var p ConnectionParams
    if err := json.Unmarshal(raw, &p); err != nil {
        return nil, err
    }
    if err := p.Validate(); err != nil {
        return nil, err
    }
    return &p, nil
}

