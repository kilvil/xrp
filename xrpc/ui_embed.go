//go:build ui_embed

package main

import (
    "embed"
    "io/fs"
    "net/http"
)

// Embed static UI assets produced by Vite (xrpc/web/dist)
// Ensure you run the web build before go build:
//   (cd xrpc/web && npm ci && npm run build)
// Then build with: go build -tags ui_embed ./xrpc
//go:embed web/dist
var uiEmbed embed.FS

func getEmbeddedUI() http.FileSystem {
    sub, err := fs.Sub(uiEmbed, "web/dist")
    if err != nil {
        return nil
    }
    return http.FS(sub)
}

