//go:build ui_embed

package main

import (
    "embed"
    "io/fs"
    "net/http"
)

// Embed static UI assets produced by Vite (web/dist)
// Ensure you run the web build before go build:
//   (cd web && pnpm i && pnpm build)
// Then build with: go build -tags ui_embed ./src
//go:embed ui
var uiEmbed embed.FS

func getEmbeddedUI() http.FileSystem {
    sub, err := fs.Sub(uiEmbed, "ui")
    if err != nil {
        return nil
    }
    return http.FS(sub)
}
