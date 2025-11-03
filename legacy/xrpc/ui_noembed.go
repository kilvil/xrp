//go:build !ui_embed

package bridge

import "net/http"

// Default build: no embedded UI. Use env XRPC_UI_DIR to serve built assets.
func getEmbeddedUI() http.FileSystem { return nil }
