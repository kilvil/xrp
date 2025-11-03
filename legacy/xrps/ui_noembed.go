//go:build !ui_embed

package portal

import "net/http"

// Default build: no embedded UI. Use env XRPS_UI_DIR to serve built assets.
func getEmbeddedUI() http.FileSystem { return nil }
