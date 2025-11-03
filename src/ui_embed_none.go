//go:build !ui_embed

package main

import "net/http"

// Fallback when UI is not embedded.
func getEmbeddedUI() http.FileSystem { return nil }

