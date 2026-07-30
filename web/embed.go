// Package web embeds the built Vue 3 SPA (produced by `npm run build` into
// dist/) so the Orca binary serves its operator UI with no external assets.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// Dist returns the built SPA filesystem rooted at dist/, or ok=false if the
// app has not been built yet (in which case the API falls back to its built-in
// dashboard).
func Dist() (fs.FS, bool) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}
