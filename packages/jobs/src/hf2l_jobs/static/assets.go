// Package dashboard embeds the same browser assets used by the Python manager.
package dashboard

import "embed"

// Files contains the packaged job manager UI.
//
//go:embed index.html styles.css app.js
var Files embed.FS
