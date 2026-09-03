// Package staticassets exposes the original Robine brand assets for embedding
// in the Go server binary.
package staticassets

import "embed"

// Files contains the Robine marks and favicon used by the HTTP adapter.
//
//go:embed favicon.ico images/brand/*.png
var Files embed.FS
