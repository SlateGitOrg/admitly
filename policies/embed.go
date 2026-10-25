// Package policies embeds admitly's built-in policy library.
package policies

import (
	"embed"
	"io/fs"
)

//go:embed builtin/*.yaml
var builtin embed.FS

// Builtin returns the built-in policy files as an fs.FS rooted at the
// directory that contains them.
func Builtin() fs.FS {
	sub, err := fs.Sub(builtin, "builtin")
	if err != nil {
		// fs.Sub only fails for an invalid path, which is a compile-time constant here.
		panic(err)
	}
	return sub
}
