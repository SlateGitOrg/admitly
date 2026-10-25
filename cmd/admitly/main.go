// Command admitly is a Kubernetes validating and mutating admission webhook
// with a CEL policy engine and image signature verification.
package main

import (
	"os"

	"github.com/SlateGitOrg/admitly/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
