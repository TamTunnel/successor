// Command success: successor — handover of employee-built agents when
// their builder leaves, with a full audit trail.
package main

import (
	"os"

	"successor/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
