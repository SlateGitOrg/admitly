package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/archit2501/admitly/internal/bench"
)

func runBench(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("bench", stderr)
	n := fs.Int("requests", 2000, "measured requests per scenario")
	c := fs.Int("concurrency", 8, "concurrent clients")
	warmup := fs.Int("warmup", 200, "unmeasured warm-up requests per scenario")
	jsonOut := fs.String("json", "", "also write the report as JSON to this file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *n <= 0 || *c <= 0 || *warmup < 0 {
		return fmt.Errorf("%w: --requests and --concurrency must be positive", errUsage)
	}
	rep, err := bench.Run(ctx, bench.Options{Requests: *n, Concurrency: *c, Warmup: *warmup})
	if err != nil {
		return err
	}
	rep.Print(stdout)
	if *jsonOut != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*jsonOut, append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}
