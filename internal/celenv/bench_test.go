package celenv

import (
	"context"
	"fmt"
	"testing"
)

// BenchmarkComprehension documents an upstream cel-go behaviour: with a
// runtime cost limit installed, the cost tracker's value stack makes a
// comprehension over n elements take O(n^2) time (compare ns/op at 1k vs
// 10k). admitly bounds this with the request deadline (evaluation is
// interruptible) and the request size cap; see docs/THREAT_MODEL.md.
func BenchmarkComprehension(b *testing.B) {
	for _, limit := range []uint64{DefaultCostLimit * 1000, 0} {
		for _, n := range []int{1_000, 10_000} {
			name := fmt.Sprintf("costTracking=%v/n=%d", limit != 0, n)
			b.Run(name, func(b *testing.B) {
				e, err := newEnvWithLimit(limit)
				if err != nil {
					b.Fatal(err)
				}
				p, err := e.Compile(`containers.all(c, c >= 0)`, BoolType)
				if err != nil {
					b.Fatal(err)
				}
				act := baseActivation()
				l := make([]any, n)
				for i := range l {
					l[i] = int64(i)
				}
				act[VarContainers] = l
				b.ResetTimer()
				for range b.N {
					if _, err := p.EvalBool(context.Background(), act); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
