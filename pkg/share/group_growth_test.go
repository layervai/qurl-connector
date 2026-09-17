package share

import (
	"context"
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

// Register one added route every 286ms through Run/SetRoutes/Update/Changes.
// Each isolated registration takes 63ms; replacing the resulting group must
// budget that cost for all routes, even though growth never forms a backlog.
func TestSessionGroupRunnerStaggeredGrowthMeasuresIsolatedAdditions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startGroupHarness(t, time.Hour, 0, func(_ int, id string) bool { return id != "seed" }, "seed")
		defer h.cancel()
		synctest.Wait()
		routes := groupTestRoutes("seed")
		session := h.factory.session(1)
		for i := 0; i < 1000; i++ {
			id := fmt.Sprintf("added-%04d", i)
			routes = append(routes, groupTestRoutes(id)[0])
			if err := h.runner.SetRoutes(context.Background(), routes); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			time.Sleep(63 * time.Millisecond)
			session.serve(id)
			synctest.Wait()
			time.Sleep(223 * time.Millisecond)
		}
		h.runner.mu.Lock()
		measured := h.runner.measuredPerRoute
		active := h.runner.active
		h.runner.mu.Unlock()
		lead := active.expiresAt.Sub(h.runner.rotateAt(active))
		t.Logf("1000 staggered additions: measured=%s lead=%s replacement-cost=%s", measured, lead, 1001*63*time.Millisecond)
		if measured != 63*time.Millisecond*3/2 || lead != 1001*measured {
			t.Errorf("first rotation does not use the staggered group's measured replacement cost")
		}
	})
}
