package supervisor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestRollbackRefusesReleaseWhenQuarantineFails(t *testing.T) {
	o := options(t)
	var quarantineCount, releaseCount atomic.Int32
	o.Hooks.Quarantine = func(context.Context) error {
		if quarantineCount.Add(1) >= 3 {
			return errors.New("fixture quarantine unavailable")
		}
		return nil
	}
	o.Hooks.Release = func(context.Context) error { releaseCount.Add(1); return nil }
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if err = s.Apply(context.Background(), []byte(`{"mode":"good"}`)); err != nil {
		t.Fatal(err)
	}
	old := s.Status().Revision
	if err = s.Apply(context.Background(), []byte(`{"mode":"bad-ready"}`)); err == nil {
		t.Fatal("unquarantined rollback accepted")
	}
	if releaseCount.Load() != 1 || s.Status().Ready || s.Status().Live || s.j.Active != old || s.j.Pending == "" {
		t.Fatal("quarantine failure released traffic or lost recoverable journal")
	}
}
