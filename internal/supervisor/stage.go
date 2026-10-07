package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Stage validates and probes a candidate while keeping traffic quarantined. The
// caller must stop the old runtime first and durably commit its external policy
// before CommitStaged. Pending intent survives failures and process death.
func (s *Supervisor) Stage(ctx context.Context, data []byte) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.closed || ctx.Err() != nil {
		return s.fail("stage unavailable")
	}
	s.mu.Lock()
	running := s.child != nil
	s.mu.Unlock()
	if running {
		return s.fail("stage requires stopped runtime")
	}
	if len(data) == 0 || len(data) > 4<<20 || s.opts.Semantic(data) != nil {
		return s.fail("candidate semantic validation failed")
	}
	h := sha256.Sum256(data)
	revision := hex.EncodeToString(h[:])
	if s.j.Pending != "" && s.j.Pending != revision {
		return s.fail("pending revision differs")
	}
	path, err := s.revision(revision, data)
	defer s.prune()
	if err != nil || s.validate(ctx, path) != nil {
		return s.fail("candidate core validation failed")
	}
	s.j.Pending = revision
	s.j.External = true
	if s.persist() != nil {
		return s.fail("pending persistence failed")
	}
	if s.quarantine(ctx) != nil {
		return s.fail("quarantine failed")
	}
	if err = s.launchMode(ctx, revision, true, true); err != nil {
		return s.stageFailure("candidate staging failed")
	}
	return nil
}

// VerifyStaged repeats the readiness proof without committing or releasing DNS.
func (s *Supervisor) VerifyStaged(ctx context.Context) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.closed {
		return errors.New("supervisor closed")
	}
	if err := s.verifyStaged(ctx); err != nil {
		return s.stageFailure("staged readiness failed")
	}
	return nil
}

func (s *Supervisor) verifyStaged(ctx context.Context) error {
	s.mu.Lock()
	c := s.child
	staged := s.status.State == "staged" && s.status.Live && !s.status.Ready
	s.mu.Unlock()
	if s.closed || c == nil || !staged || s.j.Pending == "" {
		return errors.New("no staged runtime")
	}
	bounded, cancel := context.WithTimeout(ctx, s.opts.ReadyTimeout)
	defer cancel()
	if s.opts.Hooks.Probe(bounded, s.path(s.j.Pending)) != nil || bounded.Err() != nil {
		return errors.New("staged readiness failed")
	}
	select {
	case <-c.done:
		return errors.New("staged core exited")
	default:
	}
	return nil
}

// CommitStaged must only be called after the caller's durable policy commit.
// Release hooks independently check that external commit before opening traffic.
func (s *Supervisor) CommitStaged(ctx context.Context) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.closed {
		return errors.New("supervisor closed")
	}
	if s.verifyStaged(ctx) != nil {
		return s.stageFailure("staged readiness failed")
	}
	revision := s.j.Pending
	s.j.Active = revision
	s.j.Pending = ""
	s.j.External = false
	known := []string{revision}
	for _, v := range s.j.KnownGood {
		if v != revision && len(known) < s.opts.KeepRevisions {
			known = append(known, v)
		}
	}
	s.j.KnownGood = known
	if s.persist() != nil {
		s.j.Pending = revision
		s.j.External = true
		return s.stageFailure("active persistence failed")
	}
	bounded, cancel := context.WithTimeout(ctx, s.opts.ReadyTimeout)
	defer cancel()
	s.gate.Lock()
	err := s.opts.Hooks.Release(bounded)
	s.gate.Unlock()
	if err != nil || bounded.Err() != nil {
		s.j.Pending = revision
		s.j.External = true
		return s.stageFailure("staged release failed")
	}
	s.mu.Lock()
	c := s.child
	if c == nil {
		s.mu.Unlock()
		s.j.Pending = revision
		s.j.External = true
		return s.stageFailure("staged core exited")
	}
	select {
	case <-c.done:
		s.mu.Unlock()
		s.j.Pending = revision
		s.j.External = true
		return s.stageFailure("staged core exited")
	default:
	}
	s.status.Ready = true
	s.status.State = "ready"
	s.status.LastError = ""
	s.mu.Unlock()
	s.event("ready", revision)
	s.prune()
	return nil
}

func (s *Supervisor) stageFailure(code string) error {
	cleanup, cancel := context.WithTimeout(context.Background(), s.opts.ReadyTimeout)
	defer cancel()
	qerr := s.quarantine(cleanup)
	s.stopChild()
	s.j.PID = 0
	perr := s.persist()
	if qerr != nil || perr != nil {
		return s.fail("staged cleanup failed")
	}
	return s.fail(code)
}
