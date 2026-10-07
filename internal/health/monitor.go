package health

import (
	"context"
	"errors"
	"sync"
	"time"
)

type Settings struct {
	Failures  int
	Successes int
	Interval  time.Duration
}
type Snapshot struct {
	Ready                bool   `json:"ready"`
	LocalReady           bool   `json:"local_ready"`
	ConsecutiveFailures  int    `json:"consecutive_failures"`
	ConsecutiveSuccesses int    `json:"consecutive_successes"`
	Samples              uint64 `json:"samples"`
	Error                string `json:"error,omitempty"`
}

// Monitor starts down. It recovers only after consecutive genuine successes.
// Sample calls are serialized; SetLocalReady(false) invalidates in-flight probes.
type Monitor struct {
	mu         sync.Mutex
	sampleMu   sync.Mutex
	checker    Checker
	settings   Settings
	state      Snapshot
	generation uint64
}

func NewMonitor(checker Checker, s Settings) (*Monitor, error) {
	if checker == nil {
		return nil, errors.New("checker required")
	}
	if s.Failures == 0 {
		s.Failures = 2
	}
	if s.Successes == 0 {
		s.Successes = 3
	}
	if s.Interval == 0 {
		s.Interval = time.Second
	}
	if s.Failures < 1 || s.Successes < 1 || s.Interval < 0 {
		return nil, errors.New("invalid health settings")
	}
	return &Monitor{checker: checker, settings: s, state: Snapshot{Error: "local dataplane unavailable"}}, nil
}
func (m *Monitor) Snapshot() Snapshot { m.mu.Lock(); defer m.mu.Unlock(); return m.state }
func (m *Monitor) SetLocalReady(ready bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.LocalReady == ready {
		return
	}
	m.generation++
	m.state.LocalReady = ready
	m.state.Ready = false
	m.state.ConsecutiveFailures = 0
	m.state.ConsecutiveSuccesses = 0
	if ready {
		m.state.Error = "awaiting proxy health samples"
	} else {
		m.state.Error = "local dataplane unavailable"
	}
}
func (m *Monitor) Sample(ctx context.Context) {
	m.sampleMu.Lock()
	defer m.sampleMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	local, generation := m.state.LocalReady, m.generation
	m.mu.Unlock()
	if !local {
		return
	}
	err := m.checker.Check(ctx)
	// Cancellation by the caller is not evidence about the outbound. Probe-owned
	// timeouts, where the caller remains active, are genuine failed samples.
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation != m.generation || !m.state.LocalReady {
		return
	}
	m.state.Samples++
	if err != nil {
		m.state.ConsecutiveSuccesses = 0
		if m.state.ConsecutiveFailures < m.settings.Failures {
			m.state.ConsecutiveFailures++
		}
		m.state.Error = "proxy canary failed"
		if m.state.ConsecutiveFailures >= m.settings.Failures {
			m.state.Ready = false
		}
	} else {
		m.state.ConsecutiveFailures = 0
		if m.state.ConsecutiveSuccesses < m.settings.Successes {
			m.state.ConsecutiveSuccesses++
		}
		if m.state.ConsecutiveSuccesses >= m.settings.Successes {
			m.state.Ready = true
			m.state.Error = ""
		}
	}
}
func (m *Monitor) Run(ctx context.Context) {
	m.Sample(ctx)
	ticker := time.NewTicker(m.settings.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Sample(ctx)
		}
	}
}
