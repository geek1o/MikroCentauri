package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"mikrocentauri.local/core/internal/config"
)

// SubscriptionSchedule is a global, serial refresh schedule. It never imports
// refreshed endpoints or changes the applied routing policy.
type SubscriptionSchedule struct {
	IntervalSeconds int64 `json:"interval_seconds"`
	Running         bool  `json:"running"`
}
type SubscriptionScheduleRequest struct {
	IntervalSeconds *int64 `json:"interval_seconds"`
}
type subscriptionScheduleRecord struct {
	Version         int   `json:"version"`
	IntervalSeconds int64 `json:"interval_seconds"`
}

func validSchedule(seconds int64) bool { return seconds == 0 || seconds >= 60 && seconds <= 86400 }

// InitializeSchedule must run before starting the HTTP listener or refresh owner.
// An existing private record takes precedence over the operator startup default.
func (s *SubscriptionResources) InitializeSchedule(interval time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.schedule != nil {
		return nil
	}
	seconds := int64(interval / time.Second)
	if interval%time.Second != 0 || !validSchedule(seconds) {
		return errors.New("invalid subscription schedule")
	}
	raw, e := privateRead(filepath.Join(s.dir, "subscription-schedule.json"), 2048)
	if e == nil {
		var record subscriptionScheduleRecord
		if decode(raw, &record) != nil || record.Version != 1 || !validSchedule(record.IntervalSeconds) {
			return errors.New("invalid durable subscription schedule")
		}
		seconds = record.IntervalSeconds
	} else if !os.IsNotExist(e) {
		return errors.New("subscription schedule unavailable")
	}
	s.schedule = &SubscriptionSchedule{IntervalSeconds: seconds}
	s.scheduleNotify = make(chan struct{}, 1)
	return nil
}
func (s *SubscriptionResources) Schedule() (SubscriptionSchedule, error) {
	if e := s.InitializeSchedule(0); e != nil {
		return SubscriptionSchedule{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.lock == nil {
		return SubscriptionSchedule{}, errors.New("subscription registry unavailable")
	}
	v := *s.schedule
	v.Running = s.running
	return v, nil
}
func (s *SubscriptionResources) SetSchedule(seconds int64) (SubscriptionSchedule, error) {
	if !validSchedule(seconds) {
		return SubscriptionSchedule{}, errors.New("invalid schedule")
	}
	if e := s.InitializeSchedule(0); e != nil {
		return SubscriptionSchedule{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.lock == nil {
		return SubscriptionSchedule{}, errors.New("subscription registry unavailable")
	}
	raw, _ := json.Marshal(subscriptionScheduleRecord{1, seconds})
	if e := config.WriteAtomic(filepath.Join(s.dir, "subscription-schedule.json"), raw); e != nil {
		s.poisoned = true
		return SubscriptionSchedule{}, errors.New("subscription schedule persistence failed")
	}
	s.schedule.IntervalSeconds = seconds
	select {
	case s.scheduleNotify <- struct{}{}:
	default:
	}
	v := *s.schedule
	v.Running = s.running
	return v, nil
}

// RunScheduled owns one refresher even while disabled. Schedule changes reset
// the waiting interval; enabling does not cause an immediate request. Refresh
// is bounded and serial; cancellation interrupts an in-flight provider.
func (s *SubscriptionResources) RunScheduled(ctx context.Context) error {
	if e := s.InitializeSchedule(0); e != nil {
		return e
	}
	s.mu.Lock()
	if s.running || s.poisoned || s.lock == nil {
		s.mu.Unlock()
		return errors.New("subscription refresher unavailable")
	}
	s.running = true
	notify := s.scheduleNotify
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	for {
		schedule, e := s.Schedule()
		if e != nil {
			return e
		}
		var timer *time.Timer
		var tick <-chan time.Time
		if schedule.IntervalSeconds > 0 {
			timer = time.NewTimer(time.Duration(schedule.IntervalSeconds) * time.Second)
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()
		case <-notify:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-tick:
		}
		metadata, e := s.Metadata()
		if e != nil {
			return e
		}
		for _, spec := range metadata {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Stop further providers promptly if disabled between requests.
			current, e := s.Schedule()
			if e != nil {
				return e
			}
			if current.IntervalSeconds == 0 {
				break
			}
			attempt, cancel := context.WithTimeout(ctx, 45*time.Second)
			_, _ = s.Refresh(attempt, spec.ID)
			cancel()
		}
	}
}
func (s *Server) scheduleGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/api/v1/subscriptions/schedule" {
		return false
	}
	if s.opts.Subscriptions == nil {
		reject(w, 501, "adapter_not_connected")
		return true
	}
	v, e := s.opts.Subscriptions.Schedule()
	if e != nil {
		reject(w, 503, "subscriptions_unavailable")
		return true
	}
	reply(w, 200, v)
	return true
}
func (s *Server) schedulePost(w http.ResponseWriter, r *http.Request, raw []byte, id string) bool {
	if r.URL.Path != "/api/v1/subscriptions/schedule" {
		return false
	}
	if s.opts.Subscriptions == nil {
		reject(w, 501, "adapter_not_connected")
		return true
	}
	var in SubscriptionScheduleRequest
	if decode(raw, &in) != nil || in.IntervalSeconds == nil || !validSchedule(*in.IntervalSeconds) {
		reject(w, 400, "invalid_request")
		return true
	}
	v, e := s.opts.Subscriptions.SetSchedule(*in.IntervalSeconds)
	if e != nil {
		reject(w, 503, "subscription_persistence_failed")
		return true
	}
	s.event("subscription_schedule_saved", id)
	reply(w, 200, v)
	return true
}
