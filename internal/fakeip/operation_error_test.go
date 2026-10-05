//go:build linux || darwin

package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func assertOperation(t *testing.T, err error, operation string, cause error) {
	t.Helper()
	var classified *OperationError
	if !errors.As(err, &classified) || classified.Operation != operation {
		t.Fatalf("missing %s operation: %v", operation, err)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("lost nested cause: %v", err)
	}
}

func TestPublicationErrorsExposeOperationAndPreserveCause(t *testing.T) {
	cause := context.DeadlineExceeded
	for _, operation := range []string{"resolve", "ensure", "verify", "persist"} {
		t.Run(operation, func(t *testing.T) {
			c := fixtureConfig(t, 2)
			r := resolverFunc(fixtureResolver)
			b := backendFuncs{}
			switch operation {
			case "resolve":
				r = func(context.Context, string) ([]netip.Addr, time.Duration, error) { return nil, 0, cause }
			case "ensure":
				b.ensure = func(context.Context, Mapping) error { return cause }
			case "verify":
				b.verify = func(context.Context, Mapping) error { return cause }
			}
			p := publisher(t, c, r, b)
			if operation == "persist" {
				if err := os.Mkdir(filepath.Join(c.Directory, "mappings.json"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err := p.Publish(context.Background(), "one.test")
			nested := error(cause)
			if operation == "persist" {
				nested = nil
			}
			assertOperation(t, err, operation, nested)
			expected := map[string]string{"resolve": "resolve A:", "ensure": "ensure mapping:", "verify": "verify mapping:", "persist": "persist reservation:"}[operation]
			if !strings.HasPrefix(err.Error(), expected) {
				t.Fatal("changed contextual message", err)
			}
		})
	}
}

func TestTargetUpdateAndCommitErrorsExposeOperation(t *testing.T) {
	for _, failAt := range []string{"update", "persist"} {
		t.Run(failAt, func(t *testing.T) {
			c := fixtureConfig(t, 2)
			now := time.Unix(1000, 0)
			c.Now = func() time.Time { return now }
			target := address("10.77.0.20")
			p := publisher(t, c, resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
				return []netip.Addr{target}, 5 * time.Second, nil
			}), backendFuncs{})
			if _, _, err := p.Publish(context.Background(), "one.test"); err != nil {
				t.Fatal(err)
			}
			target = address("10.77.0.21")
			now = now.Add(5 * time.Second)
			p.backend = updateBackend{backendFuncs: backendFuncs{verify: func(context.Context, Mapping) error {
				if failAt == "persist" {
					if err := os.Remove(filepath.Join(c.Directory, "mappings.json")); err != nil {
						return err
					}
					return os.Mkdir(filepath.Join(c.Directory, "mappings.json"), 0700)
				}
				return nil
			}}, update: func(context.Context, Mapping, Mapping) error {
				if failAt == "update" {
					return context.DeadlineExceeded
				}
				return nil
			}}
			_, _, err := p.Publish(context.Background(), "one.test")
			nested := error(nil)
			if failAt == "update" {
				nested = context.DeadlineExceeded
			}
			assertOperation(t, err, failAt, nested)
		})
	}
}
