package application

import (
	"context"
	"net/url"
	"time"

	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/grouphealth"
	"mikrocentauri.local/core/internal/subscriptions"
)

// SubscriptionProxy composes an isolated endpoint child and the downloader's
// validated-literal CONNECT dialer. It has no RouterOS or native runtime owner.
func SubscriptionProxy(binary, directory string) func(context.Context, endpoints.Endpoint, string, func(context.Context, subscriptions.DialContext) error) error {
	return func(ctx context.Context, ep endpoints.Endpoint, bootstrap string, operation func(context.Context, subscriptions.DialContext) error) error {
		p, err := grouphealth.NewProber(grouphealth.ProbeOptions{Binary: binary, Directory: directory, Bootstrap: bootstrap, Timeout: 30 * time.Second, Concurrency: 1})
		if err != nil {
			return err
		}
		return p.WithEndpointProxy(ctx, ep, func(ctx context.Context, proxy *url.URL) error {
			dial, err := subscriptions.HTTPProxyDialer(proxy)
			if err != nil {
				return err
			}
			return operation(ctx, dial)
		})
	}
}
