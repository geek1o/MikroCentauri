package health

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

const CanaryRemoteIPJSON = "remote_ip_json"
const CanaryCloudflareTrace = "cloudflare_trace"

// ParseCanaryIP extracts only the observed peer address. It never returns the
// response body, which can include unrelated network identifiers.
func ParseCanaryIP(body []byte, format string) (netip.Addr, error) {
	invalid := func() (netip.Addr, error) { return netip.Addr{}, errors.New("canary peer response invalid") }
	if len(body) == 0 || len(body) > 4096 {
		return invalid()
	}
	raw := ""
	switch format {
	case "", CanaryRemoteIPJSON:
		var v struct {
			RemoteIP string `json:"remote_ip"`
		}
		if json.Unmarshal(body, &v) != nil {
			return invalid()
		}
		raw = v.RemoteIP
	case CanaryCloudflareTrace:
		found := false
		for _, line := range strings.Split(string(body), "\n") {
			key, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
			if ok && key == "ip" {
				if found {
					return invalid()
				}
				found = true
				raw = value
			}
		}
	default:
		return invalid()
	}
	ip, e := netip.ParseAddr(raw)
	if e != nil || ip.Zone() != "" || (format == CanaryCloudflareTrace && !ip.IsGlobalUnicast()) {
		return invalid()
	}
	return ip.Unmap(), nil
}
