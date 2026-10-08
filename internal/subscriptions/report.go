package subscriptions

import (
	"encoding/base64"
	"errors"
	"mikrocentauri.local/core/internal/endpoints"
	"net/url"
	"strings"
)

type ImportIssue struct {
	Line     int    `json:"line"`
	Protocol string `json:"protocol"`
	Code     string `json:"code"`
}
type ParseReport struct {
	Nodes       []endpoints.Endpoint
	SourceCount int
	Issues      []ImportIssue
}
type ReportingParser interface {
	ParseReport([]byte) (ParseReport, error)
}

// ParseReport retains every supported distinct endpoint and explicitly reports
// unsupported entries. A wholly invalid response still preserves the LKG cache.
func (URIList) ParseReport(data []byte) (ParseReport, error) {
	var report ParseReport
	if len(data) == 0 || len(data) > 4<<20 {
		return report, errors.New("subscription exceeds size limit")
	}
	text := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if !strings.Contains(text, "://") {
		decoded := false
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			b, e := enc.DecodeString(strings.Join(strings.Fields(text), ""))
			if e == nil {
				text = string(b)
				decoded = true
				break
			}
		}
		if !decoded {
			return report, errors.New("unsupported subscription format")
		}
	}
	seen := map[string]bool{}
	for index, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		report.SourceCount++
		if report.SourceCount > 4096 {
			return ParseReport{}, errors.New("subscription node limit")
		}
		node, e := endpoints.ParseURI(line)
		if e != nil {
			protocol := "unknown"
			code := "invalid_or_unsupported_endpoint"
			u, e := url.Parse(line)
			if e == nil {
				switch u.Scheme {
				case "vless", "ss", "trojan", "hysteria2", "hy2", "tuic", "vmess":
					protocol = u.Scheme
				}
				q := u.Query()
				if q.Get("type") == "xhttp" {
					code = "unsupported_transport"
				}
				if q.Get("authority") != "" {
					code = "unsupported_grpc_authority"
				}
				if q.Get("insecure") == "1" || q.Get("allowInsecure") == "1" || q.Get("allow_insecure") == "1" {
					code = "insecure_tls_refused"
				}
			}
			report.Issues = append(report.Issues, ImportIssue{index + 1, protocol, code})
			continue
		}
		if !seen[node.ID] {
			seen[node.ID] = true
			report.Nodes = append(report.Nodes, node)
		}
	}
	if len(report.Nodes) == 0 {
		return report, errors.New("no supported subscription endpoints")
	}
	return report, nil
}
