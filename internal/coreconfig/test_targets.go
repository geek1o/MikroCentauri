package coreconfig

// TestTargetURL resolves a bounded public target; custom operator URLs remain private.
func TestTargetURL(target string) string {
	switch target {
	case "google":
		return "https://www.gstatic.com/generate_204"
	case "cloudflare":
		return "https://cp.cloudflare.com/generate_204"
	case "apple":
		return "https://www.apple.com/library/test/success.html"
	case "mozilla":
		return "https://detectportal.firefox.com/success.txt"
	}
	return ""
}

func (g Group) TestURL() string {
	if target := TestTargetURL(g.TestTarget); target != "" {
		return target
	}
	if g.URL != "" {
		return g.URL
	}
	return TestTargetURL("google")
}
