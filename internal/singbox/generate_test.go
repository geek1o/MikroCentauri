package singbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"mikrocentauri.local/core/internal/config"
)

func TestGoldenAndRealCheck(t *testing.T) {
	raw, e := os.ReadFile("../../lab/configs/hybrid.json")
	if e != nil {
		t.Fatal(e)
	}
	c, e := config.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"hybrid", "full", "socksify"} {
		t.Run(mode, func(t *testing.T) {
			c.Mode = mode
			b, e := Generate(c)
			if e != nil {
				t.Fatal(e)
			}
			gold := filepath.Join("testdata", mode+".golden.json")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				os.MkdirAll("testdata", 0755)
				if e = os.WriteFile(gold, b, 0644); e != nil {
					t.Fatal(e)
				}
			}
			want, e := os.ReadFile(gold)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(b, want) {
				t.Fatal("configuration changed; review golden diff")
			}
			binary := os.Getenv("SING_BOX_BINARY")
			if binary == "" {
				t.Log("real sing-box check NOT RUN: set SING_BOX_BINARY")
				return
			}
			path := filepath.Join(t.TempDir(), "config.json")
			os.WriteFile(path, b, 0600)
			if e = Check(context.Background(), binary, path); e != nil {
				t.Fatal(e)
			}
		})
	}
}
