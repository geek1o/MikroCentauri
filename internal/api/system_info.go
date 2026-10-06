package api

import (
	"context"
	"mikrocentauri.local/core/internal/singbox"
	"net/http"
	"runtime/debug"
	"strings"
	"syscall"
)

type SystemInfoRuntime interface {
	SingBoxVersion(context.Context) (string, error)
}
type StorageInfo struct {
	TotalBytes     uint64 `json:"total_bytes"`
	FreeBytes      uint64 `json:"free_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}
type SystemInfo struct {
	AppVersion      string      `json:"app_version"`
	BuildRevision   string      `json:"build_revision"`
	SingBoxExpected string      `json:"sing_box_expected"`
	SingBoxObserved string      `json:"sing_box_observed"`
	SingBoxVerified bool        `json:"sing_box_verified"`
	Storage         StorageInfo `json:"storage"`
}

func (s *Server) systemInfoGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/api/v1/system/info" {
		return false
	}
	info := SystemInfo{AppVersion: "0.5.0-dev", SingBoxExpected: singbox.Version}
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			if setting.Key == "vcs.revision" && len(setting.Value) <= 64 && strings.Trim(setting.Value, "0123456789abcdef") == "" {
				info.BuildRevision = setting.Value
			}
		}
	}
	if owner, ok := s.opts.Runtime.(SystemInfoRuntime); ok {
		if v, e := owner.SingBoxVersion(r.Context()); e == nil {
			info.SingBoxObserved = v
			info.SingBoxVerified = v == singbox.Version
		}
	}
	var stat syscall.Statfs_t
	if syscall.Statfs(s.opts.Directory, &stat) != nil {
		reject(w, 503, "storage_unavailable")
		return true
	}
	info.Storage = StorageInfo{uint64(stat.Bsize) * stat.Blocks, uint64(stat.Bsize) * stat.Bfree, uint64(stat.Bsize) * stat.Bavail}
	reply(w, 200, info)
	return true
}
