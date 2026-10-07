package api

import (
	"encoding/json"
	"testing"
)

func TestSystemInfoActualStorageAndExpectedVersionDistinction(t *testing.T) {
	s, _, token := setup(t, nil)
	w := call(s, "GET", "/api/v1/system/info", token, nil)
	raw, _ := json.Marshal(OpenAPI())
	var spec map[string]any
	json.Unmarshal(raw, &spec)
	contractResponse(t, spec, "GET", "/api/v1/system/info", w)
	var info SystemInfo
	json.Unmarshal(w.Body.Bytes(), &info)
	if w.Code != 200 || info.Storage.TotalBytes == 0 || info.Storage.FreeBytes > info.Storage.TotalBytes || info.SingBoxVerified || info.SingBoxObserved != "" || info.SingBoxExpected != "1.14.2" {
		t.Fatal(w.Code, w.Body.String())
	}
}
