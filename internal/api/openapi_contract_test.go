package api

import (
	"encoding/json"
	"fmt"
	"math"
	"mikrocentauri.local/core/internal/coreconfig"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Validate the supported JSON Schema vocabulary against real HTTP responses.
// This catches a drift in field names, null handling and response projections
// that a regenerated OpenAPI snapshot alone cannot detect.
func contractValue(t *testing.T, root map[string]any, s map[string]any, value any, path string) {
	t.Helper()
	if e := contractError(root, s, value, path); e != nil {
		t.Fatal(e)
	}
}
func contractError(root map[string]any, s map[string]any, value any, path string) error {
	if alternatives, ok := s["oneOf"].([]any); ok {
		matches := 0
		for _, candidate := range alternatives {
			if contractError(root, candidate.(map[string]any), value, path) == nil {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("%s matches %d oneOf alternatives", path, matches)
		}
		return nil
	}
	if ref, ok := s["$ref"].(string); ok {
		v := any(root)
		for _, key := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			v = v.(map[string]any)[key]
		}
		return contractError(root, v.(map[string]any), value, path)
	}
	if expected, ok := s["const"]; ok && fmt.Sprint(expected) != fmt.Sprint(value) {
		return fmt.Errorf("%s const mismatch", path)
	}
	var types []string
	switch v := s["type"].(type) {
	case string:
		types = []string{v}
	case []any:
		for _, x := range v {
			types = append(types, x.(string))
		}
	}
	if len(types) == 0 {
		return nil
	}
	kind := ""
	switch v := value.(type) {
	case nil:
		kind = "null"
	case bool:
		kind = "boolean"
	case string:
		kind = "string"
	case float64:
		kind = "number"
		if math.Trunc(v) == v {
			kind = "integer"
		}
	case []any:
		kind = "array"
	case map[string]any:
		kind = "object"
	}
	match := false
	for _, v := range types {
		if v == kind || v == "number" && kind == "integer" {
			match = true
		}
	}
	if !match {
		return fmt.Errorf("%s expected %v got %s", path, types, kind)
	}
	if kind == "object" {
		object := value.(map[string]any)
		properties, _ := s["properties"].(map[string]any)
		if required, ok := s["required"].([]any); ok {
			for _, key := range required {
				if _, ok := object[key.(string)]; !ok {
					return fmt.Errorf("%s missing %s", path, key)
				}
			}
		}
		for key, v := range object {
			if property, ok := properties[key].(map[string]any); ok {
				if e := contractError(root, property, v, path+"."+key); e != nil {
					return e
				}
				continue
			}
			if extra, ok := s["additionalProperties"].(bool); ok && !extra {
				return fmt.Errorf("%s unexpected %s", path, key)
			}
			if extra, ok := s["additionalProperties"].(map[string]any); ok {
				if e := contractError(root, extra, v, path+"."+key); e != nil {
					return e
				}
			}
		}
	}
	if kind == "array" {
		if items, ok := s["items"].(map[string]any); ok {
			for i, v := range value.([]any) {
				if e := contractError(root, items, v, fmt.Sprintf("%s[%d]", path, i)); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func contractResponse(t *testing.T, spec map[string]any, method, path string, w *httptest.ResponseRecorder) {
	t.Helper()
	op := spec["paths"].(map[string]any)[path].(map[string]any)[strings.ToLower(method)].(map[string]any)
	response, ok := op["responses"].(map[string]any)[strconv.Itoa(w.Code)].(map[string]any)
	if !ok {
		t.Fatalf("undocumented status %d for %s", w.Code, path)
	}
	bodySchema := response["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	var value any
	if json.Unmarshal(w.Body.Bytes(), &value) != nil {
		t.Fatalf("non-JSON response: %s", w.Body.String())
	}
	contractValue(t, spec, bodySchema, value, path)
}
func TestOpenAPIRealResourceAndWorkflowResponseContracts(t *testing.T) {
	encoded, _ := json.Marshal(OpenAPI())
	var spec map[string]any
	json.Unmarshal(encoded, &spec)
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Ready: true}}
	s, _, token := setup(t, runtime)
	registry, _, node := workflowRegistry(t)
	s.opts.Subscriptions = registry
	for _, path := range []string{"system", "routeros", "subscriptions", "proxies", "groups", "rules", "devices", "dns", "diagnostics", "config", "health/live", "health/ready", "logs", "backup", "preferences", "openapi.json"} {
		url := "/api/v1/" + path
		contractResponse(t, spec, "GET", url, call(s, "GET", url, token, nil))
	}
	w := call(s, "POST", "/api/v1/config/draft", token, fixture(t))
	contractResponse(t, spec, "POST", "/api/v1/config/draft", w)
	contractResponse(t, spec, "GET", "/api/v1/config/draft", call(s, "GET", "/api/v1/config/draft", token, nil))
	for _, path := range []string{"config/validate", "config/plan"} {
		contractResponse(t, spec, "POST", "/api/v1/"+path, call(s, "POST", "/api/v1/"+path, token, map[string]any{"draft_revision": s.draft.Sequence}))
	}
	for _, path := range []string{"subscriptions/inspect", "subscriptions/refresh"} {
		input := map[string]any{"id": "provider"}
		if path == "subscriptions/inspect" {
			input["offset"] = 0
			input["limit"] = 1
		}
		contractResponse(t, spec, "POST", "/api/v1/"+path, call(s, "POST", "/api/v1/"+path, token, input))
	}
	importResult := call(s, "POST", "/api/v1/subscriptions/import", token, SubscriptionImportRequest{ID: "provider", NodeIDs: []string{node.ID}, DraftRevision: s.draft.Sequence})
	contractResponse(t, spec, "POST", "/api/v1/subscriptions/import", importResult)
	for _, path := range []string{"backup/restore-preview", "backup/restore-draft"} {
		result := call(s, "POST", "/api/v1/"+path, token, Export(runtime.m))
		contractResponse(t, spec, "POST", "/api/v1/"+path, result)
	}
	contractResponse(t, spec, "POST", "/api/v1/preferences", call(s, "POST", "/api/v1/preferences", token, Preferences{Language: "en", Theme: "dark", TimeZone: "Europe/Moscow"}))

	deleteResult := call(s, "POST", "/api/v1/subscriptions/delete", token, SubscriptionDeleteRequest{ID: "provider"})
	contractResponse(t, spec, "POST", "/api/v1/subscriptions/delete", deleteResult)
}
func TestOpenAPIAllOperationsDescribeTypedResponsesAndUniqueIDs(t *testing.T) {
	paths := OpenAPI()["paths"].(map[string]any)
	seen := map[string]bool{}
	for path, entry := range paths {
		for method, raw := range entry.(map[string]any) {
			op := raw.(map[string]any)
			id := op["operationId"].(string)
			if seen[id] {
				t.Fatalf("duplicate operation ID %s", id)
			}
			seen[id] = true
			for status, rawResponse := range op["responses"].(map[string]any) {
				response := rawResponse.(map[string]any)
				content, ok := response["content"].(map[string]any)
				if !ok || len(content) == 0 {
					t.Fatalf("untyped %s %s %s", method, path, status)
				}
				for _, media := range content {
					if _, ok := media.(map[string]any)["schema"].(map[string]any); !ok {
						t.Fatalf("missing schema %s", path)
					}
				}
			}
		}
	}
}

func TestOpenAPIErrorAndQueryDenialContracts(t *testing.T) {
	encoded, _ := json.Marshal(OpenAPI())
	var spec map[string]any
	json.Unmarshal(encoded, &spec)
	s, _, token := setup(t, nil)
	contractResponse(t, spec, "GET", "/api/v1/config", call(s, "GET", "/api/v1/config", "", nil))
	query := call(s, "GET", "/api/v1/config?access_token="+token, token, nil)
	if query.Code != 403 {
		t.Fatal("query credentials accepted")
	}
	contractResponse(t, spec, "GET", "/api/v1/config", query)
	contractResponse(t, spec, "GET", "/api/v1/config/draft", call(s, "GET", "/api/v1/config/draft", token, nil))
	invalidMethod := call(s, "DELETE", "/api/v1/config", token, nil)
	if invalidMethod.Code != 405 {
		t.Fatal("unsupported method accepted")
	}
	contractResponse(t, spec, "GET", "/api/v1/config", invalidMethod)
}

func TestOpenAPIBusyResponsesMatchUnionContracts(t *testing.T) {
	encoded, _ := json.Marshal(OpenAPI())
	var spec map[string]any
	json.Unmarshal(encoded, &spec)
	s, _, token := setup(t, nil)
	for i := 0; i < cap(s.slots); i++ {
		s.slots <- struct{}{}
	}
	for _, methodPath := range []struct{ method, path string }{{"GET", "/api/v1/health/ready"}, {"POST", "/api/v1/subscriptions/refresh"}} {
		response := call(s, methodPath.method, methodPath.path, token, map[string]any{"id": "provider"})
		if response.Code != 503 || !strings.Contains(response.Body.String(), "busy") {
			t.Fatal(response.Code, response.Body.String())
		}
		contractResponse(t, spec, methodPath.method, methodPath.path, response)
	}
	// The union must reject a payload that mixes its distinct alternatives.
	union := map[string]any{"oneOf": []any{objectSchema(map[string]any{"ready": boolSchema()}), errorSchema()}}
	raw, _ := json.Marshal(union)
	var normalized map[string]any
	json.Unmarshal(raw, &normalized)
	if contractError(spec, normalized, map[string]any{"error": "busy", "ready": false}, "ambiguous") == nil {
		t.Fatal("union validation accepted mixed response")
	}
}

func TestOpenAPIPublicPolicyAndProxyImportHTTPContracts(t *testing.T) {
	encoded, _ := json.Marshal(OpenAPI())
	var spec map[string]any
	json.Unmarshal(encoded, &spec)
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Ready: true}}
	s, _, token := setup(t, runtime)
	projection := call(s, "GET", "/api/v1/config", token, nil)
	var source struct {
		Model  coreconfig.ModelPreview `json:"model"`
		Policy PolicyPreview           `json:"policy"`
	}
	if json.Unmarshal(projection.Body.Bytes(), &source) != nil {
		t.Fatal("GET projection")
	}
	input := DraftPolicyRequest{Mode: source.Model.Mode, Groups: source.Model.Groups, Policy: source.Policy}
	response := call(s, "POST", "/api/v1/config/draft/policy", token, input)
	if response.Code != 200 || runtime.calls != 0 || runtime.checks != 0 {
		t.Fatal("public policy workflow unavailable or mutated network", response.Code, response.Body.String())
	}
	contractResponse(t, spec, "POST", "/api/v1/config/draft/policy", response)
	proxyRequest := ProxyImportRequest{DraftRevision: s.draft.Sequence, URIs: []string{"trojan://private-http-import-secret@example.org:443#imported"}}
	response = call(s, "POST", "/api/v1/proxies/import", token, proxyRequest)
	if response.Code != 200 || runtime.calls != 0 || strings.Contains(response.Body.String(), "private-http-import-secret") {
		t.Fatal(response.Code, response.Body.String())
	}
	contractResponse(t, spec, "POST", "/api/v1/proxies/import", response)
	stale := call(s, "POST", "/api/v1/config/draft/policy", token, input)
	if stale.Code != 409 {
		t.Fatal("stale public policy accepted")
	}
	contractResponse(t, spec, "POST", "/api/v1/config/draft/policy", stale)
}
