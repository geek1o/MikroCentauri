package api

import (
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/subscriptions"
	"mikrocentauri.local/core/internal/trafficlists"
	"reflect"
	"sort"
	"strings"
	"time"
)

// OpenAPI is generated from actual request/model types and explicit resource
// projections. Every JSON response has a schema; credentials appear only in
// write request schemas, never in resource response schemas.
func OpenAPI() map[string]any {
	paths := map[string]any{}
	reads := map[string]map[string]any{
		"engine":                 schema(reflect.TypeFor[EngineState]()),
		"traffic-lists/catalog":  schema(reflect.TypeFor[[]trafficlists.CatalogEntry]()),
		"traffic-lists":          schema(reflect.TypeFor[[]trafficlists.View]()),
		"system":                 objectSchema(map[string]any{"api_version": stringSchema(), "core_schema": integerSchema(), "runtime_connected": boolSchema(), "status": schema(reflect.TypeFor[RuntimeView]()), "ipv6_fakeip": boolSchema(), "engine_connected": boolSchema(), "runtime_simulated": boolSchema(), "subscriptions_simulated": boolSchema()}),
		"routeros":               schema(reflect.TypeFor[RouterSnapshot]()),
		"routeros/network":       schema(reflect.TypeFor[routeros.Network]()),
		"system/info":            schema(reflect.TypeFor[SystemInfo]()),
		"subscriptions/schedule": objectSchema(map[string]any{"interval_seconds": integerSchema(), "running": boolSchema()}),
		"subscriptions":          schema(reflect.TypeFor[[]SubscriptionView]()),
		"proxies":                objectSchema(map[string]any{"endpoints": schema(reflect.TypeFor[coreconfig.ModelPreview]())["properties"].(map[string]any)["endpoints"], "wireguard": schema(reflect.TypeFor[coreconfig.ModelPreview]())["properties"].(map[string]any)["wireguard"]}),
		"groups":                 schema(reflect.TypeFor[[]coreconfig.Group]()),
		"rules":                  objectSchema(map[string]any{"rules": schema(reflect.TypeFor[[]coreconfig.Rule]()), "services": schema(reflect.TypeFor[[]coreconfig.Service]())}),
		"devices":                objectSchema(map[string]any{"source_direct": schema(reflect.TypeFor[[]string]()), "source_proxy": schema(reflect.TypeFor[[]coreconfig.SourcePolicy]())}),
		"dns":                    objectSchema(map[string]any{"bootstrap": stringSchema(), "fakeip_range": stringSchema(), "selected_domains": schema(reflect.TypeFor[[]string]()), "ipv6_fakeip": boolSchema()}),
		"diagnostics":            objectSchema(map[string]any{"status": schema(reflect.TypeFor[RuntimeView]()), "model": schema(reflect.TypeFor[coreconfig.ModelPreview]()), "events": schema(reflect.TypeFor[[]Event]()), "runtime_connected": boolSchema()}),
		"config":                 objectSchema(map[string]any{"revision": integerSchema(), "model": schema(reflect.TypeFor[coreconfig.ModelPreview]()), "policy": schema(reflect.TypeFor[PolicyPreview]())}),
		"config/draft":           objectSchema(map[string]any{"draft_revision": integerSchema(), "base_revision": integerSchema(), "model": schema(reflect.TypeFor[coreconfig.ModelPreview]()), "policy": schema(reflect.TypeFor[PolicyPreview]())}),
		"health/live":            objectSchema(map[string]any{"live": boolSchema()}),
		"health/ready":           objectSchema(map[string]any{"ready": boolSchema()}),
		"logs":                   schema(reflect.TypeFor[[]Event]()),
		"backup":                 schema(reflect.TypeFor[SafeExport]()),
		"preferences":            schema(reflect.TypeFor[Preferences]()),
		"openapi.json":           {"type": "object", "additionalProperties": true},
	}
	for path, body := range reads {
		responses := errorResponses()
		responses["200"] = jsonResponse("Redacted resource", body)
		if path == "health/ready" {
			responses["503"] = jsonResponse("Not ready or unavailable", map[string]any{"oneOf": []any{body, errorSchema()}})
		}
		if path == "routeros" || path == "routeros/network" || (path == "subscriptions" || path == "subscriptions/schedule") {
			responses["501"] = jsonResponse("Adapter not connected", errorSchema())
		}
		paths["/api/v1/"+path] = map[string]any{"get": operation("get", path, responses)}
	}
	responses := errorResponses()
	responses["200"] = map[string]any{"description": "Redacted fixed-name diagnostics archive", "content": map[string]any{"application/gzip": map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}}}
	paths["/api/v1/diagnostics/bundle"] = map[string]any{"get": operation("get", "diagnostics/bundle", responses)}
	objects := map[string]map[string]any{
		"sections/save":          schema(reflect.TypeFor[SectionsRequest]()),
		"traffic-lists/import":   schema(reflect.TypeFor[TrafficListRequest]()),
		"proxies/probe":          schema(reflect.TypeFor[NodeProbeRequest]()),
		"engine/select":          schema(reflect.TypeFor[EngineSelectRequest]()),
		"engine/delay":           schema(reflect.TypeFor[EngineDelayRequest]()),
		"auth/login":             objectSchema(map[string]any{"password": map[string]any{"type": "string", "maxLength": 1024}}),
		"auth/logout":            {"type": "object", "additionalProperties": false},
		"system/recover":         {"type": "object", "additionalProperties": false},
		"subscriptions":          schema(reflect.TypeFor[subscriptions.Spec]()),
		"subscriptions/inspect":  objectSchema(map[string]any{"id": subscriptionIDSchema(), "offset": map[string]any{"type": "integer", "minimum": 0}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 128}}),
		"subscriptions/refresh":  objectSchema(map[string]any{"id": subscriptionIDSchema()}),
		"subscriptions/delete":   schema(reflect.TypeFor[SubscriptionDeleteRequest]()),
		"subscriptions/schedule": objectSchema(map[string]any{"interval_seconds": integerSchema()}),
		"subscriptions/import":   schema(reflect.TypeFor[SubscriptionImportRequest]()),
		"config/draft":           {"$ref": "#/components/schemas/CoreModel"},
		"config/draft/policy":    schema(reflect.TypeFor[DraftPolicyRequest]()),
		"proxies/import":         schema(reflect.TypeFor[ProxyImportRequest]()),
		"proxies/update":         schema(reflect.TypeFor[ProxyUpdateRequest]()),
		"proxies/delete":         schema(reflect.TypeFor[ProxyDeleteRequest]()),
		"diagnostics/run":        schema(reflect.TypeFor[DiagnosticRequest]()),
		"config/validate":        revisionSchema(), "config/plan": revisionSchema(),
		"config/apply":           objectSchema(map[string]any{"plan_id": map[string]any{"type": "string", "minLength": 64, "maxLength": 64}}),
		"backup/restore-preview": schema(reflect.TypeFor[SafeExport]()),
		"backup/restore-draft":   schema(reflect.TypeFor[SafeExport]()),
		"preferences":            schema(reflect.TypeFor[Preferences]()),
	}
	revisionResponse := objectSchema(map[string]any{"draft_revision": integerSchema(), "base_revision": integerSchema()})
	resultSchemas := map[string]map[string]any{
		"sections/save":          schema(reflect.TypeFor[DraftPolicyResult]()),
		"traffic-lists/import":   schema(reflect.TypeFor[TrafficListResult]()),
		"proxies/probe":          schema(reflect.TypeFor[NodeProbeResult]()),
		"engine/select":          schema(reflect.TypeFor[EngineState]()),
		"engine/delay":           schema(reflect.TypeFor[EngineDelayResult]()),
		"subscriptions/schedule": objectSchema(map[string]any{"interval_seconds": integerSchema(), "running": boolSchema()}),
		"auth/login":             objectSchema(map[string]any{"access_token": map[string]any{"type": "string", "minLength": 64, "maxLength": 64}, "token_type": map[string]any{"const": "Bearer"}, "expires_in": map[string]any{"const": 1800}}),
		"auth/logout":            objectSchema(map[string]any{"logged_out": boolSchema()}),
		"system/recover":         schema(reflect.TypeFor[RuntimeView]()),
		"subscriptions":          objectSchema(map[string]any{"id": subscriptionIDSchema()}),
		"subscriptions/delete":   objectSchema(map[string]any{"id": subscriptionIDSchema()}),
		"subscriptions/inspect":  schema(reflect.TypeFor[SubscriptionView]()),
		"subscriptions/refresh":  schema(reflect.TypeFor[SubscriptionView]()),
		"subscriptions/import":   schema(reflect.TypeFor[SubscriptionImportResult]()),
		"config/draft":           revisionResponse,
		"config/draft/policy":    schema(reflect.TypeFor[DraftPolicyResult]()),
		"proxies/import":         schema(reflect.TypeFor[SubscriptionImportResult]()),
		"proxies/update":         schema(reflect.TypeFor[ProxyChangeResult]()),
		"proxies/delete":         schema(reflect.TypeFor[ProxyChangeResult]()),
		"diagnostics/run":        schema(reflect.TypeFor[DiagnosticResult]()),
		"config/validate":        objectSchema(map[string]any{"valid": boolSchema()}),
		"config/plan":            objectSchema(map[string]any{"plan_id": stringSchema(), "draft_revision": integerSchema(), "base_revision": integerSchema(), "expires_at": schema(reflect.TypeFor[time.Time]()), "model": schema(reflect.TypeFor[coreconfig.ModelPreview]()), "policy": schema(reflect.TypeFor[PolicyPreview]()), "apply_available": boolSchema(), "changed_sections": schema(reflect.TypeFor[[]string]())}),
		"config/apply":           schema(reflect.TypeFor[RuntimeView]()),
		"backup/restore-preview": schema(reflect.TypeFor[RestorePreview]()),
		"backup/restore-draft":   schema(reflect.TypeFor[RestorePreview]()),
		"preferences":            schema(reflect.TypeFor[Preferences]()),
	}
	objects["config/draft/policy"]["properties"].(map[string]any)["groups"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["url"] = map[string]any{"type": "string", "const": ""}
	objects["config/draft/policy"]["properties"].(map[string]any)["mode"] = map[string]any{"type": "string", "enum": []string{"hybrid", "full", "socksify"}}
	for _, path := range []string{"config/draft/policy", "proxies/import"} {
		objects[path]["properties"].(map[string]any)["draft_revision"] = integerSchema()
	}
	objects["proxies/probe"]["properties"].(map[string]any)["id"] = map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$", "minLength": 64, "maxLength": 64}
	objects["subscriptions/schedule"]["properties"].(map[string]any)["interval_seconds"] = map[string]any{"oneOf": []any{map[string]any{"type": "integer", "const": 0}, map[string]any{"type": "integer", "minimum": 60, "maximum": 86400}}}
	objects["proxies/update"]["properties"].(map[string]any)["uri"] = map[string]any{"type": "string", "maxLength": 16384, "writeOnly": true}
	objects["diagnostics/run"]["properties"].(map[string]any)["kind"] = map[string]any{"type": "string", "enum": []string{"routeros", "core", "dns", "direct", "proxy", "routing", "watchdog"}}
	objects["proxies/import"]["properties"].(map[string]any)["uris"] = map[string]any{"type": "array", "minItems": 1, "maxItems": 128, "items": map[string]any{"type": "string", "maxLength": 16384, "writeOnly": true}}
	objects["subscriptions/import"]["properties"].(map[string]any)["node_ids"] = map[string]any{"type": "array", "minItems": 1, "maxItems": 128, "uniqueItems": true, "items": stringSchema()}
	for _, path := range []string{"subscriptions", "subscriptions/delete", "subscriptions/import"} {
		objects[path]["properties"].(map[string]any)["id"] = subscriptionIDSchema()
	}
	for path, body := range objects {
		responses := errorResponses()
		responses["200"] = jsonResponse("Operation completed", resultSchemas[path])
		if strings.HasPrefix(path, "subscriptions") || path == "diagnostics/run" {
			responses["501"] = jsonResponse("Adapter not connected", errorSchema())
		}
		if path == "subscriptions/refresh" {
			responses["503"] = jsonResponse("Refresh failed; cached last-known-good nodes retained", map[string]any{"oneOf": []any{errorSchema(), objectSchema(map[string]any{"error": stringSchema(), "subscription": schema(reflect.TypeFor[SubscriptionView]())})}})
		}
		op := operation("post", path, responses)
		op["requestBody"] = map[string]any{"required": path != "auth/logout", "content": map[string]any{"application/json": map[string]any{"schema": body}}}
		if path == "auth/logout" {
			delete(op, "requestBody")
			op["description"] = "Invalidates the bearer session. A request body, if supplied, is ignored."
		}
		key := "/api/v1/" + path
		entry, ok := paths[key].(map[string]any)
		if !ok {
			entry = map[string]any{}
			paths[key] = entry
		}
		entry["post"] = op
	}
	return map[string]any{"openapi": "3.1.0", "info": map[string]any{"title": "MikroCentauri API", "version": "0.1.0", "description": "TLS, exact origin, client CIDR policy and expiring opaque bearer sessions. No cookies. Draft writes do not apply network changes; only one-use reviewed plans can apply. Safe restores require matching local credentials."}, "paths": paths, "components": map[string]any{"securitySchemes": map[string]any{"session": map[string]any{"type": "http", "scheme": "bearer"}}, "schemas": map[string]any{"CoreModel": schema(reflect.TypeFor[coreconfig.Model]())}}}
}
func operation(method, path string, responses map[string]any) map[string]any {
	op := map[string]any{"operationId": method + "_" + strings.ReplaceAll(strings.ReplaceAll(path, "/", "_"), ".", "_"), "responses": responses, "security": []any{map[string]any{"session": []any{}}}}
	if path == "health/live" || path == "auth/login" {
		op["security"] = []any{}
	}
	return op
}
func errorResponses() map[string]any {
	responses := map[string]any{}
	for code, description := range map[string]string{"400": "Invalid request", "401": "Authentication required", "403": "Client/origin denied", "404": "Resource absent", "405": "Method not allowed", "409": "Stale draft/plan", "422": "Validation failed", "429": "Capacity or login limit", "503": "Runtime or persistence unavailable"} {
		responses[code] = jsonResponse(description, errorSchema())
	}
	return responses
}
func jsonResponse(description string, body map[string]any) map[string]any {
	return map[string]any{"description": description, "content": map[string]any{"application/json": map[string]any{"schema": body}}}
}
func objectSchema(properties map[string]any) map[string]any {
	required := make([]string, 0, len(properties))
	for key := range properties {
		required = append(required, key)
	}
	sort.Strings(required)
	return map[string]any{"type": "object", "required": required, "additionalProperties": false, "properties": properties}
}
func errorSchema() map[string]any   { return objectSchema(map[string]any{"error": stringSchema()}) }
func boolSchema() map[string]any    { return map[string]any{"type": "boolean"} }
func stringSchema() map[string]any  { return map[string]any{"type": "string"} }
func integerSchema() map[string]any { return map[string]any{"type": "integer", "minimum": 0} }
func subscriptionIDSchema() map[string]any {
	return map[string]any{"type": "string", "pattern": "^[a-zA-Z0-9_-]{1,64}$"}
}
func revisionSchema() map[string]any {
	return map[string]any{"type": "object", "required": []string{"draft_revision"}, "additionalProperties": false, "properties": map[string]any{"draft_revision": map[string]any{"type": "integer", "minimum": 1}}}
}
func schema(t reflect.Type) map[string]any {
	if t == reflect.TypeFor[time.Time]() {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	if t.Kind() == reflect.Pointer {
		if t.Elem().Kind() == reflect.Bool {
			return map[string]any{"type": []string{"boolean", "null"}}
		}
		return schema(t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		p := map[string]any{}
		required := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			name := tag[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			p[name] = schema(f.Type)
			if len(tag) == 1 {
				required = append(required, name)
			}
		}
		return map[string]any{"type": "object", "properties": p, "required": required, "additionalProperties": false}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schema(t.Elem())}
	case reflect.Slice:
		return map[string]any{"type": []string{"array", "null"}, "items": schema(t.Elem())}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	default:
		return map[string]any{"type": "string"}
	}
}
