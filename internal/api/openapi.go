package api

import (
	"mikrocentauri.local/core/internal/coreconfig"
	"reflect"
	"strings"
)

// OpenAPI is generated from route declarations and the actual model JSON types.
func OpenAPI() map[string]any {
	paths := map[string]any{}
	reads := []string{"system", "routeros", "proxies", "subscriptions", "groups", "rules", "devices", "dns", "diagnostics", "config", "config/draft", "health/live", "health/ready", "logs", "backup", "openapi.json"}
	for _, path := range reads {
		responses := map[string]any{"200": map[string]any{"description": "Redacted resource"}, "401": map[string]any{"description": "Authentication required"}, "503": map[string]any{"description": "Not ready or unavailable"}}
		if path == "routeros" || path == "subscriptions" {
			responses["501"] = map[string]any{"description": "Adapter not connected"}
		}
		op := map[string]any{"operationId": "get_" + strings.ReplaceAll(strings.ReplaceAll(path, "/", "_"), ".", "_"), "responses": responses, "security": []any{map[string]any{"session": []any{}}}}
		if path == "health/live" {
			op["security"] = []any{}
		}
		paths["/api/v1/"+path] = map[string]any{"get": op}
	}
	objects := map[string]any{
		"auth/login":      map[string]any{"type": "object", "required": []string{"password"}, "additionalProperties": false, "properties": map[string]any{"password": map[string]any{"type": "string", "maxLength": 1024}}},
		"auth/logout":     map[string]any{"type": "object"},
		"config/draft":    map[string]any{"$ref": "#/components/schemas/CoreModel"},
		"config/validate": revisionSchema(), "config/plan": revisionSchema(),
		"config/apply":           map[string]any{"type": "object", "required": []string{"plan_id"}, "additionalProperties": false, "properties": map[string]any{"plan_id": map[string]any{"type": "string", "minLength": 64, "maxLength": 64}}},
		"backup/restore-preview": schema(reflect.TypeFor[SafeExport]()),
	}
	for path, body := range objects {
		op := map[string]any{"operationId": "post_" + strings.ReplaceAll(path, "/", "_"), "requestBody": map[string]any{"required": path != "auth/logout", "content": map[string]any{"application/json": map[string]any{"schema": body}}}, "responses": map[string]any{"200": map[string]any{"description": "Operation completed"}, "400": map[string]any{"description": "Invalid request"}, "401": map[string]any{"description": "Authentication required"}, "409": map[string]any{"description": "Stale draft/plan"}, "422": map[string]any{"description": "Validation failed"}, "429": map[string]any{"description": "Login limit"}, "503": map[string]any{"description": "Runtime or persistence unavailable"}}, "security": []any{map[string]any{"session": []any{}}}}
		if path == "auth/login" {
			op["security"] = []any{}
		}
		key := "/api/v1/" + path
		entry, ok := paths[key].(map[string]any)
		if !ok {
			entry = map[string]any{}
			paths[key] = entry
		}
		entry["post"] = op
	}
	return map[string]any{"openapi": "3.1.0", "info": map[string]any{"title": "MikroCentauri API", "version": "0.1.0", "description": "TLS, exact origin, client CIDR policy and expiring opaque bearer sessions. No cookies. Disconnected RouterOS/subscription adapters return 501; standalone apply returns 503."}, "paths": paths, "components": map[string]any{"securitySchemes": map[string]any{"session": map[string]any{"type": "http", "scheme": "bearer"}}, "schemas": map[string]any{"CoreModel": schema(reflect.TypeFor[coreconfig.Model]())}}}
}
func revisionSchema() map[string]any {
	return map[string]any{"type": "object", "required": []string{"draft_revision"}, "additionalProperties": false, "properties": map[string]any{"draft_revision": map[string]any{"type": "integer", "minimum": 1}}}
}
func schema(t reflect.Type) map[string]any {
	if t.Kind() == reflect.Pointer {
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
	case reflect.Slice:
		return map[string]any{"type": []string{"array", "null"}, "items": schema(t.Elem())}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	default:
		return map[string]any{"type": "string"}
	}
}
