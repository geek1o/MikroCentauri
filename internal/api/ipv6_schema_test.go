package api

import (
	"encoding/json"
	"reflect"
	"testing"

	"mikrocentauri.local/core/internal/platform/routeros"
)

func TestIPv6ForwardingContractDistinguishesUnknownFalseAndTrue(t *testing.T) {
	description := schema(reflect.TypeFor[routeros.IPv6Observation]())
	properties := description["properties"].(map[string]any)
	forwarding := properties["forwarding"].(map[string]any)
	if !reflect.DeepEqual(forwarding["type"], []string{"boolean", "null"}) {
		t.Fatal("unknown forwarding must remain nullable in OpenAPI")
	}
	for _, value := range []*bool{nil, new(false), new(true)} {
		raw, e := json.Marshal(routeros.IPv6Observation{State: "unknown", Forwarding: value})
		if e != nil {
			t.Fatal(e)
		}
		var projected map[string]any
		if e = json.Unmarshal(raw, &projected); e != nil {
			t.Fatal(e)
		}
		expected := any(nil)
		if value != nil {
			expected = *value
		}
		if v, present := projected["forwarding"]; !present || v != expected {
			t.Fatal("forwarding state collapsed")
		}
	}
}
