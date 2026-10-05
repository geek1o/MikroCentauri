// mc-generation-tool creates deliberate cache-order fixtures via stock DNS only.
// It never opens or edits the engine database. Run only with ingress quarantined.
package main

import (
	"context"
	"encoding/json"
	"log"
	"mikrocentauri.local/core/internal/dnsgate"
	"mikrocentauri.local/core/internal/generation"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("provide ordered fixture domains")
	}
	a, err := dnsgate.NewAllocator("127.0.0.1:5354")
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var bindings []generation.Binding
	for _, domain := range os.Args[1:] {
		alias, err := a.Alias(ctx, domain)
		if err != nil {
			log.Fatal(err)
		}
		bindings = append(bindings, generation.Binding{Domain: domain, Alias: alias})
	}
	_ = json.NewEncoder(os.Stdout).Encode(bindings)
}
