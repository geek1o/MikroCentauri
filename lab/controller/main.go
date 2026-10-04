// Disposable localhost CHR only. This is not a production activation command.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"mikrocentauri.local/core/internal/platform/routeros"
)

// Fault injection loses a successful PUT reply and blocks all later discovery.
// A second process with a normal transport must recover from the disk journal.
type lostReply struct{ failed bool }

func (t *lostReply) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.failed {
		return nil, errors.New("lab transport disconnected")
	}
	res, err := http.DefaultTransport.RoundTrip(r)
	if err == nil && r.Method == "PUT" && res.StatusCode >= 200 && res.StatusCode < 300 {
		t.failed = true
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return nil, errors.New("lab successful reply lost")
	}
	return res, err
}

func run() error {
	action := flag.String("action", "apply", "apply, cleanup or recover")
	distance := flag.String("distance", "1", "disabled lab route distance")
	journal := flag.String("journal", ".cache/controller-lab", "private journal directory")
	fault := flag.Bool("lose-reply", false, "disconnect after first successful creation")
	flag.Parse()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	// Check the actual destination independently before enabling fault injection.
	r, _ := http.NewRequest("GET", "http://127.0.0.1:18080/rest/system/resource", nil)
	r.SetBasicAuth("mc-lab", "DisposableLabOnly-2026")
	res, err := httpClient.Do(r)
	if err != nil {
		return errors.New("isolated CHR unavailable")
	}
	defer res.Body.Close()
	var resource map[string]string
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&resource) != nil || resource["platform"] != "MikroTik" || len(resource["board-name"]) < 4 || resource["board-name"][:4] != "CHR " {
		return errors.New("disposable CHR required")
	}
	if *fault {
		httpClient.Transport = &lostReply{}
	}
	client, err := routeros.NewLabClient("http://127.0.0.1:18080/rest", "mc-lab", "DisposableLabOnly-2026", httpClient)
	if err != nil {
		return err
	}
	controller, err := routeros.NewLabController(client, *journal)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if *action == "recover" {
		return controller.Recover(ctx)
	}
	if *action != "apply" && *action != "cleanup" {
		return errors.New("unknown lab action")
	}
	current, err := client.Discover(ctx)
	if err != nil {
		return err
	}
	var desired []routeros.Object
	if *action == "apply" {
		desired = []routeros.Object{{Path: "ip/route", Fields: map[string]string{
			"comment": "mikrocentauri:stage2:route:canary", "disabled": "true", "dst-address": "203.0.113.123/32", "gateway": "172.30.0.2", "routing-table": "main", "distance": *distance,
		}}}
	}
	plan, err := routeros.Plan("stage2", current, desired)
	if err != nil {
		return err
	}
	if err = controller.Apply(ctx, plan); err != nil {
		return err
	}
	fmt.Printf("verified lab changes: %d\n", len(plan.Changes))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
