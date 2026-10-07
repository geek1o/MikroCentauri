package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"mikrocentauri.local/core/internal/rulesets"
	"os"
	"time"
)

func rulesetCommand(action string, args []string) error {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	state := fs.String("state", "", "private verified rule-set store")
	binary := fs.String("sing-box", "sing-box", "pinned rule-set compiler")
	input := fs.String("file", "", "private local rule-set input")
	specPath := fs.String("config", "", "private remote rule-set specification")
	identifier := fs.String("id", "", "rule-set identifier")
	format := fs.String("format", "source", "source or binary input")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || *state == "" {
		return errors.New("private state directory required and positional arguments refused")
	}
	if action != "ruleset-import" && action != "ruleset-refresh" && action != "ruleset-load" {
		return errors.New("unsupported rule-set command")
	}
	m, e := rulesets.New(*state, *binary, rulesets.Policy{})
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var a rulesets.Artifact
	switch action {
	case "ruleset-load":
		a, e = m.Load(*identifier)
	case "ruleset-import":
		if *input == "" {
			return errors.New("private rule-set file required")
		}
		var b []byte
		b, e = readRouterFile(*input, rulesets.MaxBytes, true)
		if e == nil {
			a, e = m.Import(ctx, *identifier, *format, b)
		}
	case "ruleset-refresh":
		if *specPath == "" {
			return errors.New("private rule-set specification required")
		}
		var s rulesets.Spec
		e = privateJSON(*specPath, &s, 64<<10)
		if e == nil {
			a, e = m.Refresh(ctx, s)
		}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(a)
}
