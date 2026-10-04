package platform

import "context"

// Adapter separates product orchestration from RouterOS calls. Live activation is gated by lab proof.
type Adapter interface {
	Discover(context.Context) (State, error)
	Plan(State, State) (Plan, error)
	Apply(context.Context, Plan) error
	Rollback(context.Context) error
	Reconcile(context.Context, State) error
	Health(context.Context) error
	Cleanup(context.Context, bool) (Plan, error)
}
type State struct {
	Revision string
	Objects  []Object
}
type Object struct {
	Key    string
	Fields map[string]string
}
type Plan struct{ Changes []Change }
type Change struct {
	Action        string
	Before, After *Object
}
