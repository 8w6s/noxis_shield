package policy

import (
	"fmt"
	"log"

	"github.com/8w6s/noxis/internal/utils"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/valyala/fasthttp"
)

// Env represents the environment available to the expression engine
type Env struct {
	Req *RequestEnv
	IP  string
}

// RequestEnv holds request-specific properties for evaluation
type RequestEnv struct {
	Path   string
	Method string
	Host   string
	UA     string
}

// CompiledRule wraps a parseable Rule with its compiled expr Program
type CompiledRule struct {
	Rule Rule
	Prog *vm.Program
}

// Engine evaluates incoming requests against a set of rules
type Engine struct {
	rules []CompiledRule
}

// NewEngine initializes the Policy Engine
func NewEngine() *Engine {
	return &Engine{
		rules: make([]CompiledRule, 0),
	}
}

// Load compiles a slice of string-based rules into executable programs
func (e *Engine) Load(rules []Rule) error {
	var compiled []CompiledRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		
		// Compile expression to bytecode
		prog, err := expr.Compile(r.Expression, expr.Env(&Env{}))
		if err != nil {
			return fmt.Errorf("failed to compile rule '%s': %v", r.Name, err)
		}

		compiled = append(compiled, CompiledRule{
			Rule: r,
			Prog: prog,
		})
		
		log.Printf("[Policy] Loaded Rule: %s (%s)", r.Name, r.Action)
	}

	e.rules = compiled
	return nil
}

// Evaluate checks all loaded rules against the current request state.
// It returns the first matched rule, if any.
func (e *Engine) Evaluate(ctx *fasthttp.RequestCtx) *Rule {
	if len(e.rules) == 0 {
		return nil
	}

	// Prepare Evaluation Environment
	env := &Env{
		Req: &RequestEnv{
			Path:   string(ctx.Path()),
			Method: string(ctx.Method()),
			Host:   string(ctx.Host()),
			UA:     string(ctx.Request.Header.UserAgent()),
		},
		IP: utils.GetClientIP(ctx),
	}

	for _, cr := range e.rules {
		// Run compiled bytecode
		out, err := expr.Run(cr.Prog, env)
		if err != nil {
			// In production, we log error and skip or fail-open.
			log.Printf("[Policy] Rule evaluation err '%s': %v", cr.Rule.Name, err)
			continue
		}

		// Check if it resulted in a boolean 'true'
		if matched, ok := out.(bool); ok && matched {
			return &cr.Rule
		}
	}

	return nil
}
