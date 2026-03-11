package policy

import (
	"testing"

	"github.com/valyala/fasthttp"
)

func TestEngine_Evaluate_Match(t *testing.T) {
	engine := NewEngine()
	rules := []Rule{
		{
			ID:         "1",
			Name:       "Block PHP",
			Expression: `Req.Path endsWith ".php"`,
			Action:     ActionBlock,
			Enabled:    true,
		},
		{
			ID:         "2",
			Name:       "Block Bad IP",
			Expression: `IP == "10.0.0.1"`,
			Action:     ActionBlock,
			Enabled:    true,
		},
	}

	err := engine.Load(rules)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Test 1: Should match the first rule
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("http://localhost/login.php")

	matched := engine.Evaluate(ctx)
	if matched == nil {
		t.Fatalf("Expected to match rule 'Block PHP', got nil")
	}
	if matched.ID != "1" {
		t.Errorf("Expected rule ID 1, got %s", matched.ID)
	}

	// Test 2: Should not match
	ctx2 := &fasthttp.RequestCtx{}
	ctx2.Request.Header.SetMethod("GET")
	ctx2.Request.SetRequestURI("http://localhost/index.html")
	matched2 := engine.Evaluate(ctx2)
	if matched2 != nil {
		t.Errorf("Expected nil, got match for rule %s", matched2.ID)
	}
}

func TestEngine_Evaluate_ComplexExpression(t *testing.T) {
	engine := NewEngine()
	rules := []Rule{
		{
			ID:         "1",
			Name:       "Complex Auth bypass block",
			Expression: `(Req.Path startsWith "/admin" || Req.Path startsWith "/console") && Req.Method == "POST" && !(Req.Host contains "internal.noxis.io")`,
			Action:     ActionChallenge,
			Enabled:    true,
		},
	}

	err := engine.Load(rules)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Should match: POST to /admin not from internal host
	ctx1 := &fasthttp.RequestCtx{}
	ctx1.Request.SetRequestURI("/admin/login")
	ctx1.Request.Header.SetMethod("POST")
	ctx1.Request.Header.SetHost("public.example.com")
	
	if engine.Evaluate(ctx1) == nil {
		t.Errorf("Expected complex rule to match, got nil")
	}

	// Should not match: Method is GET
	ctx2 := &fasthttp.RequestCtx{}
	ctx2.Request.SetRequestURI("/admin/login")
	ctx2.Request.Header.SetMethod("GET")
	ctx2.Request.Header.SetHost("public.example.com")
	
	if engine.Evaluate(ctx2) != nil {
		t.Errorf("Expected complex rule to NOT match for GET, but it did")
	}

	// Should not match: Internal host
	ctx3 := &fasthttp.RequestCtx{}
	ctx3.Request.SetRequestURI("/admin/login")
	ctx3.Request.Header.SetMethod("POST")
	ctx3.Request.Header.SetHost("dashboard.internal.noxis.io")
	
	if engine.Evaluate(ctx3) != nil {
		t.Errorf("Expected complex rule to NOT match for internal host, but it did")
	}
}

func TestEngine_Load_DisabledRule(t *testing.T) {
	engine := NewEngine()
	rules := []Rule{
		{
			ID:         "1",
			Name:       "Disabled Rule",
			Expression: `Req.Path == "/test"`,
			Action:     ActionBlock,
			Enabled:    false,
		},
	}

	engine.Load(rules)
	
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/test")

	if engine.Evaluate(ctx) != nil {
		t.Errorf("Expected disabled rule to not be evaluated")
	}
}
