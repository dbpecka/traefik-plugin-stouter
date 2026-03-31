package traefik_plugin_stouter

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"
)

// ---------------------------------------------------------------------------
// CreateConfig defaults
// ---------------------------------------------------------------------------

func TestCreateConfig(t *testing.T) {
	cfg := CreateConfig()

	if cfg.PollInterval != "5s" {
		t.Errorf("PollInterval = %q, want %q", cfg.PollInterval, "5s")
	}
	if cfg.Endpoint != "http://127.0.0.1:5381" {
		t.Errorf("Endpoint = %q, want %q", cfg.Endpoint, "http://127.0.0.1:5381")
	}
	if cfg.RuleTemplate != "Host(`{{ .Name }}.stouter.local`)" {
		t.Errorf("RuleTemplate = %q", cfg.RuleTemplate)
	}
	if len(cfg.DefaultEntryPoints) != 1 || cfg.DefaultEntryPoints[0] != "web" {
		t.Errorf("DefaultEntryPoints = %v", cfg.DefaultEntryPoints)
	}
}

// ---------------------------------------------------------------------------
// fetchServices
// ---------------------------------------------------------------------------

func TestFetchServices(t *testing.T) {
	body := `[{"name":"web","port":8080,"address":"127.0.0.1:8080"},{"name":"api","port":9090,"address":"127.0.0.1:9090"}]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	services, err := fetchServices(srv.URL)
	if err != nil {
		t.Fatalf("fetchServices: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("got %d services, want 2", len(services))
	}
	if services[0].Name != "web" || services[0].Port != 8080 {
		t.Errorf("services[0] = %+v", services[0])
	}
	if services[1].Name != "api" || services[1].Port != 9090 {
		t.Errorf("services[1] = %+v", services[1])
	}
}

func TestFetchServicesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchServices(srv.URL)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestFetchServicesInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer srv.Close()

	_, err := fetchServices(srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// buildDynamicConfig
// ---------------------------------------------------------------------------

func TestBuildDynamicConfig(t *testing.T) {
	tpl := template.Must(template.New("rule").Parse("Host(`{{ .Name }}.stouter.local`)"))
	entryPoints := []string{"web"}

	services := []StouterService{
		{Name: "plex", Port: 32400, Address: "127.0.0.1:32400"},
		{Name: "grafana", Port: 3000, Address: "127.0.0.1:3000"},
	}

	cfg := buildDynamicConfig(services, tpl, entryPoints)

	if cfg.HTTP == nil {
		t.Fatal("HTTP config is nil")
	}
	if len(cfg.HTTP.Routers) != 2 {
		t.Fatalf("got %d routers, want 2", len(cfg.HTTP.Routers))
	}
	if len(cfg.HTTP.Services) != 2 {
		t.Fatalf("got %d services, want 2", len(cfg.HTTP.Services))
	}

	// Check plex router.
	r, ok := cfg.HTTP.Routers["stouter-plex"]
	if !ok {
		t.Fatal("missing router stouter-plex")
	}
	if r.Rule != "Host(`plex.stouter.local`)" {
		t.Errorf("rule = %q", r.Rule)
	}
	if r.Service != "stouter-plex" {
		t.Errorf("service = %q", r.Service)
	}
	if len(r.EntryPoints) != 1 || r.EntryPoints[0] != "web" {
		t.Errorf("entryPoints = %v", r.EntryPoints)
	}

	// Check plex service.
	s, ok := cfg.HTTP.Services["stouter-plex"]
	if !ok {
		t.Fatal("missing service stouter-plex")
	}
	if len(s.LoadBalancer.Servers) != 1 {
		t.Fatalf("got %d servers", len(s.LoadBalancer.Servers))
	}
	if s.LoadBalancer.Servers[0].URL != "http://127.0.0.1:32400" {
		t.Errorf("url = %q", s.LoadBalancer.Servers[0].URL)
	}
}

func TestBuildDynamicConfigCustomTemplate(t *testing.T) {
	tpl := template.Must(template.New("rule").Parse("PathPrefix(`/{{ .Name }}`)"))
	entryPoints := []string{"websecure"}

	services := []StouterService{
		{Name: "api", Port: 9090, Address: "127.0.0.1:9090"},
	}

	cfg := buildDynamicConfig(services, tpl, entryPoints)

	r := cfg.HTTP.Routers["stouter-api"]
	if r.Rule != "PathPrefix(`/api`)" {
		t.Errorf("rule = %q", r.Rule)
	}
	if r.EntryPoints[0] != "websecure" {
		t.Errorf("entryPoints = %v", r.EntryPoints)
	}
}

func TestBuildDynamicConfigEmpty(t *testing.T) {
	tpl := template.Must(template.New("rule").Parse("Host(`{{ .Name }}.local`)"))
	cfg := buildDynamicConfig(nil, tpl, []string{"web"})

	if len(cfg.HTTP.Routers) != 0 {
		t.Errorf("expected 0 routers, got %d", len(cfg.HTTP.Routers))
	}
	if len(cfg.HTTP.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(cfg.HTTP.Services))
	}
}

// ---------------------------------------------------------------------------
// Change detection
// ---------------------------------------------------------------------------

func TestHashConfigChangeDetection(t *testing.T) {
	tpl := template.Must(template.New("rule").Parse("Host(`{{ .Name }}.local`)"))
	ep := []string{"web"}

	cfg1 := buildDynamicConfig([]StouterService{
		{Name: "a", Port: 1000, Address: "127.0.0.1:1000"},
	}, tpl, ep)

	cfg2 := buildDynamicConfig([]StouterService{
		{Name: "a", Port: 1000, Address: "127.0.0.1:1000"},
	}, tpl, ep)

	cfg3 := buildDynamicConfig([]StouterService{
		{Name: "a", Port: 1000, Address: "127.0.0.1:1000"},
		{Name: "b", Port: 2000, Address: "127.0.0.1:2000"},
	}, tpl, ep)

	h1 := hashConfig(cfg1)
	h2 := hashConfig(cfg2)
	h3 := hashConfig(cfg3)

	if h1 != h2 {
		t.Error("identical configs should produce the same hash")
	}
	if h1 == h3 {
		t.Error("different configs should produce different hashes")
	}
}

// ---------------------------------------------------------------------------
// MarshalJSON
// ---------------------------------------------------------------------------

func TestDynConfigMarshalJSON(t *testing.T) {
	cfg := &DynConfig{
		HTTP: &HTTPConfig{
			Routers: map[string]*Router{
				"stouter-test": {
					Rule:        "Host(`test.local`)",
					Service:     "stouter-test",
					EntryPoints: []string{"web"},
				},
			},
			Services: map[string]*Service{
				"stouter-test": {
					LoadBalancer: &LoadBalancer{
						Servers: []Server{{URL: "http://127.0.0.1:8080"}},
					},
				},
			},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Round-trip to verify structure.
	var parsed DynConfig
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.HTTP.Routers["stouter-test"].Rule != "Host(`test.local`)" {
		t.Errorf("round-trip rule = %q", parsed.HTTP.Routers["stouter-test"].Rule)
	}
}

// ---------------------------------------------------------------------------
// New / Init
// ---------------------------------------------------------------------------

func TestNewInvalidPollInterval(t *testing.T) {
	cfg := CreateConfig()
	cfg.PollInterval = "nope"

	_, err := New(nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid pollInterval")
	}
}

func TestNewInvalidRuleTemplate(t *testing.T) {
	cfg := CreateConfig()
	cfg.RuleTemplate = "{{ .Bad"

	_, err := New(nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid ruleTemplate")
	}
}

func TestNewAndInit(t *testing.T) {
	cfg := CreateConfig()
	p, err := New(nil, cfg, "stouter")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Integration: Provide pushes config from mock API
// ---------------------------------------------------------------------------

func TestProvideIntegration(t *testing.T) {
	body := `[{"name":"svc1","port":4000,"address":"127.0.0.1:4000"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := CreateConfig()
	cfg.Endpoint = srv.URL
	cfg.PollInterval = "50ms"

	p, err := New(nil, cfg, "stouter")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfgChan := make(chan json.Marshaler, 1)
	if err := p.Provide(cfgChan); err != nil {
		t.Fatalf("Provide: %v", err)
	}
	defer p.Stop()

	// Wait for the first config push.
	select {
	case msg := <-cfgChan:
		data, _ := json.Marshal(msg)
		var got DynConfig
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := got.HTTP.Routers["stouter-svc1"]; !ok {
			t.Error("missing router stouter-svc1")
		}
		if _, ok := got.HTTP.Services["stouter-svc1"]; !ok {
			t.Error("missing service stouter-svc1")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for config")
	}

	// Second tick should NOT produce a duplicate (same hash).
	select {
	case <-cfgChan:
		t.Error("unexpected duplicate config push")
	case <-time.After(200 * time.Millisecond):
		// Expected — no duplicate.
	}

	// Verify that after changing the hash, a new config IS pushed.
	// (We can't easily change the mock mid-test without races, so we
	// just verify the no-duplicate path above.)
}

// Verify hashConfig returns the zero hash for nil input gracefully.
func TestHashConfigNil(t *testing.T) {
	h := hashConfig(nil)
	if h == ([sha256.Size]byte{}) {
		// json.Marshal(nil) → "null", so hash should be non-zero.
		t.Error("expected non-zero hash for nil config")
	}
}
