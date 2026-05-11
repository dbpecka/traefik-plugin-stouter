package traefik_plugin_stouter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func mustTpl(t *testing.T, s string) *template.Template {
	t.Helper()
	return template.Must(template.New("rule").Parse(s))
}

func singleInstance(name, ruleTpl string, entryPoints []string, certResolver string) []instance {
	if certResolver == "" {
		certResolver = "acme"
	}
	if len(entryPoints) == 0 {
		entryPoints = []string{"web"}
	}
	return []instance{{
		name:         name,
		endpoint:     "http://unused",
		ruleTpl:      template.Must(template.New("rule").Parse(ruleTpl)),
		entryPoints:  entryPoints,
		certResolver: certResolver,
	}}
}

// ---------------------------------------------------------------------------
// CreateConfig defaults
// ---------------------------------------------------------------------------

func TestCreateConfig(t *testing.T) {
	cfg := CreateConfig()

	if cfg.PollInterval != "5s" {
		t.Errorf("PollInterval = %q, want %q", cfg.PollInterval, "5s")
	}
	if len(cfg.Instances) != 1 {
		t.Fatalf("Instances length = %d, want 1", len(cfg.Instances))
	}
	ic := cfg.Instances[0]
	if ic.Name != "default" {
		t.Errorf("Instances[0].Name = %q, want %q", ic.Name, "default")
	}
	if ic.Endpoint != "http://127.0.0.1:5381" {
		t.Errorf("Instances[0].Endpoint = %q", ic.Endpoint)
	}
	if ic.RuleTemplate != "Host(`{{ .Name }}.stouter.local`)" {
		t.Errorf("Instances[0].RuleTemplate = %q", ic.RuleTemplate)
	}
	if len(ic.DefaultEntryPoints) != 1 || ic.DefaultEntryPoints[0] != "web" {
		t.Errorf("Instances[0].DefaultEntryPoints = %v", ic.DefaultEntryPoints)
	}
	if ic.CertResolver != "acme" {
		t.Errorf("Instances[0].CertResolver = %q", ic.CertResolver)
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

	services, err := fetchServices(http.DefaultClient, srv.URL)
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

	_, err := fetchServices(http.DefaultClient, srv.URL)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestFetchServicesInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer srv.Close()

	_, err := fetchServices(http.DefaultClient, srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// buildDynamicConfig
// ---------------------------------------------------------------------------

func TestBuildDynamicConfig(t *testing.T) {
	insts := singleInstance("default", "Host(`{{ .Name }}.stouter.local`)", []string{"web"}, "acme")
	cache := map[string][]StouterService{
		"default": {
			{Name: "plex", Port: 32400, Address: "127.0.0.1:32400"},
			{Name: "grafana", Port: 3000, Address: "127.0.0.1:3000"},
		},
	}

	cfg := buildDynamicConfig(insts, cache)

	if cfg.HTTP == nil {
		t.Fatal("HTTP config is nil")
	}
	if len(cfg.HTTP.Routers) != 2 {
		t.Fatalf("got %d routers, want 2", len(cfg.HTTP.Routers))
	}
	if len(cfg.HTTP.Services) != 2 {
		t.Fatalf("got %d services, want 2", len(cfg.HTTP.Services))
	}

	r, ok := cfg.HTTP.Routers["stouter-default-plex"]
	if !ok {
		t.Fatal("missing router stouter-default-plex")
	}
	if r.Rule != "Host(`plex.stouter.local`)" {
		t.Errorf("rule = %q", r.Rule)
	}
	if r.Service != "stouter-default-plex" {
		t.Errorf("service = %q", r.Service)
	}
	if len(r.EntryPoints) != 1 || r.EntryPoints[0] != "web" {
		t.Errorf("entryPoints = %v", r.EntryPoints)
	}

	s, ok := cfg.HTTP.Services["stouter-default-plex"]
	if !ok {
		t.Fatal("missing service stouter-default-plex")
	}
	if len(s.LoadBalancer.Servers) != 1 {
		t.Fatalf("got %d servers", len(s.LoadBalancer.Servers))
	}
	if s.LoadBalancer.Servers[0].URL != "http://127.0.0.1:32400" {
		t.Errorf("url = %q", s.LoadBalancer.Servers[0].URL)
	}
}

func TestBuildDynamicConfigCustomTemplate(t *testing.T) {
	insts := singleInstance("default", "PathPrefix(`/{{ .Name }}`)", []string{"websecure"}, "acme")
	cache := map[string][]StouterService{
		"default": {{Name: "api", Port: 9090, Address: "127.0.0.1:9090"}},
	}

	cfg := buildDynamicConfig(insts, cache)

	r := cfg.HTTP.Routers["stouter-default-api"]
	if r.Rule != "PathPrefix(`/api`)" {
		t.Errorf("rule = %q", r.Rule)
	}
	if r.EntryPoints[0] != "websecure" {
		t.Errorf("entryPoints = %v", r.EntryPoints)
	}
}

func TestBuildDynamicConfigEmpty(t *testing.T) {
	insts := singleInstance("default", "Host(`{{ .Name }}.local`)", []string{"web"}, "acme")
	cfg := buildDynamicConfig(insts, map[string][]StouterService{})

	if len(cfg.HTTP.Routers) != 0 {
		t.Errorf("expected 0 routers, got %d", len(cfg.HTTP.Routers))
	}
	if len(cfg.HTTP.Services) != 0 {
		t.Errorf("expected 0 services, got %d", len(cfg.HTTP.Services))
	}
}

func TestBuildDynamicConfigMultipleInstances(t *testing.T) {
	insts := []instance{
		{
			name:         "prod",
			endpoint:     "http://unused",
			ruleTpl:      mustTpl(t, "Host(`{{ .Name }}.prod.example.com`)"),
			entryPoints:  []string{"websecure"},
			certResolver: "acme-prod",
		},
		{
			name:         "dev",
			endpoint:     "http://unused",
			ruleTpl:      mustTpl(t, "Host(`{{ .Name }}.dev.example.com`)"),
			entryPoints:  []string{"web"},
			certResolver: "acme-dev",
		},
	}
	cache := map[string][]StouterService{
		"prod": {{Name: "web", Port: 80, Address: "10.0.0.1:80"}},
		"dev":  {{Name: "web", Port: 80, Address: "10.0.0.2:80"}},
	}

	cfg := buildDynamicConfig(insts, cache)

	if len(cfg.HTTP.Routers) != 2 {
		t.Fatalf("routers = %d, want 2", len(cfg.HTTP.Routers))
	}

	prod, ok := cfg.HTTP.Routers["stouter-prod-web"]
	if !ok {
		t.Fatal("missing router stouter-prod-web")
	}
	if prod.Rule != "Host(`web.prod.example.com`)" {
		t.Errorf("prod rule = %q", prod.Rule)
	}
	if prod.EntryPoints[0] != "websecure" {
		t.Errorf("prod entryPoints = %v", prod.EntryPoints)
	}
	if prod.TLS.CertResolver != "acme-prod" {
		t.Errorf("prod certResolver = %q", prod.TLS.CertResolver)
	}

	dev, ok := cfg.HTTP.Routers["stouter-dev-web"]
	if !ok {
		t.Fatal("missing router stouter-dev-web")
	}
	if dev.Rule != "Host(`web.dev.example.com`)" {
		t.Errorf("dev rule = %q", dev.Rule)
	}
	if dev.EntryPoints[0] != "web" {
		t.Errorf("dev entryPoints = %v", dev.EntryPoints)
	}

	// Same service name across instances must produce distinct backends.
	if cfg.HTTP.Services["stouter-prod-web"].LoadBalancer.Servers[0].URL == cfg.HTTP.Services["stouter-dev-web"].LoadBalancer.Servers[0].URL {
		t.Error("prod and dev services collided")
	}
}

func TestBuildDynamicConfigMissingInstanceInCache(t *testing.T) {
	// Two instances configured, but the cache only has data for one. The other
	// is silently skipped (e.g. first poll never succeeded yet).
	insts := []instance{
		{
			name:         "a",
			endpoint:     "http://unused",
			ruleTpl:      mustTpl(t, "Host(`{{ .Name }}.a`)"),
			entryPoints:  []string{"web"},
			certResolver: "acme",
		},
		{
			name:         "b",
			endpoint:     "http://unused",
			ruleTpl:      mustTpl(t, "Host(`{{ .Name }}.b`)"),
			entryPoints:  []string{"web"},
			certResolver: "acme",
		},
	}
	cache := map[string][]StouterService{
		"b": {{Name: "svc", Port: 1, Address: "127.0.0.1:1"}},
	}

	cfg := buildDynamicConfig(insts, cache)

	if len(cfg.HTTP.Routers) != 1 {
		t.Fatalf("routers = %d, want 1", len(cfg.HTTP.Routers))
	}
	if _, ok := cfg.HTTP.Routers["stouter-b-svc"]; !ok {
		t.Error("expected stouter-b-svc")
	}
}

// ---------------------------------------------------------------------------
// Change detection
// ---------------------------------------------------------------------------

func TestHashConfigChangeDetection(t *testing.T) {
	insts := singleInstance("default", "Host(`{{ .Name }}.local`)", []string{"web"}, "acme")

	cfg1 := buildDynamicConfig(insts, map[string][]StouterService{
		"default": {{Name: "a", Port: 1000, Address: "127.0.0.1:1000"}},
	})
	cfg2 := buildDynamicConfig(insts, map[string][]StouterService{
		"default": {{Name: "a", Port: 1000, Address: "127.0.0.1:1000"}},
	})
	cfg3 := buildDynamicConfig(insts, map[string][]StouterService{
		"default": {
			{Name: "a", Port: 1000, Address: "127.0.0.1:1000"},
			{Name: "b", Port: 2000, Address: "127.0.0.1:2000"},
		},
	})

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
				"stouter-default-test": {
					Rule:        "Host(`test.local`)",
					Service:     "stouter-default-test",
					EntryPoints: []string{"web"},
				},
			},
			Services: map[string]*Service{
				"stouter-default-test": {
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

	var parsed DynConfig
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.HTTP.Routers["stouter-default-test"].Rule != "Host(`test.local`)" {
		t.Errorf("round-trip rule = %q", parsed.HTTP.Routers["stouter-default-test"].Rule)
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
	cfg.Instances[0].RuleTemplate = "{{ .Bad"

	_, err := New(nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error for invalid ruleTemplate")
	}
}

func TestNewRequiresAtLeastOneInstance(t *testing.T) {
	cfg := CreateConfig()
	cfg.Instances = nil

	_, err := New(nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error when no instances configured")
	}
}

func TestNewRequiresInstanceName(t *testing.T) {
	cfg := CreateConfig()
	cfg.Instances[0].Name = ""

	_, err := New(nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error when instance name missing")
	}
}

func TestNewRejectsDuplicateInstanceNames(t *testing.T) {
	cfg := &Config{
		PollInterval: "5s",
		Instances: []InstanceConfig{
			{Name: "a", Endpoint: "http://x"},
			{Name: "a", Endpoint: "http://y"},
		},
	}

	_, err := New(nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error for duplicate instance names")
	}
}

func TestNewRequiresInstanceEndpoint(t *testing.T) {
	cfg := &Config{
		PollInterval: "5s",
		Instances:    []InstanceConfig{{Name: "a"}},
	}

	_, err := New(nil, cfg, "test")
	if err == nil {
		t.Fatal("expected error for missing endpoint")
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
	cfg.PollInterval = "50ms"
	cfg.Instances[0].Endpoint = srv.URL

	p, err := New(nil, cfg, "stouter")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfgChan := make(chan json.Marshaler, 1)
	if err := p.Provide(cfgChan); err != nil {
		t.Fatalf("Provide: %v", err)
	}
	defer p.Stop()

	select {
	case msg := <-cfgChan:
		data, _ := json.Marshal(msg)
		var got DynConfig
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := got.HTTP.Routers["stouter-default-svc1"]; !ok {
			t.Errorf("missing router stouter-default-svc1, got routers: %v", got.HTTP.Routers)
		}
		if _, ok := got.HTTP.Services["stouter-default-svc1"]; !ok {
			t.Error("missing service stouter-default-svc1")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for config")
	}

	select {
	case <-cfgChan:
		t.Error("unexpected duplicate config push")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestProvideIntegrationMultipleInstances(t *testing.T) {
	bodyA := `[{"name":"svc","port":4000,"address":"127.0.0.1:4000"}]`
	bodyB := `[{"name":"svc","port":5000,"address":"127.0.0.1:5000"}]`

	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, bodyA)
	}))
	defer srvA.Close()

	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, bodyB)
	}))
	defer srvB.Close()

	cfg := &Config{
		PollInterval: "50ms",
		Instances: []InstanceConfig{
			{Name: "a", Endpoint: srvA.URL, RuleTemplate: "Host(`{{ .Name }}.a`)", DefaultEntryPoints: []string{"web"}},
			{Name: "b", Endpoint: srvB.URL, RuleTemplate: "Host(`{{ .Name }}.b`)", DefaultEntryPoints: []string{"web"}},
		},
	}

	p, err := New(nil, cfg, "stouter")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfgChan := make(chan json.Marshaler, 1)
	if err := p.Provide(cfgChan); err != nil {
		t.Fatalf("Provide: %v", err)
	}
	defer p.Stop()

	select {
	case msg := <-cfgChan:
		data, _ := json.Marshal(msg)
		var got DynConfig
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := got.HTTP.Routers["stouter-a-svc"]; !ok {
			t.Errorf("missing router stouter-a-svc, got: %v", got.HTTP.Routers)
		}
		if _, ok := got.HTTP.Routers["stouter-b-svc"]; !ok {
			t.Errorf("missing router stouter-b-svc, got: %v", got.HTTP.Routers)
		}
		if got.HTTP.Routers["stouter-a-svc"].Rule != "Host(`svc.a`)" {
			t.Errorf("a rule = %q", got.HTTP.Routers["stouter-a-svc"].Rule)
		}
		if got.HTTP.Routers["stouter-b-svc"].Rule != "Host(`svc.b`)" {
			t.Errorf("b rule = %q", got.HTTP.Routers["stouter-b-svc"].Rule)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for config")
	}
}

// One instance failing must not blow away the cached state of healthy
// instances on subsequent polls.
func TestProvideKeepsCacheOnInstanceFailure(t *testing.T) {
	srvGood := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `[{"name":"svc","port":1,"address":"127.0.0.1:1"}]`)
	}))
	defer srvGood.Close()

	// Bad endpoint that always returns 500.
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srvBad.Close()

	cfg := &Config{
		PollInterval: "30ms",
		Instances: []InstanceConfig{
			{Name: "good", Endpoint: srvGood.URL, RuleTemplate: "Host(`{{ .Name }}.good`)", DefaultEntryPoints: []string{"web"}},
			{Name: "bad", Endpoint: srvBad.URL, RuleTemplate: "Host(`{{ .Name }}.bad`)", DefaultEntryPoints: []string{"web"}},
		},
	}

	p, err := New(nil, cfg, "stouter")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfgChan := make(chan json.Marshaler, 4)
	if err := p.Provide(cfgChan); err != nil {
		t.Fatalf("Provide: %v", err)
	}
	defer p.Stop()

	select {
	case msg := <-cfgChan:
		data, _ := json.Marshal(msg)
		var got DynConfig
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := got.HTTP.Routers["stouter-good-svc"]; !ok {
			t.Error("missing router from healthy instance")
		}
		if _, ok := got.HTTP.Routers["stouter-bad-svc"]; ok {
			t.Error("did not expect router from failing instance")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first config push")
	}

	// No further pushes expected (hash unchanged across ticks even though bad
	// keeps failing).
	select {
	case <-cfgChan:
		t.Error("unexpected duplicate config push")
	case <-time.After(150 * time.Millisecond):
	}
}

// ---------------------------------------------------------------------------
// buildDynamicConfig with custom domains
// ---------------------------------------------------------------------------

func TestBuildDynamicConfigCustomDomains(t *testing.T) {
	insts := singleInstance("default", "Host(`{{ .Name }}.stouter.local`)", []string{"websecure"}, "acme")
	cache := map[string][]StouterService{
		"default": {
			{Name: "equipflo-test-web", Port: 3200, Address: "127.0.0.1:3200", Domains: []string{"equipflo.com", "www.equipflo.com"}},
		},
	}

	cfg := buildDynamicConfig(insts, cache)

	r, ok := cfg.HTTP.Routers["stouter-default-equipflo-test-web"]
	if !ok {
		t.Fatal("missing router stouter-default-equipflo-test-web")
	}
	want := "Host(`equipflo.com`) || Host(`www.equipflo.com`)"
	if r.Rule != want {
		t.Errorf("rule = %q, want %q", r.Rule, want)
	}

	if r.TLS == nil {
		t.Fatal("router TLS is nil")
	}
	if len(r.TLS.Domains) != 1 {
		t.Fatalf("TLS.Domains length = %d, want 1", len(r.TLS.Domains))
	}
	if r.TLS.Domains[0].Main != "equipflo.com" {
		t.Errorf("TLS.Domains[0].Main = %q, want %q", r.TLS.Domains[0].Main, "equipflo.com")
	}
	if len(r.TLS.Domains[0].SANs) != 1 || r.TLS.Domains[0].SANs[0] != "www.equipflo.com" {
		t.Errorf("TLS.Domains[0].SANs = %v, want [www.equipflo.com]", r.TLS.Domains[0].SANs)
	}
}

func TestBuildDynamicConfigSingleCustomDomain(t *testing.T) {
	insts := singleInstance("default", "Host(`{{ .Name }}.stouter.local`)", []string{"web"}, "acme")
	cache := map[string][]StouterService{
		"default": {
			{Name: "web", Port: 8080, Address: "127.0.0.1:8080", Domains: []string{"example.com"}},
		},
	}

	cfg := buildDynamicConfig(insts, cache)

	r := cfg.HTTP.Routers["stouter-default-web"]
	if r.Rule != "Host(`example.com`)" {
		t.Errorf("rule = %q", r.Rule)
	}

	if r.TLS == nil {
		t.Fatal("router TLS is nil")
	}
	if len(r.TLS.Domains) != 1 {
		t.Fatalf("TLS.Domains length = %d, want 1", len(r.TLS.Domains))
	}
	if r.TLS.Domains[0].Main != "example.com" {
		t.Errorf("TLS.Domains[0].Main = %q, want %q", r.TLS.Domains[0].Main, "example.com")
	}
	if len(r.TLS.Domains[0].SANs) != 0 {
		t.Errorf("TLS.Domains[0].SANs = %v, want empty", r.TLS.Domains[0].SANs)
	}
}

func TestBuildDynamicConfigMixedDomainsAndTemplate(t *testing.T) {
	insts := singleInstance("default", "Host(`{{ .Name }}.stouter.local`)", []string{"web"}, "acme")
	cache := map[string][]StouterService{
		"default": {
			{Name: "with-domains", Port: 3200, Address: "127.0.0.1:3200", Domains: []string{"custom.com"}},
			{Name: "no-domains", Port: 8080, Address: "127.0.0.1:8080"},
		},
	}

	cfg := buildDynamicConfig(insts, cache)

	r1 := cfg.HTTP.Routers["stouter-default-with-domains"]
	if r1.Rule != "Host(`custom.com`)" {
		t.Errorf("with-domains rule = %q, want Host(`custom.com`)", r1.Rule)
	}

	r2 := cfg.HTTP.Routers["stouter-default-no-domains"]
	if r2.Rule != "Host(`no-domains.stouter.local`)" {
		t.Errorf("no-domains rule = %q, want Host(`no-domains.stouter.local`)", r2.Rule)
	}

	if r1.TLS == nil || len(r1.TLS.Domains) != 1 || r1.TLS.Domains[0].Main != "custom.com" {
		t.Errorf("with-domains TLS.Domains = %+v, want [{Main:custom.com}]", r1.TLS)
	}
	if len(r1.TLS.Domains[0].SANs) != 0 {
		t.Errorf("with-domains SANs = %v, want empty", r1.TLS.Domains[0].SANs)
	}

	if r2.TLS == nil {
		t.Fatal("no-domains router TLS is nil")
	}
	if r2.TLS.Domains != nil {
		t.Errorf("no-domains TLS.Domains = %v, want nil", r2.TLS.Domains)
	}
}

func TestFetchServicesWithDomains(t *testing.T) {
	body := `[{"name":"web","port":8080,"address":"127.0.0.1:8080","domains":["example.com","www.example.com"]}]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	services, err := fetchServices(http.DefaultClient, srv.URL)
	if err != nil {
		t.Fatalf("fetchServices: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("got %d services, want 1", len(services))
	}
	if len(services[0].Domains) != 2 {
		t.Fatalf("got %d domains, want 2", len(services[0].Domains))
	}
	if services[0].Domains[0] != "example.com" || services[0].Domains[1] != "www.example.com" {
		t.Errorf("domains = %v", services[0].Domains)
	}
}

// TestMarshalRouterTLSDomains verifies the JSON shape of a router with
// tls.domains matches what Traefik expects (and what yaegi produces).
func TestMarshalRouterTLSDomains(t *testing.T) {
	insts := singleInstance("default", "Host(`{{ .Name }}.stouter.local`)", []string{"websecure"}, "acme")
	cache := map[string][]StouterService{
		"default": {{Name: "x", Address: "127.0.0.1:1", Domains: []string{"a.com", "b.com"}}},
	}
	cfg := buildDynamicConfig(insts, cache)

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(data)

	for _, want := range []string{
		`"tls":{`,
		`"certResolver":"acme"`,
		`"domains":[{"main":"a.com","sans":["b.com"]}]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("JSON missing %q\ngot: %s", want, got)
		}
	}
}

// Verify hashConfig returns a stable value for nil input.
func TestHashConfigNil(t *testing.T) {
	h := hashConfig(nil)
	if h == "" {
		t.Error("expected non-empty hash for nil config")
	}
	if h != hashConfig(nil) {
		t.Error("nil hash is not stable")
	}
}
