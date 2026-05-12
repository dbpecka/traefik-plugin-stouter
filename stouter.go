// Package traefik_plugin_stouter is a Traefik provider plugin that polls the
// stouter subscribe REST API and dynamically creates routers and services for
// each tunneled service.
package traefik_plugin_stouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Config holds the plugin configuration supplied by the Traefik static config.
//
// One Traefik provider plugin can fan out to multiple stouter endpoints by
// listing them under Instances. Each instance polls independently and
// contributes routers/services into the merged dynamic configuration.
type Config struct {
	PollInterval string           `json:"pollInterval,omitempty"`
	Instances    []InstanceConfig `json:"instances,omitempty"`
}

// InstanceConfig describes a single stouter endpoint to poll.
type InstanceConfig struct {
	Name               string   `json:"name,omitempty"`
	Endpoint           string   `json:"endpoint,omitempty"`
	RuleTemplate       string   `json:"ruleTemplate,omitempty"`
	DefaultEntryPoints []string `json:"defaultEntryPoints,omitempty"`
	CertResolver       string   `json:"certResolver,omitempty"`
}

// CreateConfig returns a Config populated with sensible defaults.
func CreateConfig() *Config {
	return &Config{
		PollInterval: "5s",
		Instances: []InstanceConfig{
			{
				Name:               "default",
				Endpoint:           "http://127.0.0.1:5381",
				RuleTemplate:       "Host(`{{ .Name }}.stouter.local`)",
				DefaultEntryPoints: []string{"web"},
				CertResolver:       "acme",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Stouter API types
// ---------------------------------------------------------------------------

// StouterService represents a single service returned by the stouter API.
type StouterService struct {
	Name    string            `json:"name"`
	Port    int               `json:"port"`
	Address string            `json:"address"`
	Domains []string          `json:"domains"`
	Meta    map[string]string `json:"meta"`
}

// metaSchemeKey is the meta key consulted to override the URL scheme used
// when proxying to a service (e.g. "h2c" for gRPC backends).
const metaSchemeKey = "traefik.scheme"

// ---------------------------------------------------------------------------
// Traefik dynamic configuration types
// ---------------------------------------------------------------------------

// DynConfig is the top-level dynamic configuration sent to Traefik.
type DynConfig struct {
	HTTP *HTTPConfig `json:"http,omitempty"`
}

// MarshalJSON implements json.Marshaler so *DynConfig satisfies the channel
// type (chan<- json.Marshaler) required by Traefik's Provide method.
// Note: the usual "type Alias" trick causes infinite recursion under yaegi,
// so we build a plain map instead.
func (d *DynConfig) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{}, 1)
	if d.HTTP != nil {
		m["http"] = d.HTTP
	}
	return json.Marshal(m)
}

// HTTPConfig contains the dynamic HTTP routers and services.
type HTTPConfig struct {
	Routers  map[string]*Router  `json:"routers,omitempty"`
	Services map[string]*Service `json:"services,omitempty"`
}

// Domain represents a TLS domain entry with a main name and optional SANs.
type Domain struct {
	Main string   `json:"main,omitempty"`
	SANs []string `json:"sans,omitempty"`
}

// RouterTLS holds TLS configuration for a router.
type RouterTLS struct {
	CertResolver string   `json:"certResolver,omitempty"`
	Domains      []Domain `json:"domains,omitempty"`
}

// Router is a Traefik HTTP router.
type Router struct {
	Rule        string     `json:"rule"`
	Service     string     `json:"service"`
	EntryPoints []string   `json:"entryPoints,omitempty"`
	TLS         *RouterTLS `json:"tls,omitempty"`
}

// Service is a Traefik HTTP service with a load balancer.
type Service struct {
	LoadBalancer *LoadBalancer `json:"loadBalancer,omitempty"`
}

// LoadBalancer holds the list of backend servers.
type LoadBalancer struct {
	Servers []Server `json:"servers,omitempty"`
}

// Server is a single backend target.
type Server struct {
	URL string `json:"url"`
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

// instance is the compiled runtime form of an InstanceConfig.
type instance struct {
	name         string
	endpoint     string
	ruleTpl      *template.Template
	entryPoints  []string
	certResolver string
}

// Provider implements the Traefik provider plugin interface.
type Provider struct {
	name         string
	pollInterval time.Duration
	instances    []instance
	httpClient   *http.Client

	mu     sync.Mutex
	cancel context.CancelFunc
}

// New creates a new Provider from the supplied config.
func New(_ context.Context, config *Config, name string) (*Provider, error) {
	d, err := time.ParseDuration(config.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid pollInterval %q: %w", config.PollInterval, err)
	}

	if len(config.Instances) == 0 {
		return nil, fmt.Errorf("at least one instance is required under `instances`")
	}

	seen := make(map[string]bool, len(config.Instances))
	instances := make([]instance, len(config.Instances))
	for i, ic := range config.Instances {
		if ic.Name == "" {
			return nil, fmt.Errorf("instance at index %d: name is required", i)
		}
		if seen[ic.Name] {
			return nil, fmt.Errorf("duplicate instance name %q", ic.Name)
		}
		seen[ic.Name] = true

		if ic.Endpoint == "" {
			return nil, fmt.Errorf("instance %q: endpoint is required", ic.Name)
		}

		ruleStr := ic.RuleTemplate
		if ruleStr == "" {
			ruleStr = "Host(`{{ .Name }}.stouter.local`)"
		}
		tpl, err := template.New("rule-" + ic.Name).Parse(ruleStr)
		if err != nil {
			return nil, fmt.Errorf("instance %q: invalid ruleTemplate %q: %w", ic.Name, ruleStr, err)
		}

		eps := ic.DefaultEntryPoints
		if len(eps) == 0 {
			eps = []string{"web"}
		}

		certResolver := ic.CertResolver
		if certResolver == "" {
			certResolver = "acme"
		}

		instances[i] = instance{
			name:         ic.Name,
			endpoint:     ic.Endpoint,
			ruleTpl:      tpl,
			entryPoints:  eps,
			certResolver: certResolver,
		}
	}

	return &Provider{
		name:         name,
		pollInterval: d,
		instances:    instances,
		httpClient: &http.Client{
			Timeout: d - d/10, // 90% of poll interval
		},
	}, nil
}

// Init performs any one-time setup. Required by the Traefik provider interface.
func (p *Provider) Init() error {
	return nil
}

// Provide starts the polling loop and pushes dynamic configuration updates onto
// cfgChan whenever the merged set of stouter services changes.
func (p *Provider) Provide(cfgChan chan<- json.Marshaler) error {
	ctx, cancel := context.WithCancel(context.Background())

	p.mu.Lock()
	p.cancel = cancel
	p.mu.Unlock()

	go p.poll(ctx, cfgChan)
	return nil
}

// Stop signals the polling goroutine to exit.
func (p *Provider) Stop() error {
	p.mu.Lock()
	cancel := p.cancel
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

func (p *Provider) poll(ctx context.Context, cfgChan chan<- json.Marshaler) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	// Per-instance last-known-good service list. A transient fetch failure for
	// one instance preserves its previous routes rather than removing them.
	cache := make(map[string][]StouterService, len(p.instances))

	var lastHash string

	for {
		p.refreshAll(cache)

		cfg := buildDynamicConfig(p.instances, cache)
		hash := hashConfig(cfg)
		if hash != lastHash {
			var msg json.Marshaler = cfg
			select {
			case cfgChan <- msg:
				lastHash = hash
			case <-ctx.Done():
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// refreshAll fetches every instance in parallel and updates cache in place.
// Failed fetches leave the previous cache entry untouched.
func (p *Provider) refreshAll(cache map[string][]StouterService) {
	type result struct {
		name     string
		services []StouterService
		err      error
	}

	results := make(chan result, len(p.instances))
	var wg sync.WaitGroup
	for _, inst := range p.instances {
		wg.Add(1)
		go func(inst instance) {
			defer wg.Done()
			svcs, err := fetchServices(p.httpClient, inst.endpoint)
			results <- result{name: inst.name, services: svcs, err: err}
		}(inst)
	}
	wg.Wait()
	close(results)

	for r := range results {
		if r.err != nil {
			log.Printf("[stouter] instance %q: failed to fetch services: %v", r.name, r.err)
			continue
		}
		cache[r.name] = r.services
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fetchServices performs a GET to the stouter /services endpoint and returns
// the parsed service list.
func fetchServices(client *http.Client, endpoint string) ([]StouterService, error) {
	resp, err := client.Get(endpoint + "/services")
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var services []StouterService
	if err := json.Unmarshal(body, &services); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return services, nil
}

// buildDynamicConfig produces a Traefik dynamic configuration containing the
// union of routers/services across all instances. Keys are namespaced by
// instance name as `stouter-{instance}-{service}` to avoid collisions when
// two instances expose a service with the same name.
func buildDynamicConfig(instances []instance, cache map[string][]StouterService) *DynConfig {
	routers := make(map[string]*Router)
	svcMap := make(map[string]*Service)

	for _, inst := range instances {
		services, ok := cache[inst.name]
		if !ok {
			continue
		}
		for _, svc := range services {
			key := "stouter-" + inst.name + "-" + svc.Name

			var rule string
			if len(svc.Domains) > 0 {
				parts := make([]string, len(svc.Domains))
				for i, d := range svc.Domains {
					parts[i] = fmt.Sprintf("Host(`%s`)", d)
				}
				rule = strings.Join(parts, " || ")
			} else {
				var ruleBuf bytes.Buffer
				if err := inst.ruleTpl.Execute(&ruleBuf, svc); err != nil {
					log.Printf("[stouter] instance %q: rule template error for %q: %v", inst.name, svc.Name, err)
					continue
				}
				rule = ruleBuf.String()
			}

			tls := &RouterTLS{CertResolver: inst.certResolver}
			if len(svc.Domains) > 0 {
				d := Domain{Main: svc.Domains[0]}
				if len(svc.Domains) > 1 {
					d.SANs = append([]string(nil), svc.Domains[1:]...)
				}
				tls.Domains = []Domain{d}
			}

			routers[key] = &Router{
				Rule:        rule,
				Service:     key,
				EntryPoints: inst.entryPoints,
				TLS:         tls,
			}

			scheme := "http"
			if s := svc.Meta[metaSchemeKey]; s != "" {
				scheme = s
			}

			svcMap[key] = &Service{
				LoadBalancer: &LoadBalancer{
					Servers: []Server{
						{URL: fmt.Sprintf("%s://%s", scheme, svc.Address)},
					},
				},
			}
		}
	}

	return &DynConfig{
		HTTP: &HTTPConfig{
			Routers:  routers,
			Services: svcMap,
		},
	}
}

// canonicalJSON returns a deterministic JSON representation of cfg by sorting
// map keys, so the output is stable across calls regardless of Go's random map
// iteration order.
func canonicalJSON(cfg *DynConfig) []byte {
	if cfg == nil || cfg.HTTP == nil {
		return []byte("{}")
	}

	type canonicalEntry struct {
		Key     string   `json:"key"`
		Router  *Router  `json:"router,omitempty"`
		Service *Service `json:"service,omitempty"`
	}

	routerKeys := make([]string, 0, len(cfg.HTTP.Routers))
	for k := range cfg.HTTP.Routers {
		routerKeys = append(routerKeys, k)
	}
	sort.Strings(routerKeys)

	serviceKeys := make([]string, 0, len(cfg.HTTP.Services))
	for k := range cfg.HTTP.Services {
		serviceKeys = append(serviceKeys, k)
	}
	sort.Strings(serviceKeys)

	routers := make([]canonicalEntry, len(routerKeys))
	for i, k := range routerKeys {
		routers[i] = canonicalEntry{Key: k, Router: cfg.HTTP.Routers[k]}
	}

	services := make([]canonicalEntry, len(serviceKeys))
	for i, k := range serviceKeys {
		services[i] = canonicalEntry{Key: k, Service: cfg.HTTP.Services[k]}
	}

	out := struct {
		Routers  []canonicalEntry `json:"routers"`
		Services []canonicalEntry `json:"services"`
	}{routers, services}

	data, _ := json.Marshal(out)
	return data
}

// hashConfig returns a deterministic hash of the config, used for change
// detection so we only push updates when something actually changed.
func hashConfig(cfg *DynConfig) string {
	return string(canonicalJSON(cfg))
}
