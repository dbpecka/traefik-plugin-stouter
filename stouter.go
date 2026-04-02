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
type Config struct {
	PollInterval      string   `json:"pollInterval,omitempty"`
	Endpoint          string   `json:"endpoint,omitempty"`
	RuleTemplate      string   `json:"ruleTemplate,omitempty"`
	DefaultEntryPoints []string `json:"defaultEntryPoints,omitempty"`
}

// CreateConfig returns a Config populated with sensible defaults.
func CreateConfig() *Config {
	return &Config{
		PollInterval:      "5s",
		Endpoint:          "http://127.0.0.1:5381",
		RuleTemplate:      "Host(`{{ .Name }}.stouter.local`)",
		DefaultEntryPoints: []string{"web"},
	}
}

// ---------------------------------------------------------------------------
// Stouter API types
// ---------------------------------------------------------------------------

// StouterService represents a single service returned by the stouter API.
type StouterService struct {
	Name    string   `json:"name"`
	Port    int      `json:"port"`
	Address string   `json:"address"`
	Domains []string `json:"domains"`
}

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

// Router is a Traefik HTTP router.
type Router struct {
	Rule        string   `json:"rule"`
	Service     string   `json:"service"`
	EntryPoints []string `json:"entryPoints,omitempty"`
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

// Provider implements the Traefik provider plugin interface.
type Provider struct {
	name         string
	pollInterval time.Duration
	endpoint     string
	ruleTpl      *template.Template
	entryPoints  []string
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

	tpl, err := template.New("rule").Parse(config.RuleTemplate)
	if err != nil {
		return nil, fmt.Errorf("invalid ruleTemplate %q: %w", config.RuleTemplate, err)
	}

	return &Provider{
		name:         name,
		pollInterval: d,
		endpoint:     config.Endpoint,
		ruleTpl:      tpl,
		entryPoints:  config.DefaultEntryPoints,
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
// cfgChan whenever the set of stouter services changes.
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

	var lastHash string

	// Poll immediately on start, then on each tick.
	for {
		services, err := fetchServices(p.httpClient, p.endpoint)
		if err != nil {
			log.Printf("[stouter] failed to fetch services: %v", err)
		} else {
			cfg := buildDynamicConfig(services, p.ruleTpl, p.entryPoints)
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
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
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

// buildDynamicConfig maps a slice of stouter services to a Traefik dynamic
// configuration with one router and one service per stouter service.
func buildDynamicConfig(services []StouterService, ruleTpl *template.Template, entryPoints []string) *DynConfig {
	routers := make(map[string]*Router, len(services))
	svcMap := make(map[string]*Service, len(services))

	for _, svc := range services {
		key := "stouter-" + svc.Name

		var rule string
		if len(svc.Domains) > 0 {
			parts := make([]string, len(svc.Domains))
			for i, d := range svc.Domains {
				parts[i] = fmt.Sprintf("Host(`%s`)", d)
			}
			rule = strings.Join(parts, " || ")
		} else {
			var ruleBuf bytes.Buffer
			if err := ruleTpl.Execute(&ruleBuf, svc); err != nil {
				log.Printf("[stouter] rule template error for %q: %v", svc.Name, err)
				continue
			}
			rule = ruleBuf.String()
		}

		routers[key] = &Router{
			Rule:        rule,
			Service:     key,
			EntryPoints: entryPoints,
		}

		svcMap[key] = &Service{
			LoadBalancer: &LoadBalancer{
				Servers: []Server{
					{URL: fmt.Sprintf("http://%s", svc.Address)},
				},
			},
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
