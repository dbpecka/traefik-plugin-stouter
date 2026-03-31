// Package traefik_plugin_stouter is a Traefik provider plugin that polls the
// stouter subscribe REST API and dynamically creates routers and services for
// each tunneled service.
package traefik_plugin_stouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	Name    string `json:"name"`
	Port    int    `json:"port"`
	Address string `json:"address"`
}

// ---------------------------------------------------------------------------
// Traefik dynamic configuration types
// ---------------------------------------------------------------------------

// DynConfig is the top-level dynamic configuration sent to Traefik.
type DynConfig struct {
	HTTP *HTTPConfig `json:"http,omitempty"`
}

// MarshalJSON implements json.Marshaler so DynConfig satisfies the channel type
// expected by Traefik's Provide method.
func (d *DynConfig) MarshalJSON() ([]byte, error) {
	type Alias DynConfig
	return json.Marshal((*Alias)(d))
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
	cancel       context.CancelFunc
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
	p.cancel = cancel

	go p.poll(ctx, cfgChan)
	return nil
}

// Stop signals the polling goroutine to exit.
func (p *Provider) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

func (p *Provider) poll(ctx context.Context, cfgChan chan<- json.Marshaler) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	var lastHash [sha256.Size]byte

	// Poll immediately on start, then on each tick.
	for {
		services, err := fetchServices(p.endpoint)
		if err != nil {
			log.Printf("[stouter] failed to fetch services: %v", err)
		} else {
			cfg := buildDynamicConfig(services, p.ruleTpl, p.entryPoints)
			hash := hashConfig(cfg)
			if hash != lastHash {
				cfgChan <- cfg
				lastHash = hash
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
func fetchServices(endpoint string) ([]StouterService, error) {
	resp, err := http.Get(endpoint + "/services")
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

		var ruleBuf bytes.Buffer
		if err := ruleTpl.Execute(&ruleBuf, svc); err != nil {
			log.Printf("[stouter] rule template error for %q: %v", svc.Name, err)
			continue
		}

		routers[key] = &Router{
			Rule:        ruleBuf.String(),
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

// hashConfig returns a SHA-256 hash of the JSON-serialised config, used for
// change detection so we only push updates when something actually changed.
func hashConfig(cfg *DynConfig) [sha256.Size]byte {
	data, _ := json.Marshal(cfg)
	return sha256.Sum256(data)
}
