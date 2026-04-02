# traefik-plugin-stouter

A Traefik provider plugin that polls the [stouter](https://github.com/dbpecka/stouter) subscribe REST API and dynamically creates HTTP routers and services for each tunneled service.

## Installation

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    stouter:
      moduleName: github.com/dbpecka/traefik-plugin-stouter
      version: v0.1.0
```

## Configuration

Add the provider to your Traefik static configuration:

```yaml
providers:
  plugin:
    stouter:
      pollInterval: 5s
      endpoint: http://127.0.0.1:5381
      ruleTemplate: "Host(`{{ .Name }}.stouter.local`)"
      defaultEntryPoints:
        - web
```

### Options

| Option | Default | Description |
|---|---|---|
| `pollInterval` | `5s` | How often to poll the stouter API for changes. Any Go duration string (e.g. `10s`, `1m`). |
| `endpoint` | `http://127.0.0.1:5381` | Base URL of the stouter API. |
| `ruleTemplate` | `` Host(`{{ .Name }}.stouter.local`) `` | Go template for the Traefik router rule. Receives a service object with `Name`, `Port`, and `Address` fields. |
| `defaultEntryPoints` | `["web"]` | Traefik entrypoints to attach to each generated router. |

### Rule template

The `ruleTemplate` is a Go `text/template` that receives each stouter service as its context. Available fields:

- `.Name` — service name (e.g. `grafana`)
- `.Port` — service port (e.g. `3000`)
- `.Address` — service address including port (e.g. `127.0.0.1:3000`)

Examples:

```yaml
# Subdomain routing
ruleTemplate: "Host(`{{ .Name }}.example.com`)"

# Path prefix routing
ruleTemplate: "PathPrefix(`/{{ .Name }}`)"

# Combined
ruleTemplate: "Host(`tunnel.example.com`) && PathPrefix(`/{{ .Name }}`)"
```

## How it works

1. The plugin polls `GET {endpoint}/services` on the configured interval.
2. Each service in the response gets a Traefik HTTP router and load-balancer service, keyed as `stouter-{name}`.
3. Configuration is only pushed to Traefik when the set of services actually changes.
