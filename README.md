# traefik-plugin-stouter

A Traefik provider plugin that polls one or more [stouter](https://github.com/dbpecka/stouter) subscribe REST APIs and dynamically creates HTTP routers and services for each tunneled service.

## Installation

Add the plugin to your Traefik static configuration:

```yaml
experimental:
  plugins:
    stouter:
      moduleName: github.com/dbpecka/traefik-plugin-stouter
      version: v0.2.0
```

## Configuration

The plugin polls one or more stouter endpoints listed under `instances`. Each instance has its own endpoint, rule template, entrypoints, and cert resolver, and contributes routers and services into a single merged dynamic configuration.

```yaml
providers:
  plugin:
    stouter:
      pollInterval: 5s
      instances:
        - name: home
          endpoint: http://127.0.0.1:5381
          ruleTemplate: "Host(`{{ .Name }}.stouter.local`)"
          defaultEntryPoints:
            - web
          certResolver: acme
```

Multiple instances:

```yaml
providers:
  plugin:
    stouter:
      pollInterval: 5s
      instances:
        - name: prod
          endpoint: http://10.0.0.1:5381
          ruleTemplate: "Host(`{{ .Name }}.prod.example.com`)"
          defaultEntryPoints: [websecure]
          certResolver: acme
        - name: dev
          endpoint: http://10.0.0.2:5381
          ruleTemplate: "Host(`{{ .Name }}.dev.example.com`)"
          defaultEntryPoints: [websecure]
          certResolver: acme-staging
```

### Top-level options

| Option | Default | Description |
|---|---|---|
| `pollInterval` | `5s` | How often to poll each stouter API. Any Go duration string (e.g. `10s`, `1m`). |
| `instances` | (one default instance) | List of stouter endpoints to poll. At least one required. |

### Per-instance options

| Option | Default | Description |
|---|---|---|
| `name` | — | Required. Stable identifier used to namespace generated router/service keys. Must be unique across instances. |
| `endpoint` | — | Required. Base URL of the stouter API. |
| `ruleTemplate` | `` Host(`{{ .Name }}.stouter.local`) `` | Go template for the Traefik router rule. Receives a service with `Name`, `Port`, and `Address` fields. |
| `defaultEntryPoints` | `["web"]` | Traefik entrypoints to attach to each generated router. |
| `certResolver` | `acme` | Cert resolver name attached to each generated router's TLS config. |

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

If a stouter service declares its own `domains`, those take precedence over the rule template: the router rule becomes `Host(\`d1\`) || Host(\`d2\`) || …` and `tls.domains` is populated from that list.

## How it works

1. The plugin polls `GET {endpoint}/services` on every instance in parallel, on the configured interval.
2. Each service in the response gets a Traefik HTTP router and load-balancer service, keyed as `stouter-{instance}-{service}`.
3. If a single instance's fetch fails on a tick, its previously known routes are preserved — only the failing instance is affected.
4. The merged configuration is only pushed to Traefik when the union of services actually changes.
