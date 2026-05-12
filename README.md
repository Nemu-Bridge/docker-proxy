# docker-proxy

A fast, policy-aware HTTP proxy for the Docker Engine API. It sits in front of
the Docker Unix socket and enforces fine-grained access control rules --
endpoint blocking, method restrictions, request body inspection, role-based
access, IP filtering, and response data redaction.

Written in Rust on top of Tokio and Hyper. Single binary, zero runtime
dependencies beyond the Docker socket it talks to.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/Nemu-Bridge/docker-proxy/main/setup | sudo bash
```

This downloads the latest binary, generates secure tokens, writes a config to
`/etc/docker-proxy/config.yaml`, and optionally installs a systemd service
(Linux). macOS users get manual start instructions printed at the end.

If the download fails (private repo, no `gh` CLI), the script prints the exact
download URL for your platform and instructions to install manually.

To build from source instead:

```bash
# Build
cargo build --release

# Run (auto-detects the Docker socket)
cargo run

# Or with explicit configuration
DOCKER_PROXY_CONFIG=/path/to/config.yaml cargo run
```

The proxy listens on `127.0.0.1:2376` by default. Point your Docker client
at it:

```bash
curl http://127.0.0.1:2376/containers/json
docker -H tcp://127.0.0.1:2376 ps
```

To use the bundled example config with authentication, copy it and supply a
token:

```bash
cp config.yaml my-config.yaml
# edit my-config.yaml to set your own tokens

# Admin token (full access)
curl -H "Authorization: Bearer admin-token-abc123" \
  http://127.0.0.1:2376/containers/json

# Readonly token (GET-only)
curl -H "Authorization: Bearer readonly-token-xyz789" \
  http://127.0.0.1:2376/volumes
```

## Configuration file

The proxy looks for `config.yaml` in the current working directory, or at the
path specified by the `DOCKER_PROXY_CONFIG` environment variable. If no config
file exists, the proxy runs with all defaults -- no authentication, no rules,
port 2376, auto-detected Docker socket.

Environment variables can be referenced anywhere in the config using
`${VARIABLE_NAME}` syntax. Unset variables expand to an empty string.

### Top-level structure

```yaml
global:        # optional -- override defaults
auth:          # optional -- authentication configuration
rules:         # optional -- ordered access control rules
```

### `global`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `port` | `u16` | `2376` | TCP port the proxy binds to. Overrides `DOCKER_PROXY_PORT`. |
| `bind` | `string` | `127.0.0.1` | Host/IP to bind. Use `0.0.0.0` only with TLS configured; the proxy logs a loud warning if you bind off-loopback without TLS. |
| `socket` | `string` | auto | Path to the Docker Unix socket. Overrides `DOCKER_SOCKET`. |
| `log_level` | `string` | `info` | Log level filter (`trace`, `debug`, `info`, `warn`, `error`). |
| `log_format` | `string` | `text` | `text` for human logs, `json` for structured one-line-per-event output suitable for Loki/Elasticsearch. |
| `audit_log` | `string` | -- | Path to an append-only JSON audit log of denied / dry-run / auth-failure events. Each line is a self-contained JSON record. |
| `tls` | `object` | -- | TLS termination. See below. |
| `metrics` | `object` | -- | Prometheus metrics endpoint. See below. |

#### `global.tls`

When set, the listener is wrapped in rustls (ring backend, TLS 1.2+1.3). Clients must speak HTTPS.

| Key | Type | Description |
|-----|------|-------------|
| `cert` | `string` | Path to a PEM-encoded server certificate chain. |
| `key` | `string` | Path to a PEM-encoded private key (PKCS#8, PKCS#1, or SEC1). |
| `client_ca` | `string` | Optional. Path to a PEM bundle of CAs used to verify client certificates. Enables mTLS. |
| `require_client_cert` | `bool` | When `true`, the TLS handshake fails unless the client presents a valid cert. Defaults to `false` (optional client cert). |

#### `global.metrics`

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | `bool` | Set `true` to expose the metrics endpoint on the proxy port. |
| `path` | `string` | URL path the metrics live at. Defaults to `/metrics`. |

The endpoint emits Prometheus text format (counters + a histogram of upstream latency). Sample series:

```
docker_proxy_requests_total
docker_proxy_requests_denied_total
docker_proxy_requests_dry_run_total
docker_proxy_auth_failures_total
docker_proxy_rate_limited_total
docker_proxy_upgrade_total
docker_proxy_rule_decisions_total{rule="block-secrets",mode="enforced"}
docker_proxy_upstream_latency_ms_bucket{le="100"}
```

The metrics endpoint does not require authentication — keep it on a private network or wrap it in TLS.

### `auth`

Controls how incoming requests are authenticated.

| Key | Type | Description |
|-----|------|-------------|
| `type` | `string` | Auth scheme. `bearer` enforces Bearer token auth. `none` disables auth entirely. `mtls` uses the client TLS certificate as the identity. |
| `secret` | `string` | A shared Bearer token. Authenticated clients receive the `admin` role. Supports env interpolation (`"${MY_SECRET}"`). |
| `tokens` | `array` | Per-token configuration for fine-grained role assignment. |
| `mtls` | `object` | Settings used when `type: mtls`. See below. |

#### `auth.mtls`

When `auth.type` is `mtls`, the client cert subject is consulted to determine the role.

| Key | Type | Description |
|-----|------|-------------|
| `cert_role_map` | `array` | Ordered list of `{cn, role}` entries. The cert's CN and SANs are matched against each entry; `*.example.com` wildcards match one label. First match wins. |
| `default_role` | `string` | Role assigned when no map entry matches and the cert has no CN. |

If neither a map entry matches nor `default_role` is set but the cert has a CN, the CN itself is used as the role string — so a cert with `CN=admin` gets role `admin` automatically. This means you can ship mTLS with no per-cert config and just name your certs after your roles, or use the explicit map for stricter control.

**Fail-closed defaults.** If no auth section is set, the proxy refuses every request with 401 — including when `tokens: []` is empty or only contains empty strings. To run without authentication you must set `auth.type: none` explicitly. Failed auth attempts are tracked per IP; 10 failures inside 60 seconds trigger a 5-minute lockout for that source IP.

Each entry under `tokens`:

| Key | Type | Description |
|-----|------|-------------|
| `token` | `string` | The Bearer token value. Supports env interpolation. |
| `role` | `string` | Role assigned to this token (default: `user`). |

**How auth resolves:** If neither `secret` nor `tokens` are configured (or the
secret is empty), all requests pass through unauthenticated. If either is
configured, a valid `Authorization: Bearer <token>` header is required. The
`resolve_auth` function checks tokens first, then falls back to the shared
secret. Token-based roles take precedence.

Environment variables take precedence over YAML values. If `DOCKER_PROXY_SECRET`
is set in the environment, it always overrides `auth.secret` in the config file
(regardless of whether the YAML value was a `${...}` reference or a literal).
The same applies to `DOCKER_PROXY_PORT` over `global.port` and `DOCKER_SOCKET`
over `global.socket`.

When no config file exists, the proxy falls back to the `DOCKER_PROXY_SECRET`
environment variable. If that is also unset, auth is disabled. The
"unauthenticated" warning only appears when neither config-based auth nor the
env var fallback provides a secret or tokens.

### `rules`

An ordered list of access control rules. Rules are evaluated in sequence on
every request. **All conditions within a rule must match** (logical AND).
Conditions can be grouped with `and` and `or` for nested logic. The
first matching rule with a terminating action (`deny`, `allow`, `require_role`)
wins. Rules with the `response_filter` action are non-terminating -- they
always accumulate and apply after the Docker response is received.

If no rule matches, the request is allowed.

#### Rule fields

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | `string` | required | Human-readable identifier. |
| `description` | `string` | -- | Optional description of what the rule does. |
| `action` | `string` | required | One of `deny`, `allow`, `require_role`, `response_filter`. |
| `conditions` | `array` | `[]` | List of conditions. All must evaluate true for the rule to fire. |
| `message` | `string` | -- | Custom response body returned when the rule blocks a request. |
| `status` | `u16` | `403` | HTTP status code for blocked requests. |
| `role` | `string` | `admin` | Required role for `require_role` action. |
| `response_filter` | `array` | -- | List of filter entries. Used only with `action: response_filter`. |
| `priority` | `u32` | `0` | Higher priority rules are evaluated first. Rules with equal priority keep their declaration order (stable sort). |
| `dry_run` | `bool` | `false` | When `true`, a rule that would otherwise deny instead allows the request through and emits an audit-log event tagged `dry_run`. Useful for rolling out new policies. |

#### Conditions

Each condition specifies a `field` to inspect, an `operator` that defines how
to compare, and an optional `value` to compare against.

##### Condition fields

| Field | Description |
|-------|-------------|
| `path` | The request path (e.g. `/containers/json`). |
| `method` | The HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`). |
| `client_ip` | The connecting client's IP address. |
| `header.<name>` | A specific request header. `<name>` is case-insensitive. |
| `body.<path>` | A field within the parsed JSON request body. `<path>` uses dot notation for nested objects (e.g. `HostConfig.Privileged`) and numeric indices for array elements (e.g. `Env.0`). |

##### Condition operators

| Operator | Applies To | Description |
|----------|-----------|-------------|
| `equals` | all | Exact value match. For `body` fields, compares typed values (strings, booleans, numbers). |
| `not_equals` | all | Negation of `equals`. |
| `contains` | path, header, body | Substring match. |
| `not_contains` | path, header, body | Negation of `contains`. |
| `starts_with` | path, header, body | Prefix match. |
| `ends_with` | path, header | Suffix match. |
| `matches` | path, header, body | Regex match (Rust regex syntax). |
| `not_matches` | path, header | Negation of `matches`. |
| `in` | all | Value is present in a YAML list. For `client_ip`, list entries are parsed as CIDR ranges. |
| `not_in` | all | Value is absent from a YAML list. CIDR-aware for `client_ip`. |
| `exists` | header, body | The field exists or is present in the JSON body. |
| `not_exists` | header, body | The field is missing or absent from the JSON body. |

##### Condition Grouping (AND / OR)

Conditions can be nested with `and` and `or` groups to express complex logic
within a single rule. At the top level of `conditions`, items are implicitly
AND-ed. Use `or` to match any of several alternatives:

```yaml
# Block both exec creation and exec start with a single rule
- name: "block-exec"
  conditions:
    - or:
        - field: path
          operator: matches
          value: "^/containers/[^/]+/exec$"
        - field: path
          operator: matches
          value: "^/exec/[^/]+/start$"
  action: deny
  message: "Exec operations are not permitted"
```

Groups can be arbitrarily nested:

```yaml
# Block write operations to volumes OR networks, but only during off-hours
- name: "off-hour-write-block"
  conditions:
    - or:
        - field: path
          operator: starts_with
          value: "/volumes"
        - field: path
          operator: starts_with
          value: "/networks"
    - field: method
      operator: not_equals
      value: GET
  action: deny
  message: "Write operations are restricted during off-hours"
```

The implicit top-level AND combined with explicit `or` groups is equivalent to
conjunctive normal form. Flat condition lists (without `and`/`or`) remain fully
supported and continue to behave as before.

##### Actions

| Action | Terminating? | Description |
|--------|-------------|-------------|
| `deny` | yes | Blocks the request immediately with the configured `status` and `message`. |
| `allow` | yes | Explicitly allows the request, short-circuiting further rule evaluation. Useful for carving out exceptions ordered before broad deny rules. |
| `require_role` | yes | Blocks the request if the authenticated user's role is not `admin` and does not match the rule's required `role`. The `admin` role always passes. |
| `response_filter` | no | Allows the request but applies JSON transformations to the Docker response body. Filters from multiple matching rules accumulate. Only applied when the response `content-type` is `application/json`. |
| `rate_limit` | yes (when exceeded) | Enforces a token-bucket rate limit per client IP. If the bucket has tokens available, the request continues and 1 token is consumed. If the bucket is empty, the request is denied with `status` (default `429`). When the limit is not exceeded, evaluation continues to the next rule. |

##### Response filter entries

Used within the `response_filter` array of a rule.

| Key | Type | Description |
|-----|------|-------------|
| `field` | `string` | Dot-notation path to the JSON field to modify (e.g. `Config.Env`, `NetworkSettings.IPAddress`). |
| `action` | `string` | `redact` (replace with `***REDACTED***`), `remove` (delete the field), or `replace` (set to `replacement`). |
| `replacement` | `string` | Replacement value for the `replace` action. |

##### Rate limit config

Used within the `rate_limit` field of a rule with `action: rate_limit`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `requests` | `u64` | `50` | Maximum requests allowed in the window (bucket capacity). |
| `period` | `u64` | `30` | Window size in seconds. Tokens refill at `requests / period` per second. |
| `penalty` | `u64` | `30` | Cooldown in seconds after hitting the limit. Once the bucket empties, the client is blocked for this many seconds. After the penalty expires, the bucket resets to full capacity. |

The limiter uses a per-rule, per-client-IP token bucket. Each client starts
with a full bucket. Every request consumes 1 token. Tokens refill continuously.
When the bucket hits 0, a penalty cooldown activates: the client is blocked
for `penalty` seconds with a `429 Too Many Requests` response. After the
penalty expires, the bucket resets to full and the client can resume.

Idle buckets are cleaned up every 60 seconds to keep memory minimal.

## Architecture

```
Client (curl / docker CLI)
    |
    | TCP :2376
    v
+------------------+
|   docker-proxy   |
|                  |
|  1. Authenticate |--- bearer token / secret
|  2. Evaluate     |--- config.yaml rules
|  3. Forward      |
|  4. Filter       |--- redact / remove response fields
+------------------+
    |
    | Unix socket
    v
+------------------+
|   Docker Engine  |
+------------------+
```

**Request flow:**

1. Accept TCP connection, parse HTTP request.
2. Authenticate the request against configured tokens or shared secret.
   Resolve the caller's role (or `None` if unauthenticated).
3. Parse the request body as JSON (if present and non-empty).
4. Build an `EvaluationContext` containing path, method, headers, client IP,
   body JSON, and user role.
5. Iterate rules in order:
   - `deny` and `require_role` checks may reject immediately.
   - `allow` short-circuits with no further checks.
   - `response_filter` rules accumulate their filter entries.
   - If no rule terminates evaluation, the request is allowed.
6. Open a Unix socket connection to Docker, perform an HTTP/1.1 handshake,
   and forward the request (stripping the `Authorization` header).
7. Receive the Docker response.
8. If any response filters were collected and the response is JSON, apply
   them (redact, remove, replace).
9. Return the (possibly filtered) response to the client.

## Streaming (`docker exec`, `attach`, `logs -f`)

Endpoints that upgrade to a raw TCP stream are forwarded transparently. The proxy:

1. Authenticates the request and runs it through the rule engine like any other.
2. Opens a connection to the Docker socket, replays the request with the `Upgrade` header preserved.
3. When Docker responds with `101 Switching Protocols`, the proxy returns 101 to the client and then bidirectionally copies bytes between the two halves until either side closes (or until `UPGRADE_IDLE_TIMEOUT`, currently one hour with no traffic).

`docker -H tcp://proxy:2376 exec -it <container> /bin/sh` works as long as `exec` operations aren't denied by a rule. Add the `block-exec` rule to disable.

## Audit log

If `global.audit_log` is set, the proxy spawns a writer task that appends one JSON record per line for each denied, dry-run, or auth-failure event:

```json
{"timestamp":"2026-05-12T19:09:18Z","event":"deny","peer_ip":"10.0.0.5","method":"POST","path":"/containers/create","user_agent":"docker/24.0","user_role":"readonly","identity":null,"rule_name":"admin-only-create","rule_action":"require_role","status":403,"dry_run":false,"message":"Admin role required to create containers"}
```

The writer task uses a bounded channel; if the disk falls behind, events are dropped rather than blocking request handling (a warning is logged).

## Hot reload

Send `SIGHUP` to the proxy process and it re-reads the same config file it started from. The new rules and auth tables apply to the next accepted request; in-flight connections keep their old config. If the new file fails to parse, the proxy logs an error and keeps running on the previous config.

```bash
kill -HUP $(pgrep docker-proxy)
```

## CLI

```
docker-proxy [--config <path>] [--check-config]
```

| Flag | Description |
|------|-------------|
| `--config <path>` | Path to the YAML config (overrides `DOCKER_PROXY_CONFIG`). |
| `--check-config` | Parse the config, print the effective rule set sorted by priority, exit. Returns non-zero if parsing fails. Use in CI before deploys. |

## Example rule patterns

### Block an endpoint entirely

```yaml
- name: "block-secrets"
  conditions:
    - field: path
      operator: starts_with
      value: "/secrets"
  action: deny
  message: "Secrets are not accessible"
```

### Restrict a resource to read-only

```yaml
- name: "readonly-volumes"
  conditions:
    - field: path
      operator: starts_with
      value: "/volumes"
    - field: method
      operator: not_equals
      value: GET
  action: deny
  message: "Volume mutations are forbidden"
```

### Combine multiple endpoints with OR

```yaml
- name: "block-dangerous-endpoints"
  conditions:
    - or:
        - field: path
          operator: starts_with
          value: "/secrets"
        - field: path
          operator: starts_with
          value: "/configs"
  action: deny
  message: "Secrets and configs are not accessible"
```

The `or` group matches when any of its children match, so a single rule
can cover multiple endpoint patterns without duplication.

### Inspect the request body

```yaml
- name: "block-privileged"
  conditions:
    - field: path
      operator: equals
      value: "/containers/create"
    - field: body.HostConfig.Privileged
      operator: equals
      value: true
  action: deny
  message: "Privileged containers are not allowed"

- name: "block-bind-mounts"
  conditions:
    - field: path
      operator: equals
      value: "/containers/create"
    - field: body.HostConfig.Binds
      operator: exists
  action: deny
  message: "Bind mounts are not allowed"
```

### Restrict by role

```yaml
- name: "admin-only-create"
  conditions:
    - field: path
      operator: equals
      value: "/containers/create"
  action: require_role
  role: admin
  message: "Admin role required to create containers"
```

### IP-based access control (CIDR)

```yaml
- name: "internal-network-only"
  conditions:
    - field: client_ip
      operator: not_in
      value:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"
  action: deny
  message: "Access restricted to internal network"
```

### Redact sensitive response data

```yaml
- name: "redact-environment"
  conditions:
    - field: path
      operator: matches
      value: "^/containers/[^/]+/json$"
  action: response_filter
  response_filter:
    - field: Config.Env
      action: redact
    - field: Config.Cmd
      action: redact
```

### Rate limit per client IP

```yaml
- name: "rate-limit-all"
  conditions:
    - field: path
      operator: matches
      value: "^/"
  action: rate_limit
  rate_limit:
    requests: 50
    period: 30
    penalty: 30
  message: "Rate limit exceeded. You are blocked for 30 seconds."
  status: 429
```

This limits every client IP to 50 requests per 30-second window. Once the
bucket is empty, a 30-second penalty activates -- all requests during the
penalty receive `429` responses. After the penalty expires, the bucket resets
to full. Rate-limiting is per-rule and per-client-IP.

For endpoint-specific limits, narrow the `path` condition:

```yaml
- name: "rate-limit-container-create"
  conditions:
    - field: path
      operator: equals
      value: "/containers/create"
  action: rate_limit
  rate_limit:
    requests: 5
    period: 1
  message: "Too many container create requests"
```

### Dry-run a new rule before enforcing it

```yaml
- name: "watch-image-pulls"
  description: Log image pulls but don't block — yet
  priority: 100
  conditions:
    - field: path
      operator: starts_with
      value: /images/create
  action: deny
  dry_run: true
  message: "(dry-run) image pull would be denied"
```

Every matching request is recorded to the audit log with `"dry_run": true` and the metric `docker_proxy_rule_decisions_total{rule="watch-image-pulls",mode="dry_run"}` is incremented, but the request still proceeds. Once you've verified the rule isn't catching legitimate traffic, remove `dry_run` to enforce.

### Block Linux capability escalation

```yaml
- name: "block-capability-escalation"
  conditions:
    - field: path
      operator: equals
      value: /containers/create
    - or:
        - field: body.HostConfig.CapAdd
          operator: contains
          value: SYS_ADMIN
        - field: body.HostConfig.CapAdd
          operator: contains
          value: NET_ADMIN
        - field: body.HostConfig.CapAdd
          operator: contains
          value: SYS_PTRACE
        - field: body.HostConfig.CapAdd
          operator: contains
          value: ALL
  action: deny
  message: "Adding privileged Linux capabilities is not allowed"
```

### mTLS with role-mapped client certs

```yaml
auth:
  type: mtls
  mtls:
    cert_role_map:
      - cn: "admin.ops.example.com"
        role: admin
      - cn: "*.readonly.ops.example.com"
        role: readonly
    default_role: user
```

A request over mTLS with client cert `CN=svc-7.readonly.ops.example.com` matches the wildcard entry and gets the `readonly` role. Combine with the standard `require_role` rules.

### Explicit allow to override a broad deny

```yaml
- name: "allow-healthcheck"
  conditions:
    - field: path
      operator: equals
      value: "/_ping"
  action: allow

- name: "deny-everything-else"
  conditions:
    - field: path
      operator: matches
      value: "^/.*"
  action: deny
  message: "Access denied"
```

In this pattern, `/_ping` is explicitly allowed before the catch-all deny
rule, so health checks pass while everything else is blocked.

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DOCKER_PROXY_CONFIG` | Path to the YAML configuration file. | `./config.yaml` |
| `DOCKER_PROXY_SECRET` | Shared Bearer token (used when no config file or when config lacks auth). | (none) |
| `DOCKER_PROXY_PORT` | TCP listen port (overridden by `global.port` in config). | `2376` |
| `DOCKER_SOCKET` | Path to the Docker Unix socket (overridden by `global.socket` in config). | auto-detected |
| `RUST_LOG` | Tracing log filter (overrides `global.log_level`). | `docker_proxy=info` |

Socket auto-detection order:
- macOS: `~/.docker/run/docker.sock`, `/var/run/docker.sock`, `~/.docker/desktop/docker.sock`
- Linux: `/var/run/docker.sock`, `/run/docker.sock`

## Scripts

| Script | Purpose |
|--------|---------|
| `setup` | Download binary, generate config, install service. Detects OS/arch. |
| `build` | Cross-compile for all 4 targets (linux x86_64, linux aarch64, macos x86_64, macos arm64). |
| `update` | Publish built binaries as a GitHub release. Bumps version automatically. |

**Release workflow:**

```bash
./build                    # compiles all 4 targets into release/
./update                   # prompts for version, creates GitHub release
```

Requires `cargo-zigbuild`, `zig`, and `gh` CLI authenticated.

## Interactive setup (TUI)

Generate a `config.yaml` interactively using the TUI wizard:

```bash
cargo run --bin docker-proxy-setup
```

The wizard walks through:
- Port and socket configuration
- Authentication (none, shared secret, or per-token roles)
- Rule templates (block endpoints, readonly resources, body inspection, role-based access, IP filtering, response redaction, rate limiting)
- Custom rules with manual condition building

Select one or more templates from the multi-select menu, or build rules
from scratch with custom conditions.

## Build

```bash
cargo build --release
```

The binary is at `target/release/docker-proxy`.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `hyper` + `hyper-util` | HTTP server and client (Unix socket transport) |
| `http-body-util` | Request/response body utilities |
| `tracing` + `tracing-subscriber` | Structured logging |
| `serde` + `serde_yaml` | YAML config parsing |
| `serde_json` | JSON body inspection and response filtering |
| `regex` | Pattern matching in rule conditions |
| `ipnet` | CIDR matching for IP-based rules |
| `chrono` | Request log timestamps |
