# docker-proxy

A fast, policy-aware HTTP proxy for the Docker Engine API. It sits in front of
the Docker Unix socket and enforces fine-grained access control rules --
endpoint blocking, method restrictions, request body inspection, role-based
access, IP filtering, and response data redaction.

Written in Rust on top of Tokio and Hyper. Single binary, zero runtime
dependencies beyond the Docker socket it talks to.

## Quick start

One command, run as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Nemu-Bridge/docker-proxy/main/setup | sudo bash
```

That's it. The proxy is now running on `127.0.0.1:2376`.

Prefer to read the script before running it as root (recommended)? Download it
first, inspect it, then run:

```bash
curl -fsSL -o setup https://raw.githubusercontent.com/Nemu-Bridge/docker-proxy/main/setup
less setup
sudo ./setup
```

The installer downloads the latest release binary for your platform, verifies
it against the published `SHA256SUMS`, generates secure admin and readonly
tokens, writes a config to `/etc/docker-proxy/config.yaml`, and (on Linux)
installs and starts a systemd service. macOS users get manual start
instructions printed at the end. If the download fails (private repo, no `gh`
CLI), the script prints the exact download URL for your platform and manual
install instructions.

### Your tokens (the only secrets you store)

Setup generates two bearer tokens and writes them into
`/etc/docker-proxy/config.yaml` (mode `640`, readable by root only). You don't
create them - you just read them back and hand them to whatever talks to the
proxy:

```bash
sudo grep -A1 'role: admin'    /etc/docker-proxy/config.yaml   # admin token (full access)
sudo grep -A1 'role: readonly' /etc/docker-proxy/config.yaml   # readonly token (GET-only)
```

Use a token by sending it as a Bearer header:

```bash
curl -H "Authorization: Bearer <admin-token>" http://127.0.0.1:2376/version
docker -H tcp://127.0.0.1:2376 ps   # for a docker client, pass the token via your client config
```

Treat these like passwords. Rotate them by editing the config and restarting
the service (see below).

### Changing the configuration

Everything is in `/etc/docker-proxy/config.yaml` - port, bind address, Docker
socket path, auth, and the ordered access rules. To change anything:

```bash
sudo nano /etc/docker-proxy/config.yaml      # edit port / rules / tokens
docker-proxy --check-config                   # validate before applying
sudo systemctl restart docker-proxy           # apply the change
journalctl -u docker-proxy -f                 # watch it come back up
```

The rule syntax and every available knob are documented in
[Configuration file](#configuration-file) below.

### Verifying release artifacts

Each release publishes a `SHA256SUMS` file. The setup script downloads and
verifies it automatically - this is the default and requires nothing from the
user.

Releases can additionally be GPG-signed. The automated release pipeline signs
`SHA256SUMS` into `SHA256SUMS.asc` whenever the `GPG_PRIVATE_KEY` and
`GPG_PASSPHRASE` repository secrets are configured (see
[Releasing](#releasing)). For a local/manual release, set
`DOCKER_PROXY_SIGNING_KEY` to the key ID before running `./update`:

```bash
export DOCKER_PROXY_SIGNING_KEY="0xYOURKEYID"
./update
```

When a `SHA256SUMS.asc` is present, `setup` verifies it - but only succeeds if
the release signing key is already imported into the user's GPG keyring, and
**aborts the install if verification fails**. Only enable signing once you also
publish and document the public key, otherwise it breaks the one-command
install for everyone who hasn't imported it.

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

### Binding to an external interface

To accept connections from other hosts, set `bind: 0.0.0.0` in the config:

```yaml
global:
  port: 2376
  bind: 0.0.0.0
  socket: /var/run/docker.sock
```

The proxy logs a warning when binding off-loopback without TLS. Docker API
access is powerful - you should **either**:

- Configure TLS (`global.tls`) so traffic is encrypted and authenticated.
- Restrict access with a firewall (`ufw`, `iptables`, or your cloud provider's
  security group) to only allow trusted IPs.

To use the bundled example config with authentication, copy it and set the
required environment variables:

```bash
cp config.yaml my-config.yaml
# Tokens must be supplied via environment variables in the example config.
export ADMIN_TOKEN="$(openssl rand -base64 48)"
export READONLY_TOKEN="$(openssl rand -base64 48)"

# Admin token (full access)
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://127.0.0.1:2376/containers/json

# Readonly token (GET-only)
curl -H "Authorization: Bearer $READONLY_TOKEN" \
  http://127.0.0.1:2376/volumes
```

## Configuration file

The proxy looks for `config.yaml` in the current working directory, or at the
path specified by the `DOCKER_PROXY_CONFIG` environment variable. If no config
file exists, the proxy runs with all defaults -- no authentication, no rules,
port 2376, auto-detected Docker socket.

Environment variables can be referenced anywhere in the config using
`${VARIABLE_NAME}` syntax. For authentication tokens and secrets, a missing
variable causes the proxy to refuse to start. For other values, unset variables
expand to an empty string.

### Top-level structure

```yaml
global: # optional -- override defaults
auth: # optional -- authentication configuration
rules: # optional -- ordered access control rules
```

### `global`

| Key               | Type     | Default     | Description                                                                                                                               |
| ----------------- | -------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `port`            | `u16`    | `2376`      | TCP port the proxy binds to. Overrides `DOCKER_PROXY_PORT`.                                                                               |
| `bind`            | `string` | `127.0.0.1` | Host/IP to bind. Use `0.0.0.0` only with TLS configured; the proxy logs a loud warning if you bind off-loopback without TLS.              |
| `socket`          | `string` | auto        | Path to the Docker Unix socket. Overrides `DOCKER_SOCKET`.                                                                                |
| `log_level`       | `string` | `info`      | Log level filter (`trace`, `debug`, `info`, `warn`, `error`).                                                                             |
| `log_format`      | `string` | `text`      | `text` for human logs, `json` for structured one-line-per-event output suitable for Loki/Elasticsearch.                                   |
| `audit_log`       | `string` | --          | Path to an append-only JSON audit log of denied / dry-run / auth-failure events. Each line is a self-contained JSON record.               |
| `tls`             | `object` | --          | TLS termination. See below.                                                                                                               |
| `metrics`         | `object` | --          | Prometheus metrics endpoint. See below.                                                                                                   |
| `trusted_proxies` | `array`  | --          | CIDR list of trusted reverse proxies. When the direct peer matches, `client_ip` rules use `X-Forwarded-For`, `X-Real-Ip`, or `Forwarded`. |

#### `global.tls`

When set, the listener is wrapped in rustls (ring backend, TLS 1.2+1.3). Clients must speak HTTPS.

| Key                   | Type     | Description                                                                                                               |
| --------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------- |
| `cert`                | `string` | Path to a PEM-encoded server certificate chain.                                                                           |
| `key`                 | `string` | Path to a PEM-encoded private key (PKCS#8, PKCS#1, or SEC1).                                                              |
| `client_ca`           | `string` | Optional. Path to a PEM bundle of CAs used to verify client certificates. Enables mTLS.                                   |
| `require_client_cert` | `bool`   | When `true`, the TLS handshake fails unless the client presents a valid cert. Defaults to `false` (optional client cert). |

#### `global.metrics`

| Key       | Type     | Description                                                  |
| --------- | -------- | ------------------------------------------------------------ |
| `enabled` | `bool`   | Set `true` to expose the metrics endpoint on the proxy port. |
| `path`    | `string` | URL path the metrics live at. Defaults to `/metrics`.        |

The endpoint emits Prometheus text format (counters + a histogram of upstream latency).

**Counters:**

| Metric                                          | Description                                            |
| ----------------------------------------------- | ------------------------------------------------------ |
| `docker_proxy_requests_total`                   | Total requests received                                |
| `docker_proxy_requests_allowed_total`           | Requests explicitly allowed (past the rule engine)     |
| `docker_proxy_requests_denied_total`            | Requests denied by rule or auth                        |
| `docker_proxy_requests_dry_run_total`           | Requests matched by dry-run rules (allowed but logged) |
| `docker_proxy_auth_failures_total`              | Failed authentication attempts                         |
| `docker_proxy_auth_lockouts_total`              | IP-based auth lockouts triggered                       |
| `docker_proxy_rate_limited_total`               | Requests denied due to rate limiting                   |
| `docker_proxy_upgrade_total`                    | Successful upgrade connections (exec/attach/logs)      |
| `docker_proxy_upstream_errors_total`            | Docker connection or handshake failures                |
| `docker_proxy_upstream_timeouts_total`          | Docker upstream timeouts                               |
| `docker_proxy_body_too_large_total`             | Requests rejected for exceeding 10 MB body limit       |
| `docker_proxy_rule_decisions_total{rule, mode}` | Per-rule deny/dry_run counts                           |

**Histogram:**

`docker_proxy_upstream_latency_ms` with buckets: `5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf`

The metrics endpoint is served after authentication; a valid bearer token or
client certificate is required to access it. Keep the metrics path private and
avoid setting it to a path that overlaps with the Docker API.

### `auth`

Controls how incoming requests are authenticated.

| Key      | Type     | Description                                                                                                                              |
| -------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `type`   | `string` | Auth scheme. `bearer` enforces Bearer token auth. `none` disables auth entirely. `mtls` uses the client TLS certificate as the identity. |
| `secret` | `string` | A shared Bearer token. Authenticated clients receive the `admin` role. Supports env interpolation (`"${MY_SECRET}"`).                    |
| `tokens` | `array`  | Per-token configuration for fine-grained role assignment.                                                                                |
| `mtls`   | `object` | Settings used when `type: mtls`. See below.                                                                                              |

#### `auth.mtls`

When `auth.type` is `mtls`, the client cert subject is consulted to determine the role.

| Key             | Type     | Description                                                                                                                                               |
| --------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cert_role_map` | `array`  | Ordered list of `{cn, role}` entries. The cert's CN and SANs are matched against each entry; `*.example.com` wildcards match one label. First match wins. |
| `default_role`  | `string` | Role assigned when no map entry matches and the cert has no CN.                                                                                           |

If no map entry matches, the request is denied unless `default_role` is set.
The CN is never used as a role automatically; doing so would allow any CA that
issues arbitrary CNs to grant arbitrary roles.

**Fail-closed defaults.** If no auth section is set, or if `tokens: []` is empty, the proxy refuses every request with 401. To run without authentication you must set `auth.type: none` explicitly. A valid `Authorization: Bearer <token>` header is required when any token or secret is configured. The proxy checks tokens first, then falls back to the shared secret. Token-based roles take precedence.

Failed auth attempts are tracked **per source IP** (not per token). 10 failures from the same IP within 60 seconds trigger a 5-minute lockout for that entire IP. This means one misconfigured client behind a NAT can lock out all clients sharing that IP. Successful authentication immediately clears all failure counters for that source.

Each entry under `tokens`:

| Key     | Type     | Description                                         |
| ------- | -------- | --------------------------------------------------- |
| `token` | `string` | The Bearer token value. Supports env interpolation. |
| `role`  | `string` | Role assigned to this token (default: `user`).      |

**Environment variable overrides.** `DOCKER_PROXY_SECRET` overrides `auth.secret`

### `rules`

An ordered list of access control rules. Rules are evaluated in sequence on
every request. **All conditions within a rule must match** (logical AND).
Conditions can be grouped with `and` and `or` for nested logic. The
first matching rule with a terminating action (`deny`, `allow`, `require_role`)
wins. Rules with the `response_filter` action are non-terminating -- they
always accumulate and apply after the Docker response is received.

If no rule matches, the request is allowed.

#### Rule fields

| Key               | Type     | Default  | Description                                                                                                                                                          |
| ----------------- | -------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`            | `string` | required | Human-readable identifier.                                                                                                                                           |
| `description`     | `string` | --       | Optional description of what the rule does.                                                                                                                          |
| `action`          | `string` | required | One of `deny`, `allow`, `require_role`, `response_filter`.                                                                                                           |
| `conditions`      | `array`  | `[]`     | List of conditions. All must evaluate true for the rule to fire.                                                                                                     |
| `message`         | `string` | --       | Custom response body returned when the rule blocks a request.                                                                                                        |
| `status`          | `u16`    | `403`    | HTTP status code for blocked requests.                                                                                                                               |
| `role`            | `string` | `admin`  | Required role for `require_role` action.                                                                                                                             |
| `response_filter` | `array`  | --       | List of filter entries. Used only with `action: response_filter`.                                                                                                    |
| `priority`        | `u32`    | `0`      | Higher priority rules are evaluated first. Rules with equal priority keep their declaration order (stable sort).                                                     |
| `dry_run`         | `bool`   | `false`  | When `true`, a rule that would otherwise deny instead allows the request through and emits an audit-log event tagged `dry_run`. Useful for rolling out new policies. |

#### Conditions

Each condition specifies a `field` to inspect, an `operator` that defines how
to compare, and an optional `value` to compare against.

##### Condition fields

| Field           | Description                                                                                                                                                                      |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `path`          | The request path (e.g. `/containers/json`).                                                                                                                                      |
| `method`        | The HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`).                                                                                                               |
| `client_ip`     | The connecting client's IP address.                                                                                                                                              |
| `header.<name>` | A specific request header. `<name>` is case-insensitive.                                                                                                                         |
| `body.<path>`   | A field within the parsed JSON request body. `<path>` uses dot notation for nested objects (e.g. `HostConfig.Privileged`) and numeric indices for array elements (e.g. `Env.0`). |

##### Condition operators

| Operator       | Applies To         | Description                                                                               |
| -------------- | ------------------ | ----------------------------------------------------------------------------------------- |
| `equals`       | all                | Exact value match. For `body` fields, compares typed values (strings, booleans, numbers). |
| `not_equals`   | all                | Negation of `equals`.                                                                     |
| `contains`     | path, header, body | Substring match.                                                                          |
| `not_contains` | path, header, body | Negation of `contains`.                                                                   |
| `starts_with`  | path, header, body | Prefix match.                                                                             |
| `ends_with`    | path, header       | Suffix match.                                                                             |
| `matches`      | path, header, body | Regex match (Rust regex syntax).                                                          |
| `not_matches`  | path, header       | Negation of `matches`.                                                                    |
| `in`           | all                | Value is present in a YAML list. For `client_ip`, list entries are parsed as CIDR ranges. |
| `not_in`       | all                | Value is absent from a YAML list. CIDR-aware for `client_ip`.                             |
| `exists`       | header, body       | The field exists or is present in the JSON body.                                          |
| `not_exists`   | header, body       | The field is missing or absent from the JSON body.                                        |

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

| Action            | Terminating?        | Description                                                                                                                                                                                                                                                                              |
| ----------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `deny`            | yes                 | Blocks the request immediately with the configured `status` and `message`.                                                                                                                                                                                                               |
| `allow`           | yes                 | Explicitly allows the request, short-circuiting further rule evaluation. Useful for carving out exceptions ordered before broad deny rules.                                                                                                                                              |
| `require_role`    | yes                 | Blocks the request if the authenticated user's role is not `admin` and does not match the rule's required `role`. The `admin` role always passes.                                                                                                                                        |
| `response_filter` | no                  | Allows the request but applies JSON transformations to the Docker response body. Filters from multiple matching rules accumulate. Only applied when the response `content-type` is `application/json`.                                                                                   |
| `rate_limit`      | yes (when exceeded) | Enforces a token-bucket rate limit per client IP. If the bucket has tokens available, the request continues and 1 token is consumed. If the bucket is empty, the request is denied with `status` (default `429`). When the limit is not exceeded, evaluation continues to the next rule. |

##### Response filter entries

Used within the `response_filter` array of a rule.

| Key           | Type     | Description                                                                                                 |
| ------------- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `field`       | `string` | Dot-notation path to the JSON field to modify (e.g. `Config.Env`, `Items.0.Name`). Supports array indices.  |
| `action`      | `string` | `redact` (replace with `***REDACTED***`), `remove` (delete the field), or `replace` (set to `replacement`). |
| `replacement` | `string` | Replacement value for the `replace` action.                                                                 |

Response filters only apply when the Docker response `content-type` is
`application/json`. Non-JSON responses pass through unchanged. Filters are
accumulated from all matching `response_filter` rules but are **not** applied to
upgrade (streaming) connections - `docker exec`, `attach`, and `logs -f`
bypass the response filter pipeline.

**Security note:** If you rely on response filters to hide secrets such as
`Config.Env`, also add a rule that denies `/containers/*/exec` and
`/exec/*/start`, or an attacker can extract the same data through a streaming
exec session.

##### Rate limit config

Used within the `rate_limit` field of a rule with `action: rate_limit`.

| Key        | Type  | Default | Description                                                                                                                                                                       |
| ---------- | ----- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `requests` | `u64` | `50`    | Maximum requests allowed in the window (bucket capacity).                                                                                                                         |
| `period`   | `u64` | `30`    | Window size in seconds. Tokens refill at `requests / period` per second.                                                                                                          |
| `penalty`  | `u64` | `30`    | Cooldown in seconds after hitting the limit. Once the bucket empties, the client is blocked for this many seconds. After the penalty expires, the bucket resets to full capacity. |

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

## Request sanitization

The proxy applies several security transformations to every request path before
rule matching:

- **Percent-decoding**: `%2F` is decoded to `/` before matching.
- **Directory traversal normalization**: `/containers/../secrets` collapses to `/secrets`.
- **Null byte and control character rejection**: paths or query strings containing `\x00`, characters below `0x20`, or `0x7F` return `400 Bad Request`.
- **Trailing slash preservation**: `/containers/` stays as `/containers/` (path matching with `equals` must account for this).

Headers stripped from client requests before forwarding to Docker:

- `authorization`, `host`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`, `x-forwarded-port`, `x-real-ip`, `forwarded`, `via`
- Hop-by-hop headers (`connection`, `keep-alive`, `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `content-length`) are stripped in both directions.

This prevents header injection and IP spoofing through the proxy.

## Request pipeline

Every HTTP request to the proxy opens a **new** Unix socket connection to
Docker with `connection: close` (no connection reuse). The proxy enforces these
limits:

| Limit                  | Value               | Behavior                                          |
| ---------------------- | ------------------- | ------------------------------------------------- |
| Request body           | 10 MB               | Exceeding returns `413 Payload Too Large`         |
| Response body          | 64 MB               | Exceeding returns `502 Bad Gateway`               |
| Concurrent connections | 1,024               | Additional connections are dropped with a warning |
| Path length            | 8,192 bytes         | Longer paths return `400 Bad Request`             |
| Token length           | 4,096 bytes         | Longer tokens are rejected                        |
| Rate-limit buckets     | 16,384 distinct IPs | New IPs beyond this cap are denied                |
| Auth-lockout keys      | 16,384 distinct IPs | New IPs beyond this cap are not tracked           |

| Timeout                  | Value          | Applies to                                 |
| ------------------------ | -------------- | ------------------------------------------ |
| Docker socket connect    | 5 s            | Unix socket connection to Docker           |
| Request body read        | 30 s           | Client sending the request body            |
| Docker upstream response | 300 s (5 min)  | Docker processing and sending the response |
| TLS handshake            | 10 s           | TLS negotiation                            |
| Upgrade resolve          | 30 s           | 101 Switching Protocols handshake          |
| Upgrade idle             | 3,600 s (1 hr) | Streaming connections with no traffic      |

## Streaming (`docker exec`, `attach`, `logs -f`)

Endpoints that upgrade to a raw TCP stream are forwarded transparently. The proxy:

1. Authenticates the request and runs it through the rule engine like any other.
2. Opens a connection to the Docker socket, replays the request with the `Upgrade` header preserved.
3. When Docker responds with `101 Switching Protocols`, the proxy returns 101 to the client and then bidirectionally copies bytes between the two halves until either side closes (or until `UPGRADE_IDLE_TIMEOUT`, currently one hour with no traffic).

`docker -H tcp://proxy:2376 exec -it <container> /bin/sh` works as long as `exec` operations aren't denied by a rule. Add the `block-exec` rule to disable.

## Audit log

If `global.audit_log` is set, the proxy spawns a writer task that appends one JSON record per line for each denied, dry-run, or auth-failure event:

```json
{
  "timestamp": "2026-05-12T19:09:18Z",
  "event": "deny",
  "peer_ip": "10.0.0.5",
  "method": "POST",
  "path": "/containers/create",
  "user_agent": "docker/24.0",
  "user_role": "readonly",
  "identity": null,
  "rule_name": "admin-only-create",
  "rule_action": "require_role",
  "status": 403,
  "dry_run": false,
  "message": "Admin role required to create containers"
}
```

Event types: `deny` (rule blocked), `auth_denied` (auth failure), `dry_run` (would-be deny logged but allowed through).

The writer uses a 4,096-event bounded channel. If the disk falls behind,
events are dropped rather than blocking requests (a warning is logged). Each
event is immediately flushed to disk for crash consistency.

## Hot reload

Send `SIGHUP` to the proxy process and it re-reads the same config file it
started from. The listener is closed and rebound using the new `global.bind`,
`global.port`, and `global.tls` settings, so network and TLS changes take
effect. In-flight connections are dropped during the brief restart window. If
the new file fails to parse, the proxy logs an error and keeps running on the
previous config and listener.

```bash
kill -HUP $(pgrep docker-proxy)
```

Hot reload is Unix-only (Linux and macOS). It requires the proxy to have been
started with an explicit config file path (`--config` or `DOCKER_PROXY_CONFIG`).
Running with defaults does not spawn the reloader.

## CLI

```
docker-proxy [--config <path>] [--check-config]
```

| Flag              | Description                                                                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `--config <path>` | Path to the YAML config (overrides `DOCKER_PROXY_CONFIG`).                                                                            |
| `--check-config`  | Parse the config, print the effective rule set sorted by priority, exit. Returns non-zero if parsing fails. Use in CI before deploys. |
| `--help`, `-h`    | Print usage and exit.                                                                                                                 |

## Logging

Log output is controlled by `global.log_level` (default `info`) and
`global.log_format` (default `text`). Set `log_format: json` for structured
one-line output.

Request log lines include a manually formatted `[MM/DD/YYYY HH:MM:SS]` prefix
and the peer IP, method, path, user agent, and status code. Paths are truncated
to 256 characters and control characters are sanitized.

System events (config reloads, TLS errors, etc.) use the tracing subscriber
without timestamps - only request/response lines carry the manual timestamp.
When shipping logs to Loki or Elasticsearch, attach the collection timestamp
for system events.

## Token security

Token comparison uses constant-time equality to prevent timing side-channel
attacks. Exactly one `Authorization` header is allowed per request; multiple
`Authorization` headers return `401 Malformed authorization`. Tokens longer
than 4,096 bytes are rejected before comparison.

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

When running behind a trusted reverse proxy such as Cloudflare, set
`global.trusted_proxies`:

```yaml
global:
  trusted_proxies:
    - "10.0.0.0/8"
    - "103.21.244.0/22" # example Cloudflare range
```

If the direct peer matches a trusted proxy CIDR, `client_ip` is taken from
`X-Real-Ip`, `X-Forwarded-For`, or `Forwarded` (in that order). For
`X-Forwarded-For`, the rightmost untrusted address is used. If the peer is not
trusted, proxy headers are ignored and the direct peer IP is used.

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
  description: Log image pulls but don't block - yet
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

| Variable              | Description                                                                       | Default             |
| --------------------- | --------------------------------------------------------------------------------- | ------------------- |
| `DOCKER_PROXY_CONFIG` | Path to the YAML configuration file.                                              | `./config.yaml`     |
| `DOCKER_PROXY_SECRET` | Shared Bearer token. Overrides `auth.secret` (unless `auth.type: none`).          | (none)              |
| `DOCKER_PROXY_PORT`   | TCP listen port. Overridden by `global.port` if set.                              | `2376`              |
| `DOCKER_SOCKET`       | Path to the Docker Unix socket. Overridden by `global.socket` if the path exists. | auto-detected       |
| `RUST_LOG`            | Tracing log filter. Overrides `global.log_level`.                                 | `docker_proxy=info` |

Socket auto-detection order:

- macOS: `~/.docker/run/docker.sock`, `/var/run/docker.sock`, `~/.docker/desktop/docker.sock`
- Linux: `/var/run/docker.sock`, `/run/docker.sock`

**Override precedence** (highest to lowest):

1. CLI `--config <path>` - sets `DOCKER_PROXY_CONFIG`
2. `DOCKER_PROXY_PORT` / `DOCKER_SOCKET` / `DOCKER_PROXY_SECRET` env vars
3. `${ENV_VAR}` interpolation in YAML values
4. YAML file values
5. `RUST_LOG` - overrides `global.log_level`
6. Built-in defaults

## Scripts

| Script      | Purpose                                                                                   |
| ----------- | ----------------------------------------------------------------------------------------- |
| `setup`     | Download binary, generate config, install service. Detects OS/arch.                       |
| `build`     | Cross-compile for all 4 targets (linux x86_64, linux aarch64, macos x86_64, macos arm64). |
| `update`    | Publish built binaries as a GitHub release. Bumps version automatically.                  |
| `uninstall` | Stop and remove the service, binary, and config directory (with confirmation).            |

The `build` and `update` scripts are the **manual / offline** path. The normal
release path is fully automated - see [Releasing](#releasing).

```bash
./build                    # compiles all 4 targets into release/
./update                   # prompts for version, creates GitHub release
```

Requires `cargo-zigbuild`, `zig`, and `gh` CLI authenticated.

## Continuous integration

Two GitHub Actions workflows live in `.github/workflows/`:

| Workflow      | Trigger                                     | What it does                                                                                                                                                                                                                                                                                |
| ------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ci.yml`      | push / PR to `main` or `canary`             | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, bash script syntax checks, a cross-compile build matrix, and an end-to-end `api_e2e` job that runs the proxy against the runner's real Docker socket and asserts auth + a deny rule + the metrics endpoint behave correctly. |
| `release.yml` | push of a `v*.*.*` tag (or manual dispatch) | Cross-compiles all 4 targets, generates `SHA256SUMS`, optionally GPG-signs, and publishes a GitHub Release with the assets - the same artifact layout `setup` expects.                                                                                                                      |

## Releasing

Releases are automated. To cut one, tag a commit and push the tag:

```bash
git tag v1.0.1
git push origin v1.0.1
```

`release.yml` then builds every target, checksums them, optionally signs, and
publishes the release. No local toolchain, no `gh` login, no running `./build`
or `./update` by hand.

**Repository secrets:**

| Secret            | Required? | Purpose                                                                |
| ----------------- | --------- | ---------------------------------------------------------------------- |
| `GITHUB_TOKEN`    | automatic | Provided by Actions; used to create the release. Nothing to configure. |
| `GPG_PRIVATE_KEY` | optional  | ASCII-armored private key. When set, the pipeline signs `SHA256SUMS`.  |
| `GPG_PASSPHRASE`  | optional  | Passphrase for that key.                                               |

Leave the GPG secrets unset for a frictionless, checksum-only install (the
recommended default). The manual `./build` + `./update` scripts remain available
for local or offline releases.

## systemd service

The setup script asks if you want to install and start a systemd service on
Linux. The service:

- Starts after Docker and the network are ready
- Restarts automatically on failure
- Uses the config at `/etc/docker-proxy/config.yaml`
- Runs as `root:docker` with restricted system access

### Manual service setup

Download and install the unit file yourself:

```bash
curl -fsSL https://raw.githubusercontent.com/Nemu-Bridge/docker-proxy/main/docker-proxy.service \
  -o /etc/systemd/system/docker-proxy.service

systemctl daemon-reload
systemctl enable docker-proxy
systemctl start docker-proxy
systemctl status docker-proxy
```

Check the logs:

```bash
journalctl -u docker-proxy -f
```

## Interactive setup (TUI)

Generate a `config.yaml` interactively using the TUI wizard:

```bash
cargo run --bin docker-proxy-setup
```

The wizard is a separate binary (`docker-proxy-setup`). It walks through:

- Port and socket configuration
- Authentication (none, shared secret, or per-token roles)
- 15 built-in rule templates:
  1. Block exec operations
  2. Block docker build
  3. Readonly volumes
  4. Readonly networks
  5. Readonly images
  6. Block secrets
  7. Block configs
  8. Block privileged containers
  9. Block bind mounts
  10. Block host network mode
  11. Admin-only container lifecycle
  12. Admin-only create containers
  13. Admin-only delete resources
  14. Internal network only (CIDR whitelist)
  15. Redact container environment variables from inspect
  16. Rate limit all requests
- Custom rule builder with all 5 actions, configurable status codes, multiple
  conditions, rate limit parameters, and response filter values

## Build

```bash
cargo build --release
```

The binary is at `target/release/docker-proxy`.

## Dependencies

| Crate                            | Purpose                                        |
| -------------------------------- | ---------------------------------------------- |
| `tokio`                          | Async runtime                                  |
| `hyper` + `hyper-util`           | HTTP server and client (Unix socket transport) |
| `http-body-util`                 | Request/response body utilities                |
| `tracing` + `tracing-subscriber` | Structured logging                             |
| `serde` + `serde_yaml`           | YAML config parsing                            |
| `serde_json`                     | JSON body inspection and response filtering    |
| `regex`                          | Pattern matching in rule conditions            |
| `ipnet`                          | CIDR matching for IP-based rules               |
| `chrono`                         | Request log timestamps                         |
