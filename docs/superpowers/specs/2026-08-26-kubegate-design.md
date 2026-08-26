# kubegate — credential-injecting Kubernetes API proxy

**Date:** 2026-08-26
**Status:** Design approved, pending implementation plan

## 1. Problem

A developer VM (a Lima guest) needs to talk to Kubernetes clusters, but must not
hold cluster credentials. Today the guest carries a copy of `~/.kube/config`,
which means every process in the VM — including AI agents running there — holds
the developer's full cluster identity. Credentials also expire constantly,
because the host's kubeconfig authenticates through exec plugins (`aws eks
get-token`, `gcloud`, corporate SSO) that cannot be meaningfully copied into a
VM anyway.

`kubegate` runs on the **host**, holds the real credentials, and exposes a
credential-injecting proxy to the **guest**. The guest's kubeconfig contains no
cluster credential — only a proxy-scoped bearer token and a pinned CA.

### Goals

- No cluster credential of any kind exists inside the VM.
- The target cluster is chosen on the host and is not selectable by the client.
- Three capability tiers, each enforced by the proxy: read-only without secrets,
  read-only with secrets, read-write.
- Standard `kubectl` and client-go tooling work in the guest unmodified.
- Every request is authorized and audited.

### Non-goals

- Multi-tenancy. One proxy process serves one context in one mode.
- Replacing cluster RBAC. `kubegate` can only ever narrow what the host identity
  is already permitted to do.
- Interactive session forwarding (`exec`, `attach`, `port-forward`). Explicitly
  refused in all modes; see §6.3.
- High availability, horizontal scaling, or serving more than a handful of
  clients.

## 2. Threat model

**The VM is untrusted.** Anything running in the guest — a compromised
dependency, a runaway agent, a process the developer did not start — may issue
arbitrary requests to the proxy. The proxy's mode is therefore the *ceiling* of
what the entire VM can do, not a hint.

Consequences that drive the design:

1. **Deny by default in the strict mode.** An unrecognized resource in
   `ro-nosecret` is denied, not passed through. New CRDs from a secret-manager
   operator must not become readable because nobody updated a denylist.
2. **Never fail open.** A parse error, a redaction failure, or an internal error
   produces an error response, never an unfiltered one.
3. **No path to the upstream transport that bypasses policy.** Credentials are
   injected in the transport, at the last step, after every check has passed.
4. **Escaping the proxy is worse than escalating inside it.** A caller that can
   mint a cluster credential (`serviceaccounts/token`, CSR approval) can talk to
   the apiserver directly, with no policy and no audit trail. Those paths are
   denied even in `rw`.
5. **The bearer token is the entire capability**, so it never crosses the network
   in plaintext (§8.3).

### Accepted residual risks

These are conscious trade-offs, documented so they are not mistaken for
oversights:

- **`pods/log` is readable in `ro-nosecret`.** An application that logs its own
  credentials will leak them. The mode's guarantee is therefore precisely: *no
  Secret objects, and no secret material in the manifest fields we redact* — not
  "no secret material ever". Logs were judged indispensable for the mode to have
  any diagnostic value.
- **`rw` permits RBAC writes.** A caller in `rw` can grant itself any permission
  the proxy will forward. This is bounded, not unbounded: with credential minting
  and interactive subresources denied, every resulting action still flows through
  `kubegate`, where it is filtered and logged.
- **Legacy service-account-token Secrets.** On clusters where the legacy token
  controller still populates Secrets of type
  `kubernetes.io/service-account-token`, a caller in `rw` could create such a
  Secret and read a real token from it. Closing this requires request-body
  inspection on Secret writes, which was deliberately left out of v1. It does not
  affect either read-only mode.
- **Whole-VM capability.** The token is provisioned into the guest, so every
  process in the guest shares the mode. Per-process authorization is out of
  scope.

## 3. Architecture

### 3.1 Topology

```
┌───────────────────────── host (macOS) ──────────────────────────┐
│  ~/.kube/config  ──►  kubegate serve                            │
│  (exec plugins,        --context prod-eks                       │
│   client certs)        --mode ro-nosecret                       │
│                        --listen 192.168.5.2:8443                │
└──────────────────────────────┬──────────────────────────────────┘
                               │ HTTPS, self-signed cert
                               │ Authorization: Bearer <proxy token>
┌──────────────────────────────┴──────────────────────────────────┐
│  Lima guest — kubeconfig holds ONLY:                            │
│    server: https://192.168.5.2:8443                             │
│    certificate-authority-data: <kubegate CA>                    │
│    token: <proxy token>                                         │
│  No cluster credential. No context selection.                   │
└─────────────────────────────────────────────────────────────────┘
                               │
                    kubegate ──┴──►  real kube-apiserver
                    (host credentials injected here)
```

### 3.2 Process shape

One process per `(context, mode)` pair. Both are fixed at startup and immutable
for the process lifetime. There is no admin API, no config reload, and no way for
a client to change either. Running against a second cluster or in a second mode
means starting a second process on a different port.

This is the single largest simplification in the design: the policy engine never
has to ask "which mode is this request in", and the blast radius of any given
process is legible from its command line.

### 3.3 CLI

```
kubegate serve \
  --context prod-eks \                  # required; immutable
  --mode ro-nosecret|ro-secret|rw \     # required; immutable
  --listen 192.168.5.2:8443 \           # required; VM-facing address
  --namespace foo,bar \                 # optional; empty = cluster-wide
  --policy extra-rules.yaml \           # optional; extends ro-nosecret only
  --kubeconfig ~/.kube/config \         # default: $KUBECONFIG, then ~/.kube/config
  --tls-dir ~/.kubegate \               # cert + key persisted here
  --token-file ~/.kubegate/token \      # persisted; survives restarts
  --rotate-token \                      # discard and regenerate the token
  --tls-san extra.host.name \           # repeatable; added to cert SANs
  --audit-log ~/.kubegate/audit.jsonl   # default: stderr
```

There is no flag governing `pods/log`: it is unconditionally in the `ro-nosecret`
allowlist (§2, residual risks). If logs are later moved behind a gate,
`--allow-logs` is the intended spelling.

On startup, after validating credentials (§9), the proxy prints to stderr: the
server URL, the CA in PEM, the token, and a complete kubeconfig snippet ready to
paste into the guest. Nothing is written to any shared or guest-visible location.

### 3.4 Packages

| Package | Responsibility | HTTP-aware |
|---|---|---|
| `cmd/kubegate` | Flag parsing, wiring, startup validation | – |
| `internal/upstream` | kubeconfig + context → `*rest.Config` → `http.RoundTripper` | yes |
| `internal/authn` | Constant-time bearer compare; inbound header scrubbing | yes |
| `internal/reqinfo` | Wrapper over apiserver's `RequestInfoFactory` | yes |
| `internal/policy` | Rule types, matcher, mode rule sets, namespace scope | **no** |
| `internal/redact` | Streaming JSON transform of response bodies | no |
| `internal/discovery` | Filters discovery documents to the mode's allowlist | no |
| `internal/audit` | Structured one-line-per-request log | no |
| `internal/server` | TLS, reverse proxy, middleware chain, shutdown | yes |

`internal/policy` and `internal/redact` are pure and take no dependency on
`net/http`. That is what makes exhaustive table-driven testing cheap, and it is
where nearly all of the security-relevant logic lives.

### 3.5 Module and dependencies

Module path `github.com/anantadwi13/kubegate`, Go 1.26. Single static binary, no
cgo. Built and tested on `linux/arm64` and `darwin/arm64`; the proxy runs on the
host, so `darwin` is the primary target and `linux` is what CI and the Lima guest
use.

- `k8s.io/client-go` — kubeconfig loading, `rest.Config`, `rest.TransportFor`.
  Exec-plugin invocation, token caching, and refresh come free.
- `k8s.io/apiserver/pkg/endpoints/request` — `RequestInfoFactory`, the
  apiserver's own request parser.
- `k8s.io/apimachinery` — `metav1.Status`, `metav1.Table`, unstructured decoding.
- `sigs.k8s.io/controller-runtime/pkg/envtest` — integration tests only.

Hand-rolling Kubernetes URL parsing was explicitly rejected. The legacy
`/api/v1/watch/...` prefix, subresource-versus-name ambiguity, groupless `/api`
versus grouped `/apis`, and non-resource paths are exactly where an authorization
bypass hides. `RequestInfoFactory` is the code the apiserver itself trusts for
this.

## 4. Request lifecycle

```
client request (HTTPS + Bearer)
  │
  1. TLS terminate
  2. reject if Connection: Upgrade present            → 403
  3. authn: constant-time token compare               → 401 on mismatch
     scrub Authorization, Impersonate-*, X-Remote-*   (never forwarded)
  4. reqinfo: parse → {verb, group, version, resource,
                       subresource, namespace, name,
                       isResourceRequest}
  5. non-resource request?
        → non-resource policy (§6.5)                  → 403 unless allowlisted
  6. universal denylist (§6.3)                        → 403
  7. mode policy (§6.4)                               → 403 on deny
  8. namespace scope (§6.6)                           → 403 on out-of-scope
  9. rewrite URL scheme+host → upstream
     if mode == ro-nosecret: force JSON in Accept (§7.3)
 10. forward via client-go transport
     ── host credentials injected HERE and nowhere else
 11. response:
        discovery path  → filter (§6.7)
        ro-nosecret     → redact stream (§7)
 12. audit line
```

Steps 6–8 are ordered cheapest-first and each can only ever *deny*; none can
re-permit something an earlier step rejected.

**Streaming.** `FlushInterval = -1` on the reverse proxy so `watch` and `logs
--follow` stream rather than buffer. Requests whose parsed verb is `watch`, or
which target `pods/log` with `follow=true`, get no response deadline; all others
get one.

## 5. Rule model

Rules are RBAC-shaped:

```yaml
- apiGroups: ["", "apps"]      # "" is the core group
  resources: ["pods", "pods/log", "deployments"]
  verbs: ["get", "list", "watch"]
```

Matcher semantics, deliberately mirroring Kubernetes RBAC:

- `*` matches any value within its field.
- Subresources are named as `resource/subresource`.
- **A rule for `pods` does not grant `pods/log`, `pods/exec`, or any other
  subresource.** Subresources must be named explicitly.

That last property is the reason to mirror RBAC rather than invent a scheme: it
makes subresource handling fail-safe by construction instead of by vigilance.

A rule set is evaluated as either an **allowlist** (deny unless some rule
matches) or a **denylist** (allow unless some rule matches). Each mode composes
these differently.

## 6. Policy

### 6.1 Mode summary

| Mode | Verbs | Resource policy | Redaction |
|---|---|---|---|
| `ro-nosecret` | `get, list, watch` | curated **allowlist**, fail closed | on |
| `ro-secret` | `get, list, watch` | **denylist** | off |
| `rw` | all | **denylist** | off |

### 6.2 Why the strict mode fails closed and the others do not

`ro-nosecret` is the only mode that makes a promise about *content*. A denylist
cannot keep that promise, because the set of resources holding secret material is
open-ended: `ExternalSecret`, `SealedSecret`, `VaultStaticSecret`,
`ClusterSecretStore`, and whatever an operator installs next week. Fail-closed is
the only way the promise survives a cluster gaining a CRD.

The other two modes already concede secret access, so a denylist costs nothing
there and avoids blocking legitimate work on every unrecognized CRD.

### 6.3 Universal denylist — all modes, not overridable

Denied regardless of mode, and not grantable through `--policy`:

- Any `*/exec`, `*/attach`, `*/portforward`, or `*/proxy` subresource. This
  covers `pods/exec`, `pods/attach`, `pods/portforward`, `pods/proxy`,
  `services/proxy`, and `nodes/proxy`.
- `serviceaccounts/token`.
- **Write verbs** (`create`, `update`, `patch`, `delete`, `deletecollection`) on
  `certificatesigningrequests`, and **all verbs** on
  `certificatesigningrequests/approval` and `certificatesigningrequests/status`.
- Any request carrying `Connection: Upgrade`, rejected at step 2 before parsing.

Note that CSRs remain **readable** wherever the mode otherwise permits reads.
Reading a CSR yields the request and, if issued, the signed certificate — but
never the private key, which the apiserver never holds. Minting is the danger, not
inspection, so only the write paths are closed.

Because interactive subresources are denied everywhere, `kubegate` never
implements SPDY or WebSocket protocol upgrade forwarding at all. A whole class of
proxying bugs is designed out rather than guarded against.

### 6.3.1 Monotonicity invariant

The modes form a strict ladder:

```
ro-nosecret  ⊆  ro-secret  ⊆  rw
```

Anything permitted by a stricter mode must be permitted by a looser one. This is
not decoration — it is what makes the modes comprehensible, and it is easy to
break by accident (an earlier draft of this spec denied `certificatesigningrequests`
outright in `rw`, which made `kubectl get csr` fail in read-write while succeeding
in read-only). §12.1 asserts the invariant as a property test rather than trusting
review to catch it.

### 6.4 Mode rule sets

#### `ro-nosecret` — allowlist

Verb gate: `get`, `list`, `watch`. Then:

| Group | Resources |
|---|---|
| core `""` | `pods`, `pods/status`, `pods/log`, `services`, `endpoints`, `configmaps`, `namespaces`, `nodes`, `nodes/status`, `events`, `persistentvolumes`, `persistentvolumeclaims`, `replicationcontrollers`, `serviceaccounts`, `limitranges`, `resourcequotas` |
| `apps` | `deployments`, `deployments/status`, `replicasets`, `statefulsets`, `daemonsets`, `controllerrevisions` |
| `batch` | `jobs`, `cronjobs` |
| `networking.k8s.io` | `ingresses`, `ingressclasses`, `networkpolicies` |
| `discovery.k8s.io` | `endpointslices` |
| `events.k8s.io` | `events` |
| `autoscaling` | `horizontalpodautoscalers` |
| `policy` | `poddisruptionbudgets` |
| `storage.k8s.io` | `storageclasses`, `csidrivers`, `csinodes`, `volumeattachments` |
| `scheduling.k8s.io` | `priorityclasses` |
| `node.k8s.io` | `runtimeclasses` |
| `coordination.k8s.io` | `leases` |
| `metrics.k8s.io` | `pods`, `nodes` (so `kubectl top` works) |
| `apiextensions.k8s.io` | `customresourcedefinitions` — the *schemas*, never instances |

Both `events` groups are listed because Kubernetes has two: `kubectl describe`
reads the core one, `kubectl events` reads `events.k8s.io`. Omitting either makes
`describe` lose its event footer, which is where most of its diagnostic value is.

Deliberately absent, and denied by the fail-closed default: `secrets`, all of
`rbac.authorization.k8s.io`, `certificates.k8s.io`,
`admissionregistration.k8s.io`, the `*Review` authorization APIs, and every CRD
instance until opted in.

The organizing principle for what is in: **workload observability, not security
posture.** RBAC bindings, CSRs, and admission webhooks tell you how the cluster is
secured and who can do what — useful to an attacker mapping the environment,
rarely needed to find out why a Deployment is crashlooping. They stay out even
though none of them contains a secret. This does not violate §6.3.1: monotonicity
requires the stricter mode to permit *no more* than the looser one, not the same.

A consequence worth knowing: `kubectl auth can-i` uses a `create` on
`selfsubjectaccessreviews`, so it does not work in either read-only mode. That is
correct behavior — the answer it would give describes the *host* identity, not the
caller's actual capability, so it would be actively misleading.

#### `ro-secret` — denylist

Verb gate: `get`, `list`, `watch`. Denied: the universal denylist only.
Everything else is permitted, `secrets` and RBAC objects included.

#### `rw` — denylist

All verbs. Denied: the universal denylist (§6.3) and nothing further.

The credential-minting paths — `serviceaccounts/token` and the CSR write and
approval paths — live in the universal denylist precisely because they matter most
here. They mint credentials usable *outside* the proxy, which is a boundary escape
rather than an escalation (§2). Everything else is permitted, including RBAC
writes.

### 6.5 Non-resource paths

Allowed in all modes — `kubectl` is unusable without them:

`/version`, `/api`, `/api/v1`, `/apis`, `/apis/<group>`,
`/apis/<group>/<version>`, `/openapi/v2`, `/openapi/v3`, `/openapi/v3/*`

Everything else is denied, notably `/logs`, `/debug/*`, `/metrics`, `/healthz`,
`/readyz`, `/livez`, `/.well-known/openid-configuration`, and `/openid/v1/jwks`.

OpenAPI documents pass through unfiltered in every mode. They leak the *names* of
types, never instance data, and `kubectl explain` and `apply` need them intact.
Filtering them is not worth the fidelity risk.

### 6.6 Namespace scope

When `--namespace` is set:

- Namespaced requests must target a listed namespace.
- **Cluster-wide collection requests are denied**, not fanned out. `GET
  /api/v1/pods` returns 403 with a message telling the caller to name a
  namespace. Fanning out would mean synthesizing list responses and merging watch
  streams, with resource-version semantics we cannot honestly reproduce.
- Cluster-scoped resources permitted by the mode remain readable. `--namespace`
  narrows namespaced access; it does not imply "nothing cluster-scoped".

When `--namespace` is unset — the default — **no namespace constraint applies at
all**. Cluster-wide collection requests such as `GET /api/v1/pods` (`kubectl get
pods -A`) are permitted, subject only to the mode's verb gate and resource rules.
Namespace scope is strictly opt-in: the denial above is a consequence of asking
for scoping, never the default posture.

### 6.7 Discovery filtering

In `ro-nosecret` only, `APIResourceList` responses are rewritten to contain just
the allowlisted resources, and `APIGroupList` to just the groups retaining at
least one resource. `kubectl api-resources` then shows exactly what works, which
turns a confusing 403 into an absence.

The other two modes pass discovery through untouched.

### 6.8 The `--policy` extension file

`--policy` extends the `ro-nosecret` allowlist — typically to admit an
application's own CRDs. Passing it together with `--mode ro-secret` or `--mode rw`
is a **startup error**, not a silent no-op: those modes have no allowlist to
extend, and quietly ignoring the flag would let someone believe they had
constrained a proxy that is in fact wide open.

```yaml
# extends the ro-nosecret allowlist; cannot subtract from it
rules:
  - apiGroups: ["example.com"]
    resources: ["widgets", "widgets/status"]
    verbs: ["get", "list", "watch"]
```

Validated at load; **any violation is a startup failure, not a warning**, so a
malformed policy can never quietly widen access:

- `apiGroups` and `resources` must be literal. `*` is rejected — a wildcard would
  defeat the fail-closed property that is the entire point of the mode.
- `verbs` may only be `get`, `list`, or `watch`, matching the mode's verb gate.
- No rule may name `secrets`, any resource in `rbac.authorization.k8s.io`, or
  anything on the universal denylist (§6.3).

The file can only ever add resources to a single mode's allowlist. It cannot
change the verb gate, disable redaction, widen namespace scope, or override the
universal denylist.

## 7. Redaction (`ro-nosecret` only)

### 7.1 What is stripped

- `data` and `stringData`, on every kind **except `ConfigMap`**. A ConfigMap's
  `data` is the entire reason to read one; stripping it would gut an allowed
  resource. `Secret` is already denied by the allowlist, so this is
  defense-in-depth against secret-shaped fields on other kinds.
- The `kubectl.kubernetes.io/last-applied-configuration` annotation. This is the
  load-bearing redaction: it routinely embeds the full submitted manifest,
  including literal `env` values, on objects the mode legitimately allows.

`env[].value` is **not** stripped, per an explicit decision: it catches accidental
leaks without mangling pod specs that clients read for legitimate reasons. A
password typed directly into a manifest's `env` remains visible. This is the
sharpest edge of the mode and is stated plainly in §2.

### 7.2 Where it applies

- Single objects.
- `List` responses — every element of `items`.
- Watch streams — every frame's `object`, transformed independently as frames
  arrive, without buffering the stream.
- `metav1.Table` responses — the embedded `object` of every row.

### 7.3 Content negotiation

In `ro-nosecret`, `application/vnd.kubernetes.protobuf` is stripped from the
inbound `Accept` header before forwarding, forcing a JSON-family response.
Redacting protobuf bodies would require the full scheme and is not worth it. If a
client accepts *only* protobuf, the proxy returns `406 Not Acceptable` with a
`metav1.Status` explaining why. `kubectl` is unaffected — it uses JSON, including
for its `as=Table` requests.

### 7.4 Failure behavior

If a response body cannot be parsed as expected, the proxy **aborts the response
with 500** and logs it. It never forwards bytes it could not transform. For an
already-streaming watch, the connection is closed. Failing open here would
silently void the mode's guarantee.

## 8. Credentials, TLS, and tokens

### 8.1 Upstream credentials

`clientcmd` loads the kubeconfig and selects `--context`; `rest.TransportFor`
builds the `RoundTripper`. This gives exec-plugin invocation, bearer tokens,
client certificates, token file reloading, refresh-before-expiry, `proxy-url`,
and TLS/SNI configuration without writing any of it.

The proxy never reads, logs, or echoes credential material. It holds a
`RoundTripper`, not a token.

### 8.2 Listener TLS

On first run the proxy generates a self-signed certificate and key into
`--tls-dir` with mode `0600`, and reuses them afterwards. SANs are the
`--listen` IP or host, plus any `--tls-san` values. The CA is printed in PEM at
startup for pinning as `certificate-authority-data` in the guest.

Pinning matters: without it, anything on the shared network segment can present
its own certificate, harvest the bearer token, and hold the whole capability.

The `--tls-dir` directory is created `0700`, the key and certificate files `0600`.

**HTTP/2 is disabled on the listener** (`TLSNextProtos: ["http/1.1"]`). Two
reasons. First, `Connection: Upgrade` does not exist in HTTP/2 — RFC 8441 tunnels
WebSocket through extended `CONNECT` instead — so the step-2 header check is
simply inapplicable there, and a defense-in-depth layer that silently stops
applying is worse than none. Second, HTTP/1.1 keeps the proxying model small, and
`kubectl` works over it without complaint.

To be explicit about which check is load-bearing: **the `*/exec`, `*/attach`,
`*/portforward`, `*/proxy` subresource denial in §6.3 is authoritative.** The
`Connection: Upgrade` rejection is a cheap outer guard that fails fast; it is not
what makes interactive access impossible.

### 8.3 Proxy token

32 bytes from `crypto/rand`, base64url-encoded, persisted to `--token-file` at
`0600` so restarts do not invalidate the guest's kubeconfig. `--rotate-token`
regenerates it. Comparison is `crypto/subtle.ConstantTimeCompare`.

The token is proxy-scoped: it authorizes nothing but this process, in this mode,
against this context, and revoking it is deleting a file.

### 8.4 Inbound header scrubbing

`Authorization`, `Impersonate-User`, `Impersonate-Group`, `Impersonate-Uid`,
`Impersonate-Extra-*`, and `X-Remote-*` are removed from every request after
authentication and are never forwarded. A client that sets them is not rejected —
they are simply erased, so impersonation cannot be smuggled through even if the
host identity is permitted to impersonate.

## 9. Error handling

**The governing rule: never fail open.**

| Situation | Response |
|---|---|
| Policy denial | `403` + `metav1.Status` naming resource and mode |
| Missing or bad token | `401` + `metav1.Status` |
| Protobuf-only `Accept` in `ro-nosecret` | `406` + `metav1.Status` |
| Host credentials unavailable or expired | `503`, message: *host credentials unavailable for context `X`; re-run your login on the host* |
| Upstream unreachable | `502` |
| Upstream timeout (non-streaming) | `504` |
| Redaction or parse failure | `500`, response aborted |
| Write body over cap in `rw` | `413` |

Denial messages name the resource and the mode but never the upstream URL or any
credential detail. `kubectl` renders them as
`Error from server (Forbidden): pods is forbidden: denied by kubegate policy (mode=ro-nosecret)`.

**Startup validation.** Before binding the listener, the proxy issues `GET
/version` upstream, using the upstream transport directly — this is the proxy's
own client call and does not traverse the middleware chain, since there is no
inbound request to authorize. Expired SSO is the most common real-world failure,
and it should surface when the developer starts the proxy on the host, not when
the guest runs its first command.

**Body cap.** Request bodies are capped at 8 MiB in **every** mode — comfortably
above real manifests and below what would let a guest exhaust host memory. The cap
is not conditional on the mode: the read-only modes permit no body-bearing verbs,
so a body arriving there is already anomalous and should be truncated rather than
buffered.

**Shutdown.** SIGINT/SIGTERM stops accepting, drains in-flight non-streaming
requests, and closes streaming connections after a grace period.

## 10. Audit log

One JSON object per line, to `--audit-log` or stderr:

```json
{"ts":"2026-08-26T10:00:00Z","remote":"192.168.5.15:51234","method":"GET",
 "path":"/api/v1/namespaces/app/secrets","verb":"list","group":"","version":"v1",
 "resource":"secrets","subresource":"","namespace":"app","name":"",
 "decision":"deny","reason":"resource not in ro-nosecret allowlist",
 "mode":"ro-nosecret","context":"prod-eks","status":403,"bytes":142,
 "duration_ms":1,"redacted":false}
```

Never logged: the token, request bodies, response bodies. Denials are logged at a
level that surfaces by default — they are the interesting events.

## 11. Guest setup

The startup banner prints a paste-ready kubeconfig:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: kubegate
    cluster:
      server: https://192.168.5.2:8443
      certificate-authority-data: <base64 CA>
users:
  - name: kubegate
    user:
      token: <proxy token>
contexts:
  - name: kubegate
    context: {cluster: kubegate, user: kubegate}
current-context: kubegate
```

No cluster credential appears anywhere in it, and there is exactly one cluster
entry, so the guest cannot address anything else.

## 12. Testing strategy

Three layers. TDD order follows the dependency graph: policy matcher → `reqinfo`
→ redaction → server wiring → integration → e2e.

### 12.1 Unit tests

**`internal/policy` is the heart of the project.** It is pure, so exhaustiveness
is nearly free, and it is where a bypass would hide. Table-driven over
`(mode, method, path, query) → allow | deny`, including these adversarial rows:

```
/api/v1/watch/secrets                                legacy watch prefix
/api/v1/namespaces/x/pods/y/exec                     subresource escape
/api/v1/namespaces/x/pods/y/attach
/api/v1/namespaces/x/pods/y/portforward
/api/v1/namespaces/x/pods/y/proxy/foo
/api/v1/namespaces/x/services/y/proxy/foo
/api/v1/nodes/n/proxy/foo
//api/v1//secrets                                    double slashes
/api/v1/namespaces/x/secrets/na%2Fme                 percent-encoded separator
/api/v1/pods?watch=true                              vs. the /watch/ form
/api/v1/namespaces/x/serviceaccounts/y/token         POST — rw escape
.../certificatesigningrequests/c/approval            PUT  — rw escape → deny
.../certificatesigningrequests                       GET  — deny in ro-nosecret (not
                                                            in allowlist), allow in
                                                            ro-secret and rw
.../certificatesigningrequests                       POST — mint → deny (all modes)
/apis/external-secrets.io/v1beta1/externalsecrets    unknown secret CRD → deny
/apis/bitnami.com/v1alpha1/sealedsecrets             unknown secret CRD → deny
/apis/example.com/v1/widgets                         unknown CRD       → deny
/apis/rbac.authorization.k8s.io/v1/clusterrolebindings
/api/v1/pods                                         cluster-wide, --namespace set   → deny
/api/v1/pods                                         cluster-wide, no --namespace    → allow
/api/v1/namespaces/other/pods                        namespace mismatch              → deny
/api/v1/namespaces/other/pods                        no --namespace                  → allow
/logs  /debug/pprof/  /metrics  /openapi/v3          non-resource paths
HEAD, OPTIONS                                        unusual methods
```

**`internal/redact`**: `Secret.data` stripped; **`ConfigMap.data` preserved**
(the regression most likely to be introduced); last-applied annotation stripped
from a Deployment; `env[].value` retained; `List` bodies; newline-delimited watch
frames transformed without buffering; `Table` row objects; malformed JSON
produces an error rather than passthrough.

**`internal/authn`**: `Impersonate-*`, `X-Remote-*`, and client `Authorization`
absent from the forwarded request.

**Monotonicity property test** (§6.3.1). Over the cross product of every group,
resource, subresource, and verb appearing anywhere in any rule set — plus a
generated set of unknown ones — assert:

```
allow(ro-nosecret, r) ⟹ allow(ro-secret, r) ⟹ allow(rw, r)
```

This is cheap because the policy is pure, and it catches the class of mistake that
review misses: a denial added to one mode that should have gone in the universal
denylist, or vice versa.

### 12.2 Integration tests — `envtest`

Real apiserver and etcd binaries, no cluster. Fast, hermetic, and able to cover
what k3d cannot conveniently reach:

- The full middleware chain against a real apiserver's URL shapes and discovery.
- **Exec-plugin credential path**, which k3d's static kubeconfig does not
  exercise. A shell script emits envtest's admin credentials as an
  `ExecCredential` — using `clientCertificateData`/`clientKeyData` rather than a
  bearer token, since envtest's service-account token support varies by version
  and we do not want the test's validity to depend on it. A short
  `expirationTimestamp` plus a script that records its invocations proves
  `kubegate` calls the plugin and refreshes on expiry.
- Discovery filtering, by installing a CRD and asserting it is absent from
  `ro-nosecret` discovery output and present in `ro-secret`.

### 12.3 End-to-end tests — k3d

A real cluster and a real `kubectl`, driven through the proxy. This is the layer
that proves the promises in a way unit tests cannot.

**Harness.** `test/e2e`, guarded by build tag `e2e` and skipped unless
`KUBEGATE_E2E=1`, since it requires Docker.

```
k3d cluster create kubegate-e2e --agents 1 --image rancher/k3s:v1.31.14-k3s1
```

k3d v5.5.0 defaults to k3s v1.26.4, which is old enough to miss current API
shapes, so the image is pinned explicitly. `v1.31.14-k3s1` is verified to exist
with an `arm64` manifest. The k3d-written kubeconfig is the
*host* kubeconfig; the proxy binds `127.0.0.1` (the VM-facing interface is not
needed to test policy).

**Fixtures**, seeded before the modes run:

- namespaces `app` and `other`
- a `Secret` and a `ConfigMap` in each
- a `Deployment` created with `kubectl apply` — so a real
  `last-applied-configuration` annotation exists — carrying a literal `env` value
- a dummy CRD `widgets.example.com` plus one instance, standing in for a
  secret-bearing operator CRD

**Assertion matrix.** For each mode, a fresh proxy process and a generated guest
kubeconfig, driving the real `kubectl`:

| Check | `ro-nosecret` | `ro-secret` | `rw` |
|---|---|---|---|
| `get pods` | ✅ | ✅ | ✅ |
| `get configmap -o yaml` → `data` present | ✅ | ✅ | ✅ |
| `get secrets` | ❌ 403 | ✅ | ✅ |
| `get widgets` (unknown CRD) | ❌ 403 | ✅ | ✅ |
| `get deploy -o yaml` → last-applied annotation | absent | present | present |
| `api-resources` lists `secrets` | ❌ | ✅ | ✅ |
| `exec` into a pod | ❌ 403 | ❌ 403 | ❌ 403 |
| `port-forward` | ❌ 403 | ❌ 403 | ❌ 403 |
| `create token <sa>` | ❌ 403 | ❌ 403 | ❌ 403 |
| `get csr` | ❌ 403 | ✅ | ✅ |
| `certificate approve <csr>` | ❌ 403 | ❌ 403 | ❌ 403 |
| `describe pod` → events footer present | ✅ | ✅ | ✅ |
| `events` (uses `events.k8s.io`) | ✅ | ✅ | ✅ |
| `delete pod` | ❌ 403 | ❌ 403 | ✅ |
| `apply -f deployment.yaml` | ❌ 403 | ❌ 403 | ✅ |
| `create clusterrolebinding` | ❌ 403 | ❌ 403 | ✅ |
| `get pods -A`, no `--namespace` (default) | ✅ | ✅ | ✅ |
| `get pods -A` with `--namespace app` | ❌ 403 | ❌ 403 | ❌ 403 |
| `get pods -n other` with `--namespace app` | ❌ 403 | ❌ 403 | ❌ 403 |
| `get pods -w` streams | ✅ | ✅ | ✅ |
| `logs` | ✅ | ✅ | ✅ |
| `top pods` | ✅ | ✅ | ✅ |

`top pods` relies on the metrics-server that k3s bundles, which becomes ready
some seconds after the cluster does. The harness polls
`/apis/metrics.k8s.io/v1beta1` until it answers before asserting, rather than
racing it.

Plus, independent of mode:

- request with a wrong token → 401; with no token → 401
- request over plain HTTP to the TLS port → connection failure, not a downgrade
- `Connection: Upgrade` on an otherwise-allowed path → 403
- the TLS handshake advertises `http/1.1` only — no `h2` offered via ALPN (§8.2)
- **A discovery-walk classification test.** Enumerate every resource and
  subresource the live cluster advertises, run each through the policy in all
  three modes, and:
  1. Assert every entry in the `ro-nosecret` allowlist corresponds to something
     the cluster actually advertises. This catches the failure mode nothing else
     will — a typo or a stale group (`ingresses` moving out of `extensions`,
     `cronjobs` out of `batch/v1beta1`) silently denies a resource we believe we
     permit, and no allow/deny assertion notices because the path never appears.
  2. Assert every universal-denylist entry that the cluster advertises is in fact
     denied, so the denylist is spelled the way the cluster spells it.
  3. Assert the monotonicity invariant (§6.3.1) holds for every advertised entry.
  4. Write the full three-mode classification to a **golden file**. A cluster
     gaining a CRD then shows up as a reviewable diff rather than silently
     changing what is reachable.

  Point 4 is the real safety net for the fail-closed guarantee. Asserting "every
  resource gets a decision" would be tautological — the allowlist denies unknowns
  by construction. Making the *set* of denied things visible and diffable is what
  actually catches drift.

Teardown deletes the cluster. CI-safe: one cluster per run, unique name.

### 12.4 Make targets

```
make test              # unit only, no Docker, seconds
make test-integration  # envtest
make test-e2e          # k3d, KUBEGATE_E2E=1
make test-all
```

## 13. Out of scope for v1

Recorded so they are recognizably deferred rather than forgotten:

- Multiple contexts or modes in one process; path-prefix cluster routing.
- Per-client identity via mTLS, and per-token modes.
- Request-body inspection (would close the legacy SA-token-Secret gap in §2).
- Rate limiting and per-client quotas.
- Service installation (`launchd`), auto-writing the guest kubeconfig into a
  shared mount.
- Protocol-upgrade forwarding for `exec`/`attach`/`port-forward`. This is a
  deliberate permanent exclusion, not a deferral: it is what lets the design omit
  SPDY and WebSocket handling entirely.
