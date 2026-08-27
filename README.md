# kubegate

`kubegate` is a credential-injecting Kubernetes API proxy. It runs on the
**host**, holds the real cluster credentials, and exposes a scoped proxy to a
**guest** (typically a Lima VM) that never sees them.

## Problem it solves

A developer VM needs to talk to Kubernetes, but shouldn't hold cluster
credentials: every process in the VM — including any AI agent running there —
would otherwise inherit the developer's full cluster identity. Cluster
credentials also expire constantly, since real kubeconfigs often authenticate
through exec plugins (`aws eks get-token`, `gcloud`, corporate SSO) that can't
be meaningfully copied into a VM anyway.

`kubegate` gives the guest a kubeconfig containing no cluster credential at
all — only a proxy-scoped bearer token and a pinned CA — and enforces a
capability ceiling on everything that token can do. The VM is treated as
untrusted: the proxy's mode is a hard ceiling on the entire guest, not a hint.
See the [design spec](docs/superpowers/specs/2026-08-26-kubegate-design.md)
for the full threat model.

## Modes

One process serves exactly one `(context, mode)` pair, fixed and immutable
for its lifetime. Running against a second cluster, or in a second mode,
means starting a second process on a different port.

| Mode | Verbs | Resource policy | Redaction | Secrets readable |
|---|---|---|---|---|
| `ro-nosecret` | `get, list, watch` | curated **allowlist**, fails closed | on | no |
| `ro-secret` | `get, list, watch` | **denylist** (permits everything else) | off | yes |
| `rw` | all verbs | **denylist** | off | yes |

`ro-nosecret` is the only mode that makes a promise about response *content*:
it strips `kubectl.kubernetes.io/last-applied-configuration` (which can carry
literal secret values from `kubectl apply`) and advertises only its allowlist
via the `/api` and `/apis` discovery documents, so `kubectl api-resources`
shows exactly what works instead of a confusing 403. The other two modes
serve everything they advertise. This discovery filtering is partial, not a
guarantee — see "What it does not provide" below for what still passes
through `/openapi/v2` and `/openapi/v3/*` unfiltered in every mode.

Some things are refused in **every** mode, regardless of `--policy`
extensions: interactive subresources (`exec`, `attach`, `port-forward`,
`proxy`), and anything that mints a standalone cluster credential
(`serviceaccounts/token`, CSR approval) — because either would let a caller
walk straight past kubegate to the real apiserver. See spec §6.3 for the
full list and rationale, and §2 for the residual risks this design
consciously accepts (e.g. `pods/log` stays readable in `ro-nosecret`, since a
mode that hid all logs would have no diagnostic value).

## Guest setup (Lima example)

On the **host**, start kubegate against a real context:

```
kubegate serve \
  --context prod-eks \
  --mode ro-nosecret \
  --listen 192.168.5.2:8443
```

On startup, after validating the upstream credentials, kubegate prints a
paste-ready kubeconfig to stderr — the server URL, the CA, the token, and a
complete config snippet. Nothing is written anywhere guest-visible.

In the **guest**, save that snippet and point `kubectl` at it:

```
export KUBECONFIG=~/.kube/kubegate-config
kubectl get pods -A
```

The guest kubeconfig has exactly one cluster entry and no cluster credential
of any kind — only the proxy token — so it cannot address anything but this
one kubegate process, and holding it grants nothing beyond what the mode
allows.

## Testing

Three layers, each proving a different thing:

```
make test              # unit tests: pure policy logic, no Docker, seconds
make test-integration  # envtest: a real apiserver via controller-runtime
make test-e2e          # k3d: the real binary, real kubectl, a real cluster
make test-all          # all three
```

`make test-e2e` requires Docker and `k3d`/`kubectl` on `PATH`, and is gated
behind `KUBEGATE_E2E=1` (`go test -tags=e2e`) so it never runs by accident in
a plain `go test ./...`. It builds the real `kubegate` binary, spins up a
throwaway k3d cluster, starts the binary against it in each mode, and drives
it with a real `kubectl` — proving the three modes, namespace scoping, secret
redaction, and the credential-injection boundary all hold against a real
cluster, not just a fake `http.Handler`. Budget 15–25 minutes; each top-level
e2e test creates and tears down its own cluster. `test/e2e/testdata/classification.golden`
is a reviewable snapshot of every resource the cluster advertises against
every mode's verdict — regenerate it deliberately with
`KUBEGATE_E2E=1 UPDATE_GOLDEN=1 go test -tags=e2e -run TestDiscoveryWalkClassification ./test/e2e/...`
and read the diff before committing it.

## Security properties

**What kubegate provides:**

- No cluster credential of any kind exists in the guest.
- The target cluster and mode are fixed on the host at startup and cannot be
  changed by a guest-side client.
- Every forwarded request is authorized against the mode's policy and
  written to an audit log.
- A parse error, redaction failure, or internal error always denies or fails
  the request — the policy and redaction paths never fail open.

**What it does not provide** (see spec §2 "Accepted residual risks" and §13
"Out of scope for v1" for the complete, deliberate list):

- Multi-tenancy or per-process authorization within the guest — the whole VM
  shares one mode.
- A replacement for cluster RBAC; kubegate can only narrow what the host
  identity already holds.
- Protection against an application logging its own secrets: `pods/log` is
  readable even in `ro-nosecret`.
- Closing the legacy `kubernetes.io/service-account-token` Secret path in
  `rw` mode, which would require request-body inspection on Secret writes.
- Full discovery hiding: `/openapi/v2` and `/openapi/v3/*` are never
  filtered, in any mode. They can reveal the existence and schema of
  restricted resource types — including `Secret` and any installed
  third-party CRDs — even in `ro-nosecret`. They never reveal actual secret
  data or resource instances, only that the type exists and what its shape
  is.

## Repository layout

```
cmd/kubegate/       CLI entrypoint and the `serve` command
internal/policy/    pure authorization engine (no net/http import)
internal/reqinfo/   apiserver-shaped request parsing
internal/redact/    strict-mode response redaction
internal/discovery/ discovery-document filtering and namespace scope map
internal/server/    HTTP handler, TLS, tokens, kubeconfig banner
internal/authn/     bearer-token authentication
internal/audit/     structured audit logging
internal/upstream/  credential injection into the real cluster transport
test/integration/   envtest-based integration tests
test/e2e/           k3d-based end-to-end tests
```
