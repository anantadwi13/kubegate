# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`kubegate` is a credential-injecting Kubernetes API proxy. It runs on a host that
holds real cluster credentials and serves a **guest** (a Lima VM) that holds
none — only a proxy bearer token and a pinned self-signed CA. One process serves
exactly one immutable `(context, mode)` pair.

`README.md` covers the user-facing story (modes, guest setup, security
properties). Two documents are the authority on *why* the code is shaped this
way, and are worth grepping before changing behaviour:

- `docs/superpowers/specs/2026-08-26-kubegate-design.md` — threat model, mode
  definitions, request lifecycle, accepted residual risks. Code comments cite it
  by section (e.g. "design spec §6.3", "§7.3"); keep those references accurate.
- `docs/superpowers/plans/2026-08-26-kubegate.md` — the 18-task implementation
  plan the current code was built from.

## Commands

```
make build              # -> bin/kubegate
make fmt                # gofmt -l -w .
make test               # unit tests only: ./internal/... ./cmd/... — seconds, no Docker
make test-integration   # envtest (real apiserver binaries), -tags=integration
make test-e2e           # k3d (real binary, real kubectl, real cluster), -tags=e2e
make test-all           # all three
```

Single test / package:

```
go test ./internal/policy/ -run TestModeMonotonicity -v

# integration: needs KUBEBUILDER_ASSETS; `make envtest` installs setup-envtest into ./bin
KUBEBUILDER_ASSETS="$(./bin/setup-envtest use 1.31.0 -p path)" \
  go test -tags=integration -run TestDiscoveryFilteringAgainstRealAPIServer ./test/integration/...

# e2e: gated on KUBEGATE_E2E=1 AND the e2e build tag, so plain `go test ./...` never runs it.
# Needs Docker + k3d + kubectl on PATH. Each top-level test creates/destroys its own cluster; budget 15-25 min.
KUBEGATE_E2E=1 go test -tags=e2e -timeout=20m -run TestModeMatrix ./test/e2e/...
```

`test/e2e/testdata/classification.golden` is a reviewable snapshot of every
resource the cluster advertises against every mode's verdict. Regenerate
deliberately and read the diff:

```
KUBEGATE_E2E=1 UPDATE_GOLDEN=1 go test -tags=e2e -run TestDiscoveryWalkClassification ./test/e2e/...
```

There is no linter config beyond `gofmt`. The k3s image tag in
`test/e2e/cluster_test.go` is pinned with a comment explaining exactly which
tags fail to boot — don't bump it casually.

## Request lifecycle (the big picture)

Everything flows through `internal/server.handler.authorize` in
`internal/server/server.go`, in this order. The order is load-bearing; each
stage can only deny.

1. **Upgrade guard** — `Connection: Upgrade` / `Upgrade:` is refused outright.
   No SPDY/WebSocket handling exists anywhere, so `exec`/`attach`/`port-forward`
   are unimplementable by construction. TLS deliberately offers **http/1.1 only**
   (`TLSConfig`): HTTP/2 has no `Connection: Upgrade`, so this check would
   silently lapse.
2. **`internal/authn`** — constant-time bearer-token compare, then
   `authn.Scrub` *erases* (never rejects) `Authorization`, `Impersonate-*`, and
   `X-Remote-*`. Scrubbing happens before anything downstream can observe them.
3. **`internal/reqinfo`** — wraps the apiserver's own
   `request.RequestInfoFactory`. Never hand-roll Kubernetes URL parsing here;
   the legacy `/api/v1/watch/...` prefix, verb-via-path `proxy`, and
   subresource-vs-name ambiguity are where bypasses live. A parse error is a
   denial, never a passthrough.
4. **`internal/policy.Engine.Authorize`** — pure decision: non-resource
   allowlist → universal denylist → verb gate → mode resource policy → namespace
   scope.
5. **Content negotiation** (`negotiateJSON`) — in `ro-nosecret` the outbound
   `Accept` is rewritten to an **allowlist** of JSON-family types; anything else
   gets a 406. `Accept-Encoding` from the guest is always deleted in `Rewrite`
   so Go's transport does its own transparent gzip and `modifyResponse` sees
   decompressed bytes.
6. **Body cap** — `MaxBodyBytes` (8 MiB) checked against `Content-Length` up
   front, with `MaxBytesReader` as the backstop.
7. **`internal/upstream`** — the *only* place host credentials enter a request,
   reached only after every check above. All credential handling (exec plugins,
   refresh, client certs, proxy-url) is delegated to client-go; kubegate holds a
   `RoundTripper`, never a token.
8. **`modifyResponse`** — `internal/discovery.FilterBody` then
   `internal/redact.Body` for buffered responses; `redact.Stream` frame-by-frame
   for watches (`FlushInterval: -1` keeps streaming alive).
9. **`internal/audit`** — exactly one JSON line per request, always, recording
   what was asked and decided. Never bodies, never tokens.

`internal/server/status.go` renders every error as a real `metav1.Status` so
kubectl prints something useful, and every message is a hand-authored fixed
string — no transport or filesystem error text ever reaches the guest.

## Invariants that tests enforce (break one and CI tells you, cryptically)

- **Package purity.** `internal/policy` and `internal/redact` must not import
  `net/http`, `k8s.io/client-go/rest`, or the apiserver request package.
  `purity_test.go` in each asserts this via `go/build`. The point is that the
  entire decision and transform surface stays testable as data.
- **Monotonicity.** `ro-nosecret ⊆ ro-secret ⊆ rw`. Anything a stricter mode
  allows, a looser mode must allow. `TestModeMonotonicity` brute-forces the
  cross product; `policy.AllModes` must stay ordered strictest-first.
- **Fail closed, everywhere.** The recurring bug class in this repo's history is
  a *passthrough default*: an unhandled shape falling through to the original
  bytes. `discovery.FilterBody`'s kind switch errors on an unrecognized kind
  (this is how `APIGroupDiscoveryList` leaked `secrets` before it got a case);
  a non-array `resources`/`groups`/`items` field is an error, not a
  passthrough; a resource whose `namespaced` field is absent is omitted from the
  scoper rather than recorded as `false`; an undecodable body or watch frame
  aborts the response with a 500.
- **Routing off parsed state, not client input.** `modifyResponse` reads the
  already-parsed `policy.Request` out of the request context (`reqKey`), because
  keying watch-vs-buffered off raw `?watch=`/`?follow=` let a client push a
  discovery document down the unfiltered streaming path. Same lesson as the
  `Accept` allowlist: **content negotiation is an authorization surface**, and
  bypasses there are invisible to a test suite that only drives real `kubectl`.
- **`Authorize` vs `AuthorizesResourceKind`.** Discovery filtering must use the
  latter (everything except namespace scoping). Using `Authorize` there hits the
  empty-namespace-is-ambiguous branch and hides resources a correctly-scoped
  request would be allowed to read.
- **Audit `redacted` means bytes actually changed** — reported back through an
  `atomic.Bool` in the request context, never inferred from the mode.

## Where things live

`internal/policy` is where behaviour changes belong:

- `modes.go` — `universalDenyRules` (never forwardable in any mode: `*/exec`,
  `*/attach`, `*/portforward`, `*/proxy`, `serviceaccounts/token`, CSR writes
  and approval) and `roNoSecretAllow`, the curated strict allowlist. Its
  organizing principle is *workload observability*, not security posture: RBAC,
  CSRs, and webhooks stay out even though they hold no secret.
- `rule.go` — RBAC-shaped matching. A bare `pods` rule never grants
  `pods/exec`; `*` matches resource *and* subresource; an empty verb is always
  rejected regardless of the rule's `Verbs`.
- `extension.go` — the `--policy` file. It can only *extend* the `ro-nosecret`
  allowlist with read verbs, and is validated against the universal denylist by
  probing it (not string-matching) so the two definitions cannot drift.
- `scope.go` — `--namespace` scoping. An empty namespace is ambiguous
  (cluster-scoped resource vs. cluster-wide collection), so it consults the
  `ResourceScoper` that `internal/discovery.BuildScoper` populates from live
  discovery — built only when `--namespace` is set.

Adding an allowlist entry: add it to `roNoSecretAllow`, then run the e2e
classification test — it asserts every allowlist entry corresponds to something
a real cluster advertises, which is what catches typos and stale API groups that
silently deny a resource you believe you permit.

`cmd/kubegate/serve.go` `run()` is the startup order, and it matters: probe
upstream credentials → build scoper (only if scoping) → build engine → load
cert/token → open audit log → serve. Expired SSO must surface on the host at
startup, not on the guest's first command.
