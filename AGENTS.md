# AGENTS.md

This file provides guidance to coding agents (e.g. Claude Code, claude.ai/code) when working with code in this repository.

## Repository purpose

The AppsCode/kubeops fork of [kube-rbac-proxy](https://github.com/brancz/kube-rbac-proxy) — a small HTTP proxy that sits in front of a single upstream and authorizes incoming requests via the Kubernetes `SubjectAccessReview` API. Lets you protect a pod's metrics/admin endpoint with RBAC instead of relying on cluster `NetworkPolicies`.

The Go module path is **unchanged from upstream**: `github.com/brancz/kube-rbac-proxy`. The git remote is `kubeops/kube-rbac-proxy` but module imports must still use the upstream URL. This fork tracks upstream and carries AppsCode-specific patches on top.

The produced binary is `kube-rbac-proxy`.

## Architecture (upstream layout)

- `cmd/kube-rbac-proxy/` — entry point.
- `pkg/proxy/` — the HTTP proxy core (request handling, transport).
- `pkg/authn/` — authentication: token, OIDC, x509 client certs.
- `pkg/authz/` — authorization via `SubjectAccessReview` against the kube API.
- `pkg/filters/` — request filters (RBAC, header inspection, etc.).
- `pkg/tls/` — TLS termination / re-encryption.
- `test/` — integration tests.
- `examples/` — runnable example deployments.
- `scripts/` — release / test helpers.
- `Dockerfile` — release image.
- `VERSION`, `RELEASE.md` — release metadata and process notes.
- `CHANGELOG.md` — release notes.

`go.mod`'s `module github.com/brancz/kube-rbac-proxy` is the source of truth for imports.

## Common commands

This repo uses upstream's hand-rolled Makefile + scripts (no AppsCode Docker wrapper). Uses a local Go toolchain.

- `make` — default build target (see `Makefile` for the exact set).
- Tests live under `test/`; consult `scripts/` and the Makefile for the runner entry points.

(Treat the upstream `README.md`, `CHANGELOG.md`, and `RELEASE.md` as authoritative for command details — this fork inherits all of it.)

Run a single Go test:

```
go test ./pkg/proxy/... -run TestName -v
```

## Conventions

- Module path is `github.com/brancz/kube-rbac-proxy` (**upstream**); imports must use that, not `github.com/kubeops/kube-rbac-proxy`. The fork's job is to track upstream, not to fork the import path.
- **Upstream-tracking** fork. Prefer rebasing onto upstream over diverging. Isolate AppsCode-specific patches (e.g. impersonation features) into branches like `feature/impersonation-bypass-sa-verification` so they can be replayed on top of an upstream sync.
- License: Apache-2.0 (`LICENSE`).
- Sign off commits (`git commit -s`).
- Upstream is moving toward becoming a SIG-Auth-accepted Kubernetes project. The README documents that breaking changes are inbound; AppsCode patches must stay tightly scoped so the rebase pain stays manageable.
- TLS / authn / authz code lives in their respective `pkg/` subdirs — keep that separation. Authorization paths must continue to go through `SubjectAccessReview`, not an in-binary policy engine.
