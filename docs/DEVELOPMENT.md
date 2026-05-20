# Development Guide

## Prerequisites

### Superpowers

Superpowers provides the AI workflow skills used throughout this guide.
Check if it is installed:

```bash
ls ~/.claude/skills/superpowers 2>/dev/null && echo "installed" || echo "not installed"
```

If not installed, follow the instructions at: https://github.com/obra/superpowers

**This is mandatory for this project.** The workflows described below depend on it.

### gh (GitHub CLI)

This repository lives on GitHub (`Intrinsec/s3proxy`). `gh` is used for creating and managing
pull requests from the terminal.

```bash
# Debian / Ubuntu install (see project installer script)
bash /tmp/install.sh    # or follow https://github.com/cli/cli/blob/trunk/docs/install_linux.md

gh auth login           # interactive — choose GitHub.com, SSH, browser
gh auth status
```

Configured defaults for this repo:

```bash
gh repo set-default Intrinsec/s3proxy
gh config set editor vim
gh config set git_protocol ssh
```

Useful aliases (already set):

| Alias | Expansion |
|-------|-----------|
| `gh prc` | `gh pr create --fill --web` |
| `gh prv` | `gh pr view --web` |
| `gh prs` | `gh pr status` |
| `gh prm` | `gh pr merge --squash --delete-branch` |
| `gh prl` | `gh pr list --author @me` |
| `gh co`  | `gh pr checkout` |
| `gh ci`  | `gh run list --limit 10` |
| `gh watch` | `gh run watch` |

## Local Development Environment

All local development uses Docker Compose. Do not use Kubernetes or minikube locally —
the overhead kills the dev loop.

```bash
docker compose up -d      # Start all dependencies (MinIO as S3 backend, mock KMS if any)
docker compose logs -f    # Follow logs
docker compose down       # Stop
```

`docker compose up` must be sufficient to get a fully working local environment.
No manual setup steps, no access to staging or production required.
Production deployment (Kubernetes) is handled separately and is not part of the local dev workflow.

## AI-Assisted Workflow

This project uses AI agents with [superpowers](https://agentskills.io) skills.
This is a **critical project with client SLA** — every change follows a strict sequence.
Skipping steps is not allowed.

```
brainstorming → worktree → writing-plans → subagent-driven-development → review → PR
```

### Step by Step

1. **Design** — run `/brainstorming`. The agent asks questions one at a time, proposes 2–3 approaches,
   writes a spec to `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`, and waits for your
   explicit approval before proceeding.

2. **Isolate** — the agent creates a git worktree on a feature branch via
   `superpowers:using-git-worktrees`. Never work directly on `main`.

3. **Plan** — run `/writing-plans`. The agent turns the spec into a detailed step-by-step
   implementation plan with test cases and commit checkpoints, saved to
   `docs/superpowers/plans/YYYY-MM-DD-<feature>.md`.

4. **Implement** — the agent executes the plan with `superpowers:subagent-driven-development`:
   one fresh subagent per task, with **two-stage review** after each task:
   - First: spec compliance (does the code match the spec exactly?)
   - Then: code quality (is the implementation well-built?)

5. **Verify** — `superpowers:verification-before-completion` is mandatory before declaring any
   work done. Tests must pass, linter must pass, no called vulnerabilities.

6. **Final review** — `/requesting-code-review` dispatches a dedicated code-reviewer subagent
   across the entire implementation before the PR is opened.

7. **Submit** — `superpowers:finishing-a-development-branch` guides the final step:
   push branch, create GitHub PR, clean up worktree.

## Skill Reference

| Situation | Skill to invoke |
|-----------|----------------|
| Starting a feature or significant change | `/brainstorming` |
| Turning an approved spec into a plan | `/writing-plans` |
| Executing a plan | `superpowers:subagent-driven-development` |
| Bug or unexpected behavior | `/systematic-debugging` |
| Before marking any task complete | `superpowers:verification-before-completion` |
| After all tasks, before opening PR | `/requesting-code-review` |
| Responding to PR feedback | `superpowers:receiving-code-review` |
| After modifying Go files | `/lint-go` |
| After modifying go.mod / go.sum | `/govulncheck` |
| Setting up a new project | `/setup-project` |

## Branch Strategy

```
main  (protected — CI required, 2 approvers, no direct push)
 ├── feature/<ticket-id>-<short-description>    new features
 ├── fix/<ticket-id>-<short-description>        bug fixes
 ├── hotfix/<short-description>                 emergency production fixes (→ main + backport)
 └── chore/<short-description>                  non-functional changes (deps, docs, config)
```

**Rules:**
- **No direct push to `main`** — enforced via GitHub branch protection.
- Branch from latest `main`:
  ```bash
  git fetch origin && git checkout -b feature/PROJ-42-add-auth origin/main
  ```
- Include the ticket ID in the branch name for traceability.
- Target < 3 days per branch. Long branches mean merge pain and review fatigue.
- One concern per branch — do not bundle unrelated changes.
- Branches are deleted after merge.

## Pull Request Process

```bash
# 1. Push branch
git push -u origin feature/PROJ-42-add-auth

# 2. Open draft PR immediately — visibility lets the team know what's in progress
gh pr create --draft \
  --title "feat(PROJ-42): add encryption key rotation" \
  --body "Closes PROJ-42

## What
Adds support for key rotation via Vault KV versions.

## Test plan
- [ ] Unit tests pass
- [ ] Integration tests against MinIO
- [ ] golangci-lint clean
- [ ] govulncheck clean"

# 3. Before marking ready — all checks must pass locally
golangci-lint run ./...
go test -race ./...
govulncheck ./...          # or govulncheck -mod=vendor ./... if vendor/ exists

# 4. Mark ready and assign 2 reviewers
gh pr ready
gh pr edit --add-reviewer reviewer1,reviewer2
```

**PR checklist before marking ready:**
- [ ] All tests pass (`go test -race ./...`)
- [ ] Linter clean (`golangci-lint run ./...`)
- [ ] No called vulnerabilities (`govulncheck ./...`)
- [ ] New metrics / alerts added if applicable (see `monitoring/alerts/`)
- [ ] Grafana panel iterated on `https://dashboards.lan.intrinsec.com/dev` and exported to `monitoring/dashboards/s3proxy.json`
- [ ] AGENTS.md rules not violated (no secrets in code, structured logs, etc.)

**PR settings (configure once in the GitHub repository):**
- Squash commits: required
- Delete source branch: enabled
- Auto-merge when checks pass: enabled
- Required approvals: 2
- Require status checks to pass before merging

Address review feedback with `superpowers:receiving-code-review` — verify technical claims
before implementing suggestions.

## Conflict Prevention

- **Communicate before starting**: check the board for who owns which domain.
  Two people touching the same service at the same time causes conflicts.
- **Rebase daily on long branches**:
  ```bash
  git fetch origin && git rebase origin/main
  ```
  Prefer rebase over merge to keep history linear and readable.
- **Small PRs**: split large features into sequential PRs with clear dependency order.
  Each PR should be mergeable and leave the system in a valid state.
- **Feature flags**: for changes that cannot be split, use a feature flag to merge
  incomplete work safely without exposing it to end users.
- **Shared packages**: coordinate changes to shared packages (crypto, router middleware,
  metrics helpers) in a dedicated PR before building on top of them.

## Testing Standards

All code follows Red-Green-Refactor (`superpowers:test-driven-development`).
No implementation without a failing test first.

```bash
# Unit tests
go test ./...

# With race detector (mandatory before PR)
go test -race ./...

# Coverage check (minimum 70% domain code, 90% adapters)
go test -cover ./...
```

Integration tests run against real dependencies via Docker Compose:

```bash
docker compose up -d
go test ./... -tags=integration
```

## Observability Checklist

Every new endpoint or significant behaviour must have:
- [ ] Request counter metric (`http_requests_total` or domain-specific equivalent)
- [ ] Latency histogram metric
- [ ] Structured log entries at appropriate levels (INFO for normal path, WARN for retries,
      ERROR for failures)
- [ ] `trace_id` injected into log entries (from span context)
- [ ] Alert rule in `monitoring/alerts/s3proxy.yaml` if a new failure mode is introduced
- [ ] Grafana panel iterated on dev (`https://dashboards.lan.intrinsec.com/dev`) and exported
      to `monitoring/dashboards/s3proxy.json`

## Grafana Dashboard Workflow

Dashboards are developed interactively on the dev instance, then committed as code.

1. **Develop** on `https://dashboards.lan.intrinsec.com/dev`
   - Create or iterate on the dashboard in the UI
   - Use the VictoriaMetrics data source pointing at the dev environment
   - Validate panels against real service metrics before exporting

2. **Export** the finalised dashboard:
   Dashboard menu → Share → Export → Export for sharing externally → Download JSON

3. **Commit** the JSON to `monitoring/dashboards/s3proxy.json` in this repository as part of
   the feature PR.

4. **Production deployment** is managed via infrastructure-as-code (process defined separately).
   Prod instance: `https://dashboards.lan.intrinsec.com/`

Never edit dashboard JSON by hand — always iterate in the dev UI and re-export.

## Product Inventory

Every shared project must be declared in the Intrinsec product inventory:
**`https://product-inventory.int.intrinsec.com`**

Create or update the product entry with:
- Product name and description
- **Responsible person** (technical owner)
- **Responsible team**
- **Infrastructure and resources** — list all compute, storage, and managed services
  (used for cost allocation — keep this up to date when infrastructure changes)
- **Link to product documentation**
- **Intrinsec offer** — link to the associated commercial offer if applicable
- All other fields required by the form

Update this entry whenever infrastructure changes: new services, new namespaces, etc.

## Production Deployment (Kubernetes)

Production and pre-production deployments run on Kubernetes managed by the Core Infra team.

**To provision a namespace:**
1. Open a support request to Core Infra via `https://support.lan.intrinsec.com`
2. Include: project name, target environment (preprod / prod), expected resource requirements
   (CPU, memory, storage, number of replicas)
3. Core Infra will provision the namespace and provide access credentials

Kubernetes manifests and Helm charts are versioned in this repository under `charts/`.
Do not deploy manually — all production changes go through CI and the Core Infra provisioning
process.

Local development uses Docker Compose only. Do not attempt to run Kubernetes locally.

> This provisioning process will be automated in a future iteration.

## Release Checklist

Before tagging a release:
- [ ] All CI checks pass
- [ ] `govulncheck ./...` clean
- [ ] SBOM generated: `syft . -o cyclonedx-json > sbom.json`
- [ ] `grype sbom.json` — no critical or high vulnerabilities in the image
- [ ] Alertmanager rules reviewed — thresholds still appropriate for current load
