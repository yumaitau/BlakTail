# PR-Agent with OpenCode Go

PR-Agent reviews same-repository pull requests targeting `main` when opened,
reopened, marked ready for review, or updated. Drafts and forks are skipped. Same-repository PRs from people, Dependabot and
Factory are eligible; bot-authored comments are ignored to prevent loops. Automatic reviews leave the title, description and code unchanged.

## Authentication

GitHub Actions authenticates to OpenCode with OIDC. No long-lived API key or
GitHub Actions secret is needed. Each job requests a GitHub identity token for
`https://opencode.ai/console`, then exchanges it at
`https://opencode.ai/console/auth/oauth/token` for a one-hour inference token.
Both tokens are masked; the access token is passed to PR-Agent only for this job.

The OpenCode service account **Yuma PR-Agent reviews** grants **Models: Request**
only. Each repository has a separate credential pinned to its immutable repository
ID, organisation owner ID and `main` branch. Billing, workspace administration and
credential-management permissions are not granted.

The non-secret Actions variable `OPENCODE_OIDC_CLIENT_ID` selects that repository's
OpenCode credential. Its `sk_...` value is a public client identifier, not an API
key. The workflow skips with a notice if the variable is missing. Trust can be
revoked in OpenCode **Settings > Service accounts > Yuma PR-Agent reviews**.

## Review model and events

Go requests identify PR-Agent and carry a stable per-PR `x-opencode-session` header
for routing and prompt caching. Manual verification uses a separate session per run.

Reviews use `openai/glm-5.3` through the [OpenCode Go endpoint](https://opencode.ai/v2/docs/console/go/),
`https://opencode.ai/inference/go/openai/v1`. An active Go subscription and remaining
allowance are required. Fallbacks are disabled; requests use a
conservative 32,000-token context limit.

`pull_request_target` runs the workflow from trusted `main`, which matches the
OIDC branch trust. It fetches the PR diff through GitHub's API without checking
out or executing PR code. Fork PRs are rejected before authentication. Do not add
PR checkouts, builds or scripts to this privileged workflow.

## Verify authentication

From GitHub **Actions > PR Agent > Run workflow**, run the workflow on `main`.
This exchanges a fresh OIDC token and sends a small, non-sensitive GLM-5.3 request
through Go. It posts no PR comments. A green run confirms authentication and model
access; real PR events exercise the review path.

## Existing pull requests

Installation does not automatically review PRs that are already open. A trusted
user can post `/review` to request a review without changing or reopening the PR.

PR-Agent can skip PRs with no analyzable files, such as changes only to ignored
lockfiles. A green job alone does not prove that a review comment was published.

## Commands

On an open, non-draft PR from this repository, owners, members and collaborators
can post `/review`, `/describe`, `/improve`, or `/ask <question>`. Other comments
are ignored. `/describe` can update the description; `/improve` posts suggestions.
Restricted mode and read-only contents permission prevent code pushes.

The PR-Agent 0.49.0 GitHub Action container is pinned by digest. Review and update
the digest deliberately when upgrading. PR diffs and context are sent to OpenCode
Go for review. This public repository uses GitHub-hosted Ubuntu runners with Docker and Python 3.

Upstream: <https://github.com/The-PR-Agent/pr-agent>.
