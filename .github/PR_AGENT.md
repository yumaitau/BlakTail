# PR-Agent with OpenCode Go

PR-Agent reviews same-repository pull requests when opened, reopened, marked ready
for review, or updated. Drafts, fork pull requests and bot events are skipped.
Automatic reviews leave the PR title, description and code unchanged.

## Activate

1. Create an API key in an OpenCode workspace with an active **Go** subscription.
2. In GitHub, open **Settings > Secrets and variables > Actions** and create the
   repository secret `OPENCODE_API_KEY`. Alternatively, grant this repository access
   to an organisation Actions secret with the same name.
3. Fill the secret placeholder by supplying the key in GitHub; never
   put the value in the workflow, a local tracked file, a PR comment or an issue.
4. Open a non-draft PR or push another commit to one after this workflow is merged.

The workflow skips the agent with a notice until the secret is set. It uses the
[OpenCode Go OpenAI-compatible endpoint](https://opencode.ai/docs/go/),
`https://opencode.ai/inference/go/openai/v1`, with `openai/kimi-k3` by default.
PR-Agent's `OPENAI_KEY` variable receives the OpenCode key; no OpenAI key is needed.
Optionally set the Actions variable `PR_AGENT_MODEL` to another Go Chat Completions
model with the `openai/` prefix. Fallbacks are disabled, and requests use a
conservative 32,000-token context limit.

## Commands

On an open, non-draft PR from this repository, owners, members and collaborators
can post `/review`, `/describe`, `/improve`, or `/ask <question>`. Other comments
are ignored. `/describe` can update the PR description; `/improve` posts suggestions.
Restricted mode and a read-only contents token prevent code pushes.

The workflow fetches PR data through GitHub's API without checking out or executing
PR code. PR diffs and context are sent to OpenCode Go for review. The PR-Agent
0.49.0 GitHub Action container is pinned by digest; update the digest deliberately
when upgrading. This public repository uses GitHub-hosted Ubuntu runners with Docker and Python 3.

Upstream: <https://github.com/The-PR-Agent/pr-agent>.
