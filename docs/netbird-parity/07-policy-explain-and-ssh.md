# Explain effective access and finish policy-to-agent SSH enforcement

**Priority:** P0 for enforcement correctness, P1 for UX. **Depends on:** existing #38 and agent ACL filter; draft 04 for named resources. **Area:** coordinator compiler, Linux/macOS/iOS agents, console.

## Gap and outcome

BlakTail has versioned deny/allow rules, people groups, tags, host/port/protocol selectors, tests, and a visual editor. The SSH section in `acl-editor.tsx` explicitly says agents do not yet enforce those rules. NetBird's policy/group/access pages expose resource reachability and policy effects. Close the gap between editor promise and actual transport enforcement, rather than adding a second policy engine.

## Scope

- For a selected actor/source/destination/service, show matched rule, defaults, denied precedence, group/tag membership, policy revision and where enforcement happens. Expose precise limitations by OS and route type; no misleading green “allowed” when agent lacks filter support.
- Define fail-closed compatibility and minimum agent version for SSH checks/re-auth. Implement and prove enforcement at destination, including Linux sshd integration and realistic macOS/iOS boundary. Remove unsupported editor claims or gate controls until enforceable.
- Add drafts, policy diff/tests, conflict warnings and actor-attributed publish audit; preserve etag concurrency and legacy same-tag semantics during migration.

## Acceptance / proof

Allow, deny, stale membership, service port, tag owner and SSH-user tests align with actual packet/SSH outcomes on two nodes. Old agent cannot silently widen access. Cross-org resource probes fail; editor clearly distinguishes simulated, published and device-enforced state.

**Evidence:** `docs/policy.md`, `apps/console/src/components/acl-editor.tsx`, `blaktaild/src/acl_filter.rs`; https://docs.netbird.io/manage/access-control, https://docs.netbird.io/manage/network-routes/access-control.
