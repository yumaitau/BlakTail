# DNS workspace: resolver groups, custom zones and safe record lifecycle

**Priority:** P1. **Depends on:** existing organisation DNS #40 and draft 01 navigation. **Area:** coordinator DNS, agent resolver, console.

## Gap and outcome

BlakTail has MagicDNS, split suffixes, global resolvers, search domains and A/AAAA records in Settings. NetBird exposes DNS Settings, Nameserver Groups and Custom Zones as separate workflows. Build first-class management around existing schema; only expand backend for real zone/record requirements.

## Scope

- Dedicated DNS overview with effective settings per organisation and client group, resolver health, split-match preview, per-name diagnostics and published revision. Nameserver groups need assignment semantics, ordering/failover, safe private DNS through routes and optional DoT/DoH only after transport/security design.
- Custom-zone lifecycle with constrained A/AAAA/CNAME/TXT/MX if needed; define TTL, recursion boundary, collision with protected `*.blaktail`, delegation, authoritative versus forwarded answer and who may edit. Do not turn coordinator into a public recursive resolver.
- Console validates suffixes/IDNA, private/loopback targets, ambiguous overlaps and stale routes; show diff/etag conflicts, rollback and audit. Preserve current JSON documents and agent behaviour on upgrade.

## Acceptance / proof

Dual-stack split DNS returns correct answer across two isolated organisations and two client groups; longest suffix wins. Resolver outage follows documented fallback without leaking internal names to public DNS. Zone create/edit/delete updates agents and rollback safely; member cannot write via API.

**Evidence:** `docs/org-dns.md`, `apps/console/src/components/dns-settings.tsx`; https://docs.netbird.io/manage/dns, https://docs.netbird.io/manage/dns/nameserver-groups, https://docs.netbird.io/manage/dns/custom-zones.

## Status (2 October 2026)

**Done:**
- Backward-compatible document extension in `blaktail-coord/src/org_dns.rs`: `nameserver_groups` (ordered resolvers, match domains, enabled, all devices or office/ranger/store tags) and `zones` (A/AAAA/CNAME/TXT, TTL 30-86400). Empty arrays are not serialised, so pre-upgrade `dns_json` keeps its bytes, etag and agent snapshot. Validation: IDNA/mixed-script, no wildcards, protected `.blaktail` suffix, nested/duplicate zones, zone vs forwarded suffix, legacy records inside zones, CNAME exclusivity/apex/loops, unusable addresses, limits. Advisory warnings: loopback/link-local targets and resolvers, shadowed groups, empty zones, CNAMEs leaving BlakTail names, and private targets no device address or approved subnet route covers.
- Per-device agent view: groups resolved from device tags and flattened into legacy `split`; zones flattened into empty-resolver `split` plus A/AAAA `records` for old agents; new `zones` key for current agents.
- `blaktaild/src/dns.rs`: authoritative zone answers (all A/AAAA, CNAME chased locally through zones, extra records and MagicDNS, TXT, per-record TTL, NXDOMAIN/NODATA, TC on overflow); longest suffix wins between zone and split; public names still REFUSED.
- `blaktail-coord/src/dns_workspace.rs` + slot 23 (`org_dns_revisions`): revision history (last 50), `rollback_to`, read-only validate, split-match preview per device or tag set. `PUT /dns` now uses `Permission::ManageDns`; audit records group/zone counts and `rollback_to`.
- Console `/dns` workspace (nav group "DNS"); Settings links there. Docs: `docs/org-dns.md`, `docs/console.md`.

**Proven by tests:** two organisations publishing the same zone name get their own answers and devices; tag-assigned groups reach only matching devices; longest suffix wins (unit and router-level preview); member PUT and `rollback_to` rejected (403) while validate/preview/revisions are readable; stale etag 412; rollback to an older revision; validation failures (28 rejected documents); pre-upgrade JSON keeps its etag, round-trips byte-identical and yields an agent snapshot without `zones`; agent zone answering, CNAME chase, NXDOMAIN/NODATA, split-under-zone forwarding, and forward/backward snapshot compatibility.

**Still needs live/field proof or a decision:** dual-stack split DNS on real devices across two isolated organisations and two client groups; resolver outage fallback without leaking internal names (existing last-known-good probing covers new resolvers only; per-group failover is the stub's in-order forwarding); OS-level routing of zone names on macOS/Linux/Windows/iOS; DoT/DoH (needs transport and security design); health probing of group resolvers; old-agent behaviour for CNAME/TXT is REFUSED until agents upgrade; no `/api/v1` routes for revisions/preview yet.
