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
