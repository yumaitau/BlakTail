# Console: give every network-control workflow a clear home without losing All networks

**Priority:** P1. **Depends on:** none. **Area:** console navigation, role-aware UX.

## Gap and outcome

NetBird's dashboard separates Peers, Networks, Routes, Access Control, Groups, Posture Checks, DNS, Events, Team, Setup Keys and Settings. BlakTail currently has six top-level links in `apps/console/src/components/console-shell.tsx`; routes, tags and network-specific changes live inside device rows, while DNS, SSO, directory and automation share a long Settings page. Keep BlakTail's superior one-session **All networks** inventory, but give network-scoped workflows identifiable homes. This is information architecture, not a visual clone.

## Scope

- Design task-based nav with Devices/Networks/Access/DNS/People/Events/Settings; hide or read-only-label controls per actual organisation role, never by client-side visibility alone. Keep owner organisation name, scope and role visible on every mutation.
- Add contextual links from device to routes, policies, DNS and relevant audit entries without changing stable hostname/MagicDNS identity. Keep global device search across linked accounts and scoped drilldowns; never silently edit another organisation.
- Provide loading/empty/error states, keyboard and VoiceOver navigation, responsive layouts, Australian English, and clear distinction between network status and coordinator status. Split pages only when backed by real data/API, not placeholder panels.

## Acceptance / proof

Owner, admin and member each navigate real flows across two linked organisations; member writes are rejected server-side; changing selected organisation never changes an unsaved mutation's target. Browser tests cover deep links, mobile width, keyboard focus and partial coordinator failure. Do not present Sydney residency as universally guaranteed by arbitrary self-hosting.

**Evidence:** `docs/console.md`, `PRODUCT.md`, `apps/console/src/components/console-shell.tsx`; https://github.com/netbirdio/dashboard/tree/main/src/app/%28dashboard%29, https://docs.netbird.io/manage/control-center.

## Status (2 October 2026)

**Done:** Task-based nav groups in `apps/console/src/components/console-shell.tsx` (Devices, Networks, Access, DNS, Services, Events, Settings), now with Topology and Change drafts under Networks. Contextual links: device detail → its topology paths (organisation-pinned deep link), network resources, DNS (with its MagicDNS name) and change drafts, alongside the existing policy link and per-device audit trail; topology edges link to the owner-scoped policy, resource or router page; Access policy links to Topology and Change drafts. Organisation name and role are shown on Access policy, Topology and Change drafts; draft mutation forms pin the organisation in a hidden field and the server re-checks membership and permission. The Topology error state says existing tunnels are unaffected, separating coordinator status from network status.
**Proven by tests:** server-side permission and cross-organisation rejection for the new topology and draft endpoints (coordinator tests listed in drafts 02 and 03); console typecheck and lint.
**Still needs live/field proof or a decision:** browser tests across two linked organisations for owner/admin/member (deep links, mobile width, keyboard focus, partial coordinator failure); a screen-reader pass; Networks, DNS and Access pages still follow the switcher cookie rather than accepting an organisation deep link; the All networks devices page is unchanged.
