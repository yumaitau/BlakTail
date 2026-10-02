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
