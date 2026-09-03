# Windows service note (issue #11)

Trivial note only — no Windows code exists yet, and this file changes no
build. See `docs/windows-agent.md` for the full plan.

Intended shape when the backend lands:

```cmd
:: After enrolment (browser approval, same as other agents):
sc.exe create BlakTail binPath= "\"C:\Program Files\BlakTail\blaktaild.exe\" run" start= auto
sc.exe start BlakTail
sc.exe query BlakTail
```

- The service runs the persisted-state `run` equivalent, never `up` with a
  join key in argv.
- Join keys (when used for automation) arrive via stdin or a restricted
  environment handoff, matching the Linux agent's rule.
- Stop/remove:

```cmd
sc.exe stop BlakTail
sc.exe delete BlakTail
```

`cargo check` cfg-gating: add `cfg(windows)`-gated backend modules only
when the userspace implementation exists; do not add empty gating that
silently compiles to nothing.
