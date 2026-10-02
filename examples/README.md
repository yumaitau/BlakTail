# Examples

Annotated inputs for a laptop Compose stack. Secrets stay out of git; generate
them with `scripts/quickstart.sh` or copy [env.local](env.local) to `.env` and
replace every `change-me` value.

| File | Use |
| --- | --- |
| [env.local](env.local) | Compose environment for `localhost` |
| [agent.toml](agent.toml) | Agent file config for the same stack |
| [automation/](automation/README.md) | `/api/v1` curl walkthrough and read-only-by-default Terraform |
| [../config/blaktail.toml.example](../config/blaktail.toml.example) | Full schema-v1 reference for coordinator, relay, agent, and console |

`scripts/quickstart.sh` writes `.env` and copies the coordinator CA to
`certs/ca.crt`. Coordinator private keys stay in the Compose `coordcerts`
volume. Point the agent at `--coord https://127.0.0.1:8443` and
`--coord-ca certs/ca.crt` (or `BLAKTAIL_COORD_CA`). The CA path is a flag or
environment variable, not a TOML field.
