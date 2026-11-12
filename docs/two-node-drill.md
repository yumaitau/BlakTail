# Two-node release drill

Run this drill manually from a controller with root SSH access to two disposable
Linux VMs. For the literal NAT acceptance test, place each VM behind a different NAT
with outbound UDP allowed and no inbound port forwarding. Use a deployed Australian
coordinator and relay, two short-lived single-use join keys, and a pinned agent tag.

Install only published packages on both clean VMs using the tagged
`scripts/install-agent.sh`. Confirm both report the expected version. Then, on the
controller checkout for that same tag:

```sh
export VM1=root@vm-one.example
export VM2=root@vm-two.example
export COORD=https://coord.example.org
export JOIN_KEY1='set without writing to disk'
export JOIN_KEY2='set without writing to disk'
PREINSTALLED=1 scripts/two-vm-test.sh
unset JOIN_KEY1 JOIN_KEY2
```

Leave `ENDPOINT1` and `ENDPOINT2` unset to exercise relay/NAT fallback. The script
waits for peer convergence, then proves bidirectional IPv4, IPv6, and MagicDNS. Save
the coordinator/relay/agent logs showing relay fallback and any later nonce-confirmed
direct promotion; redact public socket addresses and never attach credentials.

For development, set `BLAKTAILD` to a locally built Linux binary instead of
`PREINSTALLED=1`. That mode tests code but does **not** satisfy release-artifact
acceptance.

After recording results, revoke both disposable nodes with `blaktaild down` or the
console, stop their agent processes, and destroy the VMs. This drill is manual. It
is not run from GitHub Actions, because this repository is public and hosted CI does
not provide the required two-NAT topology.
