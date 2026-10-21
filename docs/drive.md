# Shared folders

A device can publish a folder to other devices on the same network, and
browse the folders those devices publish. Access follows the device's
network identity. There is no separate password.

This is not file sync. BlakSync is the sync product. A phone or tablet can
open the WebDAV URL below; there is no Files-app or Android provider
integration.

## Publish

On the device:

```bash
blaktaild drive share company-docs /absolute/path
blaktaild drive list
blaktaild drive rename company-docs docs
blaktaild drive unshare docs
```

`drive list` reads the local config and does not need the coordinator.
The other three save `shares.json` and publish it. Names are stored in
lowercase, 1–32 characters: letters, digits, hyphens, underscores,
parentheses, and spaces inside the name. A node publishes at most four
folders, all on TCP port 5647.

`drive share` records the operating-system user that published the folder
(`as` in `drive list`). That field is blank on Windows. Windows paths such
as `C:\Shared\Docs` are accepted.

`blaktaild share enable|disable|send|list` still works. `drive share`
publishes the folder as writable. A share created read-only stays read-only
even when a grant says `rw`.

## Browse

While the agent is connected it listens on `127.0.0.1:8080` and proxies
requests to peers. The path is:

```text
http://127.0.0.1:8080/<magicdns-domain>/<host>/<share>/
```

For `store.abcdef12.blaktail` and a share named `files`:

```text
http://127.0.0.1:8080/abcdef12.blaktail/store/files/
```

The browser only dials overlay addresses from the current peer map. If two
devices share a host label, the name gains the first eight characters of
the node id. Direct overlay URLs still work:

```text
http://store.abcdef12.blaktail:5647/files/
```

Finder or rclone can use either URL. `GET`, `HEAD`, `PROPFIND`, `PUT`,
`MKCOL`, `DELETE`, and `MOVE` are supported on a writable share. `COPY`,
`LOCK`, and `PROPPATCH` are refused. `PROPFIND` with `Depth: infinity` is
refused. A `PUT` is limited to 8MB and is held in memory on the sharing
device.

If port 8080 is already taken, the agent logs the failure and keeps running.
The overlay listener is unchanged.

## Policy

Without a `drive` section, any device the network policy can already reach
may open an enabled share. With a `drive` section, publishing and browsing
fail closed. See [policy.md](policy.md#shared-folders).

A device that is not allowed to publish stops its overlay listener. It
does not rewrite `shares.json` on each poll. A publish of an enabled share
from that device is rejected with the coordinator's reason. Publishing an
empty or fully disabled list is still allowed, so the device can unshare.
