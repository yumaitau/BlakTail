/** Loopback folder browser for one share. Domain comes from the MagicDNS name. */
export function folderBrowserUrl(dnsName: string, label: string): string {
  const trimmed = dnsName.trim().replace(/\.$/, "");
  const dot = trimmed.indexOf(".");
  const host = (dot === -1 ? trimmed : trimmed.slice(0, dot)).toLowerCase();
  const domain =
    dot !== -1 && trimmed.toLowerCase().endsWith(".blaktail")
      ? trimmed.slice(dot + 1).toLowerCase()
      : "blaktail";
  return `http://127.0.0.1:8080/${domain}/${host}/${label}/`;
}
