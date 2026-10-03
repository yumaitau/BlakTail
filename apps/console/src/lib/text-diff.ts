export type DiffLine = { kind: "same" | "added" | "removed"; text: string };

// Line diff via longest common subsequence. Inputs are small DNS documents
// (bounded by the coordinator's 64 KiB body limit), so O(n*m) is fine.
export function lineDiff(before: string, after: string): DiffLine[] {
  const a = before.split("\n");
  const b = after.split("\n");
  const lcs: number[][] = Array.from({ length: a.length + 1 }, () =>
    new Array<number>(b.length + 1).fill(0),
  );
  for (let i = a.length - 1; i >= 0; i -= 1) {
    for (let j = b.length - 1; j >= 0; j -= 1) {
      lcs[i]![j] =
        a[i] === b[j]
          ? lcs[i + 1]![j + 1]! + 1
          : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i]! });
      i += 1;
      j += 1;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      out.push({ kind: "removed", text: a[i]! });
      i += 1;
    } else {
      out.push({ kind: "added", text: b[j]! });
      j += 1;
    }
  }
  while (i < a.length) out.push({ kind: "removed", text: a[i++]! });
  while (j < b.length) out.push({ kind: "added", text: b[j++]! });
  return out;
}
