import Link from "next/link";

export function Wordmark({ href = "/control-center" }: { href?: string }) {
  return (
    <Link className="wordmark" href={href} aria-label="BlakTail home">
      <svg
        className="wordmark-mark"
        width="22"
        height="22"
        viewBox="0 0 22 22"
        aria-hidden="true"
      >
        <path
          d="M4 16 C 7 16, 8 7, 12 7 S 16 16, 19 12"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.7"
          strokeLinecap="round"
        />
        <circle cx="4" cy="16" r="1.6" fill="var(--primary)" />
        <circle cx="12" cy="7" r="1.6" fill="var(--foreground)" />
        <circle cx="19" cy="12" r="1.6" fill="var(--primary)" />
      </svg>
      <span>
        <span className="wordmark-blak">Blak</span>
        <span className="wordmark-tail">Tail</span>
      </span>
    </Link>
  );
}
