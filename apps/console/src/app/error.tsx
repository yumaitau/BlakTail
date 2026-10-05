"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { StatusPage } from "@/components/status-page";
import { shortRef } from "@/lib/errors";

/**
 * Catches errors thrown while rendering a page. In production Next replaces
 * the message with a `digest` that matches the server log line, so the digest
 * is the reference people quote. The message itself is never shown.
 */
export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Console page error", error.digest ?? "", error.name);
  }, [error]);

  const [fallbackRef] = useState(() => shortRef());
  const reference = error.digest ?? fallbackRef;
  return (
    <StatusPage
      code="Something went wrong"
      title="This page couldn't load"
      body="BlakTail hit a problem showing this page. Try again, and if it keeps happening, contact support with the reference below."
      reference={reference}
      actions={
        <>
          <button type="button" onClick={() => reset()}>
            Try again
          </button>
          <Link className="button secondary" href="/control-center">
            Go to Control Center
          </Link>
        </>
      }
    />
  );
}
