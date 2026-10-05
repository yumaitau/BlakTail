"use client";

import "./globals.css";
import { useState } from "react";
import { StatusPage } from "@/components/status-page";
import { shortRef } from "@/lib/errors";

/**
 * Last-resort boundary for errors in the root layout itself. It replaces the
 * whole document, so it renders its own <html> and <body>.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const [fallbackRef] = useState(() => shortRef());
  return (
    <html lang="en-AU">
      <body>
        <StatusPage
          code="Something went wrong"
          title="The console couldn't load"
          body="BlakTail hit a problem starting the console. Try again in a moment. If it keeps happening, contact support with the reference below."
          reference={error.digest ?? fallbackRef}
          actions={
            <>
              <button type="button" onClick={() => reset()}>
                Try again
              </button>
              {/* A plain link: the router may be what failed. */}
              <a className="button secondary" href="/control-center">
                Reload the console
              </a>
            </>
          }
        />
      </body>
    </html>
  );
}
