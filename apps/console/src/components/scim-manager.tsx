"use client";

import { useState, useTransition } from "react";
import { mintScimTokenAction } from "@/app/scim-actions";

export function ScimManager() {
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  return (
    <section className="panel stack" aria-labelledby="scim-heading">
      <h2 id="scim-heading">Directory provisioning</h2>
      <p className="muted">
        SCIM sits beside single sign-on. The identity provider creates and
        suspends members here. Password sign-in stays the break-glass path.
        Point the provider at <span className="mono">/api/scim/v2</span> with
        the bearer token.
      </p>
      <button
        type="button"
        className="secondary"
        disabled={pending}
        onClick={() => {
          setError(null);
          startTransition(async () => {
            const result = await mintScimTokenAction();
            if (!result.ok) {
              setError(result.error);
              return;
            }
            setToken(result.token);
          });
        }}
      >
        {pending ? "Minting…" : "Mint SCIM token"}
      </button>
      {token ? (
        <label>
          Token, shown once
          <input readOnly value={token} />
        </label>
      ) : null}
      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}
