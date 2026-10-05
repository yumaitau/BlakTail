"use client";

import { useState, useTransition } from "react";
import { mintScimTokenAction } from "@/app/scim-actions";
import { Button } from "./ui/button";
import { SecretPanel } from "./ui/secret-panel";
import { Section } from "./ui/section";
import { toast, toastResult } from "./ui/toast";

export function ScimManager() {
  const [token, setToken] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  return (
    <Section
      id="scim"
      headingLevel={3}
      title="Directory provisioning (SCIM)"
      description="Your identity provider can create, suspend and group members here using SCIM 2.0 (Users and Groups). Password sign-in stays as the break-glass path."
      actions={
        <Button
          variant="secondary"
          loading={pending}
          loadingLabel="Creating…"
          onClick={() => {
            setToken(null);
            startTransition(async () => {
              const result = await mintScimTokenAction();
              if (!result.ok) {
                toastResult(result);
                return;
              }
              setToken(result.token);
              toast.success("SCIM token created");
            });
          }}
        >
          Create SCIM token
        </Button>
      }
    >
      <dl className="detail-list">
        <dt>SCIM base URL</dt>
        <dd className="mono">/api/scim/v2 on this console&apos;s address</dd>
        <dt>Authentication</dt>
        <dd>Bearer token, created here</dd>
      </dl>
      {token ? (
        <SecretPanel
          title="Copy the SCIM token now"
          label="SCIM token"
          secret={token}
          description="Paste it into your identity provider's provisioning settings. It's shown only once and is stored as a hash. Creating another token doesn't revoke this one."
          onDone={() => setToken(null)}
        />
      ) : null}
    </Section>
  );
}
