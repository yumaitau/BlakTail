"use client";

import { useState, useTransition } from "react";
import { mintJoinKeyAction } from "@/app/actions";
import { can, permissionReason, type OrgRole } from "@/lib/roles";

export function JoinKeyForm({ role }: { role: OrgRole }) {
  const [message, setMessage] = useState<string | null>(null);
  const [mintedKey, setMintedKey] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const canMutate = can(role, "manage_join_keys");

  if (!canMutate) {
    return (
      <p className="muted">{permissionReason(role, "manage_join_keys")}</p>
    );
  }

  return (
    <div className="stack">
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          const formData = new FormData(event.currentTarget);
          setMessage(null);
          setMintedKey(null);
          startTransition(async () => {
            const result = await mintJoinKeyAction(formData);
            if (!result.ok) {
              setMessage(result.error);
              return;
            }
            setMintedKey(result.data.key);
            setMessage(
              `Key minted. It expires at ${new Date(result.data.expiresAt * 1000).toLocaleString("en-AU")}. Copy it now; we will not show it again.`,
            );
          });
        }}
      >
        <label>
          Expires in (seconds)
          <input
            name="expiresInSeconds"
            type="number"
            min={60}
            max={2592000}
            defaultValue={3600}
            required
          />
        </label>
        <label>
          Single use
          <select name="singleUse" defaultValue="true">
            <option value="true">Yes</option>
            <option value="false">No</option>
          </select>
        </label>
        <fieldset className="stack">
          <legend>Device tags</legend>
          <label>
            <input type="checkbox" name="tags" value="office" /> Office
          </label>
          <label>
            <input type="checkbox" name="tags" value="ranger" /> Ranger
          </label>
          <label>
            <input type="checkbox" name="tags" value="store" /> Store
          </label>
        </fieldset>
        <button type="submit" disabled={pending}>
          {pending ? "Minting…" : "Mint join key"}
        </button>
      </form>
      {mintedKey ? <p className="mono">{mintedKey}</p> : null}
      {message ? (
        <p className={mintedKey ? "muted" : "error"}>{message}</p>
      ) : null}
    </div>
  );
}
