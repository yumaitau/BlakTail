"use client";

import { useRef, useState, useTransition } from "react";
import { authClient } from "@/lib/auth-client";
import { authErrorMessage } from "@/lib/errors";
import { Button } from "./ui/button";
import { FormField } from "./ui/form-field";
import { Section } from "./ui/section";
import { toast } from "./ui/toast";

const MIN_LENGTH = 10;

type Field = "currentPassword" | "newPassword" | "confirmPassword";

/** Changes the signed-in person's own password and signs out their other sessions. */
export function ChangePassword() {
  const [pending, startTransition] = useTransition();
  const [errors, setErrors] = useState<Partial<Record<Field, string>>>({});
  const formRef = useRef<HTMLFormElement>(null);

  function fail(field: Field, message: string) {
    setErrors({ [field]: message });
    formRef.current?.querySelector<HTMLInputElement>(`[name="${field}"]`)?.focus();
  }

  return (
    <Section
      id="password"
      title="Password"
      description="Change the password you use to sign in. Other browsers and devices signed in with it are signed out; this one stays signed in."
    >
      <form
        ref={formRef}
        className="ui-form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const currentPassword = String(form.get("currentPassword") ?? "");
          const newPassword = String(form.get("newPassword") ?? "");
          const confirmPassword = String(form.get("confirmPassword") ?? "");
          setErrors({});
          if (!currentPassword) {
            fail("currentPassword", "Enter your current password.");
            return;
          }
          if (newPassword.length < MIN_LENGTH) {
            fail("newPassword", `Use at least ${MIN_LENGTH} characters.`);
            return;
          }
          if (newPassword !== confirmPassword) {
            fail("confirmPassword", "The new passwords don't match.");
            return;
          }
          if (newPassword === currentPassword) {
            fail("newPassword", "Choose a password different from your current one.");
            return;
          }
          startTransition(async () => {
            const result = await authClient.changePassword({
              currentPassword,
              newPassword,
              revokeOtherSessions: true,
            });
            if (result.error) {
              const user = authErrorMessage(result.error, "Your password wasn't changed. Try again.");
              if (result.error.code?.toUpperCase() === "INVALID_PASSWORD") {
                fail("currentPassword", user.message);
              } else {
                toast.error(user.message, { reference: user.ref });
              }
              return;
            }
            formElement.reset();
            toast.success("Password changed", {
              description: "Other browsers and devices were signed out.",
            });
          });
        }}
      >
        <FormField label="Current password" required error={errors.currentPassword}>
          <input name="currentPassword" type="password" autoComplete="current-password" />
        </FormField>
        <FormField
          label="New password"
          hint={`At least ${MIN_LENGTH} characters.`}
          required
          error={errors.newPassword}
        >
          <input
            name="newPassword"
            type="password"
            autoComplete="new-password"
            minLength={MIN_LENGTH}
          />
        </FormField>
        <FormField label="Confirm new password" required error={errors.confirmPassword}>
          <input
            name="confirmPassword"
            type="password"
            autoComplete="new-password"
            minLength={MIN_LENGTH}
          />
        </FormField>
        <div className="actions">
          <Button type="submit" loading={pending} loadingLabel="Changing…">
            Change password
          </Button>
        </div>
      </form>
    </Section>
  );
}
