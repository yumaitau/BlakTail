import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { nextCookies } from "better-auth/next-js";
import { twoFactor } from "better-auth/plugins/two-factor";
import { db } from "./db/client";
import * as schema from "./db/schema";

const betterAuthSecret = process.env.BETTER_AUTH_SECRET;
if (!betterAuthSecret || Buffer.byteLength(betterAuthSecret) < 32) {
  throw new Error("BETTER_AUTH_SECRET must be at least 32 bytes.");
}

export const auth = betterAuth({
  appName: "BlakTail",
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
  secret: betterAuthSecret,
  database: drizzleAdapter(db(), {
    provider: "pg",
    schema: {
      user: schema.user,
      session: schema.session,
      account: schema.account,
      verification: schema.verification,
      rateLimit: schema.rateLimit,
      twoFactor: schema.twoFactor,
    },
  }),
  emailAndPassword: {
    enabled: true,
    disableSignUp: true,
    minPasswordLength: 10,
  },
  rateLimit: {
    enabled: true,
    storage: "database",
    window: 60,
    max: 20,
    customRules: {
      "/sign-in/email": { window: 60, max: 10 },
      "/sign-up/email": { window: 60, max: 3 },
      "/two-factor/*": { window: 60, max: 10 },
    },
  },
  session: {
    expiresIn: 60 * 60 * 24 * 7,
    updateAge: 60 * 60 * 24,
  },
  trustedOrigins: (
    process.env.BETTER_AUTH_TRUSTED_ORIGINS ??
    process.env.BETTER_AUTH_URL ??
    "http://localhost:3000"
  )
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  plugins: [
    // TOTP with encrypted secret and backup codes for password sign-ins.
    // No email/SMS OTP and no "trust this device": every password sign-in
    // of an enrolled identity asks for a code.
    twoFactor({
      issuer: "BlakTail",
      backupCodeOptions: { amount: 10, length: 10, storeBackupCodes: "encrypted" },
      accountLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
    }),
    nextCookies(),
  ],
});

export type Session = typeof auth.$Infer.Session;
