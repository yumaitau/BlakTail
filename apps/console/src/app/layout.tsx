import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";
import { Toaster } from "@/components/ui/toast";

export const metadata: Metadata = {
  title: "BlakTail console",
  description:
    "Manage BlakTail devices, join keys, and access policy for your organisation.",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Reading the request makes every page render per request, so Next can
  // stamp the CSP nonce from src/proxy.ts onto its scripts.
  await headers();
  return (
    <html lang="en-AU">
      <body>
        {children}
        <Toaster />
      </body>
    </html>
  );
}
