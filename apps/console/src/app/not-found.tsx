import type { Metadata } from "next";
import Link from "next/link";
import { StatusPage } from "@/components/status-page";

export const metadata: Metadata = {
  title: "Page not found · BlakTail console",
};

export default function NotFound() {
  return (
    <StatusPage
      code="404 · Not found"
      title="We couldn't find that page"
      body="The link may be out of date, or the page may have moved. If you followed a link to a device or resource, it may have been removed."
      actions={
        <>
          <Link className="button" href="/control-center">
            Go to Control Center
          </Link>
          <Link className="button secondary" href="/devices">
            View devices
          </Link>
        </>
      }
    />
  );
}
