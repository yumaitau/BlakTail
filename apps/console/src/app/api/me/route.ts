import { errorText } from "@/lib/server-errors";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { resolveSessionContext } from "@/lib/session";

/** Browser session view. Better Auth's cookie remains unchanged. */
export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  }
  try {
    const ctx = await resolveSessionContext(session);
    return NextResponse.json({
      personId: ctx.personId,
      currentIdentity: {
        userId: ctx.userId,
        email: ctx.email,
        name: ctx.identityName,
      },
      organisations: ctx.organisations.map((organisation) => ({
        id: organisation.organisationId,
        name: organisation.organisationName,
        role: organisation.role,
        networkAccounts: organisation.networkAccountIds.map((id, index) => ({
          id,
          name:
            organisation.networkAccountNames[index] ??
            organisation.organisationName,
        })),
      })),
    });
  } catch (error) {
    return NextResponse.json(
      {
        error:
          errorText(error, "Could not resolve this session."),
      },
      { status: 403 },
    );
  }
}

