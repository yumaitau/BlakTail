"use client";

import "@xterm/xterm/css/xterm.css";
import { useCallback, useEffect, useRef, useState } from "react";
import type { Terminal } from "@xterm/xterm";
import type { FitAddon } from "@xterm/addon-fit";
import { startRemoteSessionAction, type StartedSession } from "@/app/remote-access/actions";

type Phase = "idle" | "requesting" | "connecting" | "connected" | "closed";

type GatewayStatus = {
  type: "status";
  state: "connecting" | "connected" | "closed";
  reason?: string;
  target?: string;
  os_user?: string;
  max_end_at?: number;
};

const CLOSE_REASONS: Record<string, string> = {
  user_closed: "You ended the session.",
  idle_timeout: "Ended after 10 minutes without input.",
  max_duration: "Reached the session's time limit. Start a new session to continue.",
  target_closed: "The device closed the shell.",
  host_key_mismatch:
    "Refused: the device presented an SSH host key that does not match the one its agent reported. Nothing was sent to it. Check the device before accepting a new key.",
  connect_failed:
    "The gateway could not reach the device over the overlay. Check that it is online and that policy lets the gateway reach TCP 22.",
  auth_failed:
    "The device refused the session certificate. Check that its agent has installed the organisation SSH CA and that the account exists.",
  revoked: "The session was revoked.",
};

function closeMessage(reason: string | undefined): string {
  if (!reason) return "Session closed.";
  if (CLOSE_REASONS[reason]) return CLOSE_REASONS[reason];
  if (reason.startsWith("policy")) return `Ended by policy: ${reason.replace(/^policy:\s*/, "")}`;
  return `Session closed: ${reason}`;
}

function clock(seconds: number): string {
  return new Date(seconds * 1000).toLocaleTimeString("en-AU", { timeStyle: "short" });
}

export function RemoteTerminal({
  organisationId,
  organisationName,
  roleName,
  nodeId,
  deviceName,
  disabledReason,
}: {
  organisationId: string;
  organisationName: string;
  roleName: string;
  nodeId: string;
  deviceName: string;
  disabledReason: string | null;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const endButton = useRef<HTMLButtonElement | null>(null);
  const socket = useRef<WebSocket | null>(null);
  const terminal = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [session, setSession] = useState<StartedSession | null>(null);

  const live = phase === "connecting" || phase === "connected";

  // Leaving the page with a live shell asks first; closing the tab closes
  // the socket and the gateway records the session as ended.
  useEffect(() => {
    if (!live) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [live]);

  useEffect(
    () => () => {
      socket.current?.close();
      terminal.current?.dispose();
    },
    [],
  );

  const end = useCallback(() => {
    socket.current?.close(1000, "user_closed");
  }, []);

  async function connect(started: StartedSession) {
    const [{ Terminal }, { FitAddon }] = await Promise.all([
      import("@xterm/xterm"),
      import("@xterm/addon-fit"),
    ]);
    terminal.current?.dispose();
    const term = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      fontSize: 14,
      screenReaderMode: true,
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    if (host.current) {
      term.open(host.current);
      fitAddon.fit();
    }
    // Ctrl+Alt+E leaves the terminal, which otherwise keeps Tab for the shell.
    term.attachCustomKeyEventHandler((event) => {
      if (event.type === "keydown" && event.ctrlKey && event.altKey && event.key.toLowerCase() === "e") {
        endButton.current?.focus();
        return false;
      }
      return true;
    });
    terminal.current = term;
    fit.current = fitAddon;

    const ws = new WebSocket(`${started.gatewayUrl}/v1/session`);
    ws.binaryType = "arraybuffer";
    socket.current = ws;
    const encoder = new TextEncoder();
    ws.onopen = () => {
      ws.send(JSON.stringify({ ticket: started.ticket, cols: term.cols, rows: term.rows }));
    };
    ws.onmessage = (event) => {
      if (typeof event.data === "string") {
        let status: GatewayStatus | null = null;
        try {
          status = JSON.parse(event.data) as GatewayStatus;
        } catch {
          return;
        }
        if (status.state === "connected") {
          setPhase("connected");
          setNotice(
            `Connected to ${status.target ?? started.targetName} as ${status.os_user ?? started.osUser}. Ends by ${clock(status.max_end_at ?? started.maxEndAt)}.`,
          );
          term.focus();
        } else if (status.state === "closed") {
          setNotice(closeMessage(status.reason));
        }
        return;
      }
      term.write(new Uint8Array(event.data as ArrayBuffer));
    };
    ws.onclose = () => {
      setPhase("closed");
      setNotice((current) => current ?? "Session closed.");
      socket.current = null;
    };
    ws.onerror = () => {
      setError(
        "Could not reach the remote-access gateway. Check that it is running and that this console's address is an allowed origin.",
      );
    };
    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(encoder.encode(data));
    });
    term.onResize(({ cols, rows }) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols, rows }));
      }
    });
  }

  useEffect(() => {
    if (!live) return;
    const onResize = () => fit.current?.fit();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [live]);

  return (
    <div className="stack">
      <p className="muted">
        {organisationName} · {roleName}
      </p>
      {phase === "idle" || phase === "requesting" || phase === "closed" ? (
        <form
          className="stack"
          aria-label={`Open an SSH session to ${deviceName}`}
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            setError(null);
            setNotice(null);
            setPhase("requesting");
            void startRemoteSessionAction(form).then(async (result) => {
              if (!result.ok) {
                setError(result.error);
                setPhase("idle");
                return;
              }
              setSession(result.data);
              setPhase("connecting");
              await connect(result.data);
            });
          }}
        >
          <input type="hidden" name="organisationId" value={organisationId} />
          <input type="hidden" name="nodeId" value={nodeId} />
          <input type="hidden" name="kind" value="ssh" />
          <label>
            Log in as (OS account)
            <input
              name="osUser"
              required
              autoComplete="off"
              spellCheck={false}
              pattern="[A-Za-z_][A-Za-z0-9._-]{0,31}"
              placeholder="deploy"
              disabled={disabledReason !== null}
            />
          </label>
          <label>
            Reason for access (recorded in the audit log)
            <input
              name="reason"
              required
              minLength={4}
              maxLength={200}
              placeholder="Restart the stock service after the update"
              disabled={disabledReason !== null}
            />
          </label>
          <label>
            Session length (minutes, up to 30)
            <input
              name="durationMinutes"
              type="number"
              min={1}
              max={30}
              defaultValue={30}
              disabled={disabledReason !== null}
            />
          </label>
          <div className="row">
            <button type="submit" disabled={disabledReason !== null || phase === "requesting"}>
              {phase === "requesting" ? "Requesting…" : phase === "closed" ? "Start a new session" : "Open terminal"}
            </button>
          </div>
          {disabledReason ? <p className="muted">{disabledReason}</p> : null}
        </form>
      ) : null}
      {live ? (
        <div className="row">
          <button ref={endButton} type="button" className="danger" onClick={end}>
            End session
          </button>
          <span className="muted">
            Ctrl+Alt+E moves focus out of the terminal. Copy and paste use your browser&apos;s clipboard; file transfer is off.
          </span>
        </div>
      ) : null}
      <div
        ref={host}
        className="remote-terminal"
        role="region"
        aria-label={`Terminal on ${deviceName}`}
        hidden={phase === "idle" || phase === "requesting"}
      />
      {session && live ? (
        <p className="muted">
          Session {session.sessionId.slice(0, 8)} · {session.osUser}@{session.targetName}
        </p>
      ) : null}
      {notice ? (
        <p className="muted" role="status" aria-live="polite">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
