"use client";

import { useEffect, useRef, useState } from "react";
import type * as GuacamoleTypes from "guacamole-common-js";
import { startRemoteSessionAction } from "@/app/remote-access/actions";

type GuacamoleModule = typeof GuacamoleTypes;
type Phase = "idle" | "requesting" | "connecting" | "connected" | "closed";

/** Guacamole element: length in Unicode code points, as guacd counts. */
function element(value: unknown): string {
  const text = String(value);
  return `${Array.from(text).length}.${text}`;
}

function encode(elements: unknown[]): string {
  return `${elements.map(element).join(",")};`;
}

/** Splits complete instructions; the gateway only sends whole ones. */
function parse(data: string): string[][] {
  const out: string[][] = [];
  let position = 0;
  let current: string[] = [];
  while (position < data.length) {
    const dot = data.indexOf(".", position);
    if (dot < 0) break;
    const length = Number(data.slice(position, dot));
    if (!Number.isInteger(length) || length < 0) break;
    let end = dot + 1;
    for (let count = 0; count < length; count += 1) {
      const point = data.codePointAt(end);
      if (point === undefined) return out;
      end += point > 0xffff ? 2 : 1;
    }
    current.push(data.slice(dot + 1, end));
    position = end;
    const terminator = data[position];
    position += 1;
    if (terminator === ";") {
      out.push(current);
      current = [];
    } else if (terminator !== ",") {
      break;
    }
  }
  return out;
}

const CLOSE: Record<string, string> = {
  user_closed: "You ended the session.",
  idle_timeout: "Ended after 10 minutes without input.",
  max_duration: "Reached the session's time limit.",
  target_closed: "The desktop closed the connection.",
  connect_failed:
    "The gateway could not open the desktop. Check the password, that RDP is on and that policy lets the gateway reach TCP 3389.",
  revoked: "The session was revoked.",
};

export function RemoteDesktop({
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
  const display = useRef<HTMLDivElement | null>(null);
  const client = useRef<GuacamoleTypes.Client | null>(null);
  const socket = useRef<WebSocket | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const live = phase === "connecting" || phase === "connected";

  useEffect(() => {
    if (!live) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [live]);

  useEffect(() => () => socket.current?.close(), []);

  async function connect(
    started: { gatewayUrl: string; ticket: string; targetName: string; osUser: string },
    password: string,
  ) {
    const loaded = (await import("guacamole-common-js")) as unknown as {
      default?: GuacamoleModule;
    } & GuacamoleModule;
    const Guacamole = loaded.default ?? loaded;
    const tunnel = new (Guacamole.Tunnel as unknown as new () => GuacamoleTypes.Tunnel)();
    const setState = (state: GuacamoleTypes.Tunnel.State) =>
      (tunnel as unknown as { setState: (state: GuacamoleTypes.Tunnel.State) => void }).setState(state);
    const width = display.current?.clientWidth ?? 1280;
    const height = Math.round(width * 0.5625);
    tunnel.connect = () => {
      const ws = new WebSocket(`${started.gatewayUrl}/v1/session`);
      socket.current = ws;
      ws.onopen = () => {
        // The password goes to the gateway once, inside TLS, for the guacd
        // handshake. It is not stored or logged anywhere.
        ws.send(
          JSON.stringify({
            ticket: started.ticket,
            password,
            width,
            height,
            dpi: Math.round(96 * (window.devicePixelRatio || 1)),
          }),
        );
      };
      ws.onmessage = (event) => {
        if (typeof event.data !== "string") return;
        if (event.data.startsWith("{")) {
          const status = JSON.parse(event.data) as { state: string; reason?: string };
          if (status.state === "connected") {
            setPhase("connected");
            setNotice(`Connected to ${started.targetName} as ${started.osUser}.`);
            setState(Guacamole.Tunnel.State.OPEN);
          } else if (status.state === "closed") {
            setNotice(CLOSE[status.reason ?? ""] ?? `Session closed: ${status.reason ?? "unknown"}`);
          }
          return;
        }
        for (const [opcode, ...args] of parse(event.data)) {
          tunnel.oninstruction?.(opcode!, args);
        }
      };
      ws.onclose = () => {
        setState(Guacamole.Tunnel.State.CLOSED);
        setPhase("closed");
      };
      ws.onerror = () => setError("Could not reach the remote-access gateway.");
    };
    tunnel.disconnect = () => socket.current?.close(1000, "user_closed");
    tunnel.sendMessage = (...elements: unknown[]) => {
      if (socket.current?.readyState === WebSocket.OPEN && elements.length > 0) {
        socket.current.send(encode(elements));
      }
    };

    const guac = new Guacamole.Client(tunnel);
    client.current = guac;
    const host = display.current;
    if (host) {
      host.replaceChildren(guac.getDisplay().getElement());
      const mouse = new Guacamole.Mouse(guac.getDisplay().getElement());
      mouse.onEach(["mousedown", "mouseup", "mousemove"], (event) => {
        guac.sendMouseState((event as unknown as GuacamoleTypes.Mouse.Event).state);
      });
      const keyboard = new Guacamole.Keyboard(host);
      keyboard.onkeydown = (keysym) => {
        guac.sendKeyEvent(1, keysym);
        return false;
      };
      keyboard.onkeyup = (keysym) => guac.sendKeyEvent(0, keysym);
      host.focus();
    }
    guac.onerror = (status) => setError(status.message ?? "The desktop reported an error.");
    guac.connect();
  }

  return (
    <div className="stack">
      <p className="muted">
        {organisationName} · {roleName}
      </p>
      {!live ? (
        <form
          className="stack"
          aria-label={`Open a remote desktop on ${deviceName}`}
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            const password = String(form.get("password") ?? "");
            form.delete("password");
            event.currentTarget.reset();
            setError(null);
            setNotice(null);
            setPhase("requesting");
            void startRemoteSessionAction(form).then(async (result) => {
              if (!result.ok) {
                setError(result.error);
                setPhase("idle");
                return;
              }
              setPhase("connecting");
              await connect(result.data, password);
            });
          }}
        >
          <input type="hidden" name="organisationId" value={organisationId} />
          <input type="hidden" name="nodeId" value={nodeId} />
          <input type="hidden" name="kind" value="rdp" />
          <label>
            Windows or xrdp account (DOMAIN\user allowed)
            <input name="osUser" required autoComplete="off" spellCheck={false} disabled={disabledReason !== null} />
          </label>
          <label>
            Password (sent once to the gateway for this session; never stored)
            <input name="password" type="password" required autoComplete="off" disabled={disabledReason !== null} />
          </label>
          <label>
            Reason for access (recorded in the audit log)
            <input name="reason" required minLength={4} maxLength={200} disabled={disabledReason !== null} />
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
              {phase === "requesting" ? "Requesting…" : "Open remote desktop"}
            </button>
          </div>
          {disabledReason ? <p className="muted">{disabledReason}</p> : null}
        </form>
      ) : (
        <div className="row">
          <button type="button" className="danger" onClick={() => client.current?.disconnect()}>
            End session
          </button>
          <span className="muted">Clipboard uses your browser; file transfer and drives are off.</span>
        </div>
      )}
      <div
        ref={display}
        className="remote-desktop"
        tabIndex={0}
        role="application"
        aria-label={`Remote desktop on ${deviceName}`}
        hidden={!live}
      />
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
