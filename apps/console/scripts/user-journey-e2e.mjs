#!/usr/bin/env bun
/**
 * Operator journey: a device asks to join, the owner signs in, matches the
 * WireGuard fingerprint, approves, and then sees that device on the inventory.
 *
 *   CONSOLE_URL=https://127.0.0.1:3443 \
 *   COORD_URL=https://coord:18443 \
 *   COORD_RESOLVE=coord:18443:127.0.0.1 \
 *   COORD_CA_FILE=/path/to/ca.crt \
 *   CONSOLE_EMAIL=owner@example.org.au \
 *   CONSOLE_PASSWORD_FILE=/path/to/0600-password \
 *   bun scripts/user-journey-e2e.mjs
 *
 * COORD_RESOLVE is an optional curl --resolve value when the coordinator
 * certificate name is not the host in COORD_URL.
 */

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { connect, createServer } from "node:net";
import { chromium } from "playwright-core";

function requiredEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function readPassword() {
  if (process.env.CONSOLE_PASSWORD?.trim()) {
    return process.env.CONSOLE_PASSWORD.trim();
  }
  const path = requiredEnv("CONSOLE_PASSWORD_FILE");
  const metadata = await stat(path);
  if (!metadata.isFile()) throw new Error("CONSOLE_PASSWORD_FILE must be a regular file");
  if ((metadata.mode & 0o077) !== 0) {
    throw new Error("CONSOLE_PASSWORD_FILE must not be readable by group or other");
  }
  const password = (await readFile(path, "utf8")).trim();
  if (!password) throw new Error("CONSOLE_PASSWORD_FILE is empty");
  return password;
}

function fingerprint(publicKey) {
  return createHash("sha256").update(publicKey).digest("hex").slice(0, 12);
}

function coord(method, path, body) {
  const args = [
    "--silent",
    "--show-error",
    "--cacert",
    requiredEnv("COORD_CA_FILE"),
    "--request",
    method,
    "--write-out",
    "\n%{http_code}",
    "--header",
    "content-type: application/json",
  ];
  const resolve = process.env.COORD_RESOLVE?.trim();
  if (resolve) args.push("--resolve", resolve);
  if (body !== undefined) args.push("--data-binary", JSON.stringify(body));
  args.push(`${requiredEnv("COORD_URL").replace(/\/$/u, "")}${path}`);
  const result = spawnSync("curl", args, { encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr || `curl exited ${result.status}`);
  }
  const text = result.stdout ?? "";
  const split = text.lastIndexOf("\n");
  const payload = split === -1 ? "" : text.slice(0, split);
  const status = Number(split === -1 ? text : text.slice(split + 1));
  let json = null;
  if (payload) {
    try {
      json = JSON.parse(payload);
    } catch {
      json = null;
    }
  }
  return { status, json, payload };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("could not allocate a CDP port"));
        return;
      }
      const { port } = address;
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
    server.on("error", reject);
  });
}

async function resolveLightpanda() {
  const configured = process.env.LIGHTPANDA_BIN?.trim();
  if (configured) return configured;
  const home = process.env.HOME ?? "";
  const which = spawnSync("sh", ["-c", "command -v lightpanda"], { encoding: "utf8" });
  if (which.status === 0 && which.stdout.trim()) return which.stdout.trim();
  for (const candidate of [
    home ? `${home}/.local/bin/lightpanda` : "",
    "/opt/homebrew/bin/lightpanda",
    "/usr/local/bin/lightpanda",
  ].filter(Boolean)) {
    if ((await Bun.file(candidate).exists()) && spawnSync("test", ["-x", candidate]).status === 0) {
      return candidate;
    }
  }
  throw new Error("lightpanda is not installed. Install the nightly binary or set LIGHTPANDA_BIN.");
}

async function waitForCdp(url, child) {
  const deadline = Date.now() + 15_000;
  const httpUrl = url.replace(/^ws:/u, "http:");
  while (Date.now() < deadline) {
    if (child?.exitCode !== null && child?.exitCode !== undefined) {
      throw new Error(`lightpanda exited early with ${child.exitCode}`);
    }
    try {
      const response = await fetch(`${httpUrl}/json/version`);
      if (response.ok) return;
    } catch {
      // still starting
    }
    await Bun.sleep(100);
  }
  throw new Error(`lightpanda CDP did not become ready at ${url}`);
}

async function startLightpanda() {
  if (process.env.LIGHTPANDA_CDP_URL?.trim()) {
    return { url: process.env.LIGHTPANDA_CDP_URL.trim(), child: null };
  }
  const bin = await resolveLightpanda();
  const port = await freePort();
  const child = spawn(
    bin,
    [
      "serve",
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--insecure-disable-tls-host-verification",
      "--enable-external-stylesheets",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  const url = `ws://127.0.0.1:${port}`;
  try {
    await waitForCdp(url, child);
  } catch (error) {
    child.kill("SIGTERM");
    throw error;
  }
  return { url, child };
}

async function waitForPort(url) {
  const parsed = new URL(url);
  const port = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const ready = await new Promise((resolve) => {
      const socket = connect({ host: parsed.hostname, port }, () => {
        socket.end();
        resolve(true);
      });
      socket.on("error", () => resolve(false));
    });
    if (ready) return;
    await Bun.sleep(150);
  }
  throw new Error(`console is not accepting connections at ${parsed.hostname}:${port}`);
}

async function signIn(page, origin, email, password) {
  const response = await page.goto(`${origin}/sign-in`, {
    waitUntil: "load",
    timeout: 30_000,
  });
  const html = await page.content();
  if (!html.includes('name="email"') && !html.includes("name='email'")) {
    throw new Error(
      `sign-in page missing email field (status=${response?.status()} url=${page.url()})`,
    );
  }
  await page.evaluate(
    ({ nextEmail, nextPassword }) => {
      const assign = (selector, value) => {
        const field = document.querySelector(selector);
        if (!(field instanceof HTMLInputElement)) throw new Error(`missing ${selector}`);
        const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
        descriptor?.set?.call(field, value);
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      };
      assign("input[name='email']", nextEmail);
      assign("input[name='password']", nextPassword);
      const form = document.querySelector(".sign-in-card form");
      if (!(form instanceof HTMLFormElement)) throw new Error("missing sign-in form");
      if (typeof form.requestSubmit === "function") form.requestSubmit();
      else form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    },
    { nextEmail: email, nextPassword: password },
  );
  await page.waitForFunction(
    () => document.querySelector("h1")?.textContent?.trim() === "Devices",
    undefined,
    { timeout: 20_000 },
  );
}

async function clickNamed(page, name) {
  const clicked = await page.evaluate((nextName) => {
    const match = [...document.querySelectorAll("button")].find(
      (button) => button.textContent?.trim() === nextName,
    );
    if (!(match instanceof HTMLElement)) return false;
    match.click();
    return true;
  }, name);
  assert(clicked, `missing button ${name}`);
}

async function main() {
  const origin = requiredEnv("CONSOLE_URL").replace(/\/$/u, "");
  const email = requiredEnv("CONSOLE_EMAIL");
  const password = await readPassword();
  const deviceName = `journey-${randomBytes(3).toString("hex")}`;
  const publicKey = randomBytes(32).toString("base64");
  const expectedFingerprint = fingerprint(publicKey);

  const started = coord("POST", "/v1/device-authorizations", {
    name: deviceName,
    wg_public_key: publicKey,
  });
  assert(
    started.status === 201 && started.json?.user_code && started.json?.device_code,
    `device did not receive an enrolment code (${started.status})`,
  );
  const userCode = String(started.json.user_code);
  const deviceCode = String(started.json.device_code);
  console.log(`ok device asked to join as ${deviceName}`);

  await waitForPort(`${origin}/sign-in`);
  const { url, child } = await startLightpanda();
  let browser;
  try {
    browser = await chromium.connectOverCDP({ endpointURL: url });
    const context = await browser.newContext({
      baseURL: origin,
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();
    try {
      await signIn(page, origin, email, password);
      console.log("ok owner signed in");

      await page.goto(`${origin}/enroll?code=${encodeURIComponent(userCode)}`, {
        waitUntil: "load",
        timeout: 30_000,
      });
      await page.waitForFunction(
        () => document.querySelector("h1")?.textContent?.trim() === "Approve device",
        undefined,
        { timeout: 15_000 },
      );
      const approval = (await page.locator("body").innerText()) ?? "";
      assert(approval.includes(deviceName), "enrolment page did not show the device name");
      assert(
        approval.includes(expectedFingerprint),
        "enrolment page did not show the WireGuard fingerprint",
      );
      assert(approval.includes(userCode), "enrolment page did not show the device code");
      console.log("ok owner matched the device name and fingerprint");

      const office = await page.evaluate(() => {
        const box = document.querySelector("input[name='tags'][value='office']");
        if (!(box instanceof HTMLInputElement)) return false;
        box.click();
        return box.checked;
      });
      assert(office, "owner could not select the office tag");
      await clickNamed(page, "Approve this device");
      await page.waitForFunction(
        () => (document.body.innerText ?? "").includes("Device approved"),
        undefined,
        { timeout: 20_000 },
      );
      console.log("ok owner approved the device");

      const polled = coord("GET", `/v1/device-authorizations/${encodeURIComponent(deviceCode)}`);
      assert(
        polled.status === 200 && polled.json?.status === "approved",
        `device was not told the approval succeeded (${polled.status} ${polled.json?.status ?? ""})`,
      );
      const registered = coord("POST", "/v1/nodes/register", {
        join_key: deviceCode,
        name: deviceName,
        wg_public_key: publicKey,
        os: "linux",
        hostname: deviceName,
      });
      assert(
        registered.status === 201 && registered.json?.dns_name && registered.json?.assigned_ip,
        `device did not join after approval (${registered.status})`,
      );
      console.log("ok device joined the network");

      await page.goto(`${origin}/devices`, { waitUntil: "load", timeout: 30_000 });
      await page.waitForFunction(
        () => document.querySelector("h1")?.textContent?.trim() === "Devices",
        undefined,
        { timeout: 15_000 },
      );
      await page.evaluate((name) => {
        const field = document.querySelector("input[placeholder='Name, DNS, network, or person']");
        if (!(field instanceof HTMLInputElement)) throw new Error("missing device search");
        const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
        descriptor?.set?.call(field, name);
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      }, deviceName);
      await page.waitForFunction(
        (name) => (document.body.innerText ?? "").includes(name),
        deviceName,
        { timeout: 15_000 },
      );
      const inventory = (await page.locator("body").innerText()) ?? "";
      assert(inventory.includes("Connected places"), "Devices page is missing the summary");
      assert(inventory.includes(registered.json.dns_name), "Devices page is missing the DNS name");
      console.log("ok inventory shows the new device");

      const opened = await page.evaluate((name) => {
        const row = [...document.querySelectorAll("tr")].find((candidate) =>
          candidate.textContent?.includes(name),
        );
        const button = [...(row?.querySelectorAll("button") ?? [])].find(
          (item) => item.textContent?.trim() === "Details",
        );
        if (!(button instanceof HTMLElement)) return false;
        button.click();
        return true;
      }, deviceName);
      assert(opened, "could not open the device details");
      const friendly = `Journey ${deviceName.slice(-4)}`;
      await page.evaluate((nextName) => {
        const field = document.querySelector("input[name='friendlyName']");
        if (!(field instanceof HTMLInputElement)) throw new Error("missing friendly name");
        const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
        descriptor?.set?.call(field, nextName);
        field.dispatchEvent(new Event("input", { bubbles: true }));
        field.dispatchEvent(new Event("change", { bubbles: true }));
      }, friendly);
      await clickNamed(page, "Save name");
      await page.waitForFunction(
        (nextName) => (document.body.innerText ?? "").includes(`shown as ${nextName}`),
        friendly,
        { timeout: 20_000 },
      );
      console.log("ok owner saved a friendly name");

      await page.goto(`${origin}/status`, { waitUntil: "load", timeout: 30_000 });
      await page.waitForFunction(
        () => document.querySelector("h1")?.textContent?.trim() === "Status",
        undefined,
        { timeout: 15_000 },
      );
      const status = (await page.locator("body").innerText()) ?? "";
      assert(status.includes("ready"), "Status page did not show the coordinator as ready");
      assert(!status.includes("Unreachable"), "Status page reported the coordinator as unreachable");
      console.log("ok status shows the coordinator");
    } finally {
      await page.close();
      await context.close();
    }
  } finally {
    await browser?.close().catch(() => undefined);
    child?.kill("SIGTERM");
  }
  console.log("user_journey_e2e passed");
}

void main().catch((error) => {
  process.stderr.write(
    `user journey failed: ${error instanceof Error ? error.message : error}\n`,
  );
  process.exitCode = 1;
});
