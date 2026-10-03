#!/usr/bin/env bun
/**
 * Console UI smoke via Playwright-core over Lightpanda CDP.
 *
 * Starts `lightpanda serve` unless LIGHTPANDA_CDP_URL is already set
 * (for example when Cursor is running `lightpanda mcp --cdp-port 9222`).
 *
 *   CONSOLE_URL=https://127.0.0.1:3443 \
 *   CONSOLE_EMAIL=owner@homelab.test \
 *   CONSOLE_PASSWORD_FILE=/path/to/0600-password \
 *   CONSOLE_SSH_TUNNEL=homelab \
 *   bun --filter @blaktail/console test:ui
 */

import { spawn } from "node:child_process";
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
    throw new Error("CONSOLE_PASSWORD_FILE must not be readable by group/other");
  }
  const password = (await readFile(path, "utf8")).trim();
  if (!password) throw new Error("CONSOLE_PASSWORD_FILE is empty");
  return password;
}

async function resolveLightpanda() {
  const configured = process.env.LIGHTPANDA_BIN?.trim();
  if (configured) return configured;
  const home = process.env.HOME ?? "";
  const which = Bun.spawnSync(["sh", "-c", "command -v lightpanda"]);
  if (which.exitCode === 0) {
    return new TextDecoder().decode(which.stdout).trim();
  }
  for (const candidate of [
    home ? `${home}/.local/bin/lightpanda` : "",
    "/opt/homebrew/bin/lightpanda",
    "/usr/local/bin/lightpanda",
  ].filter(Boolean)) {
    if ((await Bun.file(candidate).exists()) && Bun.spawnSync(["test", "-x", candidate]).exitCode === 0) {
      return candidate;
    }
  }
  throw new Error(
    "lightpanda is not installed. Install the nightly binary or set LIGHTPANDA_BIN.",
  );
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

function startSshTunnel(spec, localUrl) {
  const parsed = new URL(localUrl);
  const localPort = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
  const child = spawn(
    "ssh",
    [
      "-N",
      "-o",
      "BatchMode=yes",
      "-o",
      "ExitOnForwardFailure=yes",
      "-L",
      `${localPort}:127.0.0.1:${localPort}`,
      spec,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  return {
    child,
    close: () => {
      child.kill("SIGTERM");
    },
  };
}

async function waitForLoopback(url) {
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
  throw new Error(`SSH tunnel did not expose ${parsed.hostname}:${port}`);
}

async function startLightpanda() {
  if (process.env.LIGHTPANDA_CDP_URL?.trim()) {
    return { url: process.env.LIGHTPANDA_CDP_URL.trim(), child: null };
  }
  const bin = await resolveLightpanda();
  const port = await freePort();
  const args = [
    "serve",
    "--host",
    "127.0.0.1",
    "--port",
    String(port),
    "--insecure-disable-tls-host-verification",
    "--enable-external-stylesheets",
  ];
  const caFile = process.env.CONSOLE_CA_FILE?.trim();
  if (caFile) args.push("--ca-cert", caFile);
  const child = spawn(
    bin,
    args,
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let log = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream?.on("data", (chunk) => {
      log = (log + chunk.toString()).slice(-8_000);
    });
  }
  const url = `ws://127.0.0.1:${port}`;
  try {
    await waitForCdp(url, child);
  } catch (error) {
    child.kill("SIGTERM");
    throw new Error(`${error instanceof Error ? error.message : error}\n${log}`);
  }
  return { url, child };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function clickFirst(page, selector, label) {
  const clicked = await page.evaluate((nextSelector) => {
    const node = document.querySelector(nextSelector);
    if (!(node instanceof HTMLElement)) return false;
    node.click();
    return true;
  }, selector);
  assert(clicked, `missing ${label} (${selector})`);
}

async function fillField(page, selector, value) {
  await page.evaluate(
    ({ nextSelector, nextValue }) => {
      const field = document.querySelector(nextSelector);
      if (!(field instanceof HTMLInputElement) && !(field instanceof HTMLTextAreaElement)) {
        throw new Error(`missing ${nextSelector}`);
      }
      const descriptor = Object.getOwnPropertyDescriptor(
        field instanceof HTMLTextAreaElement
          ? HTMLTextAreaElement.prototype
          : HTMLInputElement.prototype,
        "value",
      );
      descriptor?.set?.call(field, nextValue);
      field.dispatchEvent(new Event("input", { bubbles: true }));
      field.dispatchEvent(new Event("change", { bubbles: true }));
    },
    { nextSelector: selector, nextValue: value },
  );
}

async function selectFirstPerson(page, selector) {
  return page.evaluate((nextSelector) => {
    const field = document.querySelector(nextSelector);
    if (!(field instanceof HTMLSelectElement) || field.options.length < 2) {
      throw new Error(`missing people in ${nextSelector}`);
    }
    field.selectedIndex = 1;
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
    return field.options[1]?.text ?? "";
  }, selector);
}

async function clickButton(page, name, testid) {
  const clicked = await page.evaluate(
    ({ nextName, nextTestid }) => {
      const tagged = document.querySelector(`[data-testid='${nextTestid}']`);
      if (tagged instanceof HTMLElement) {
        tagged.click();
        return true;
      }
      const match = [...document.querySelectorAll("button")].find(
        (button) => button.textContent?.trim() === nextName,
      );
      if (!match) return false;
      match.click();
      return true;
    },
    { nextName: name, nextTestid: testid },
  );
  assert(clicked, `missing button ${name}`);
}

async function runUi(page, baseUrl, email, password) {
  const origin = baseUrl.replace(/\/$/u, "");
  const response = await page.goto(`${origin}/sign-in`, {
    waitUntil: "load",
    timeout: 30_000,
  });
  const html = await page.content();
  if (!html.includes('name="email"') && !html.includes("name='email'")) {
    throw new Error(
      `sign-in page missing email field (status=${response?.status()} url=${page.url()} html=${html.slice(0, 800)})`,
    );
  }
  await page.waitForFunction(
    () => document.querySelector("h1")?.textContent?.trim() === "Sign in",
    undefined,
    { timeout: 15_000 },
  );
  await page.evaluate(
    ({ nextEmail, nextPassword }) => {
      const assign = (selector, value) => {
        const field = document.querySelector(selector);
        if (!(field instanceof HTMLInputElement)) {
          throw new Error(`missing ${selector}`);
        }
        const descriptor = Object.getOwnPropertyDescriptor(
          HTMLInputElement.prototype,
          "value",
        );
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
  // Sign-in lands on the Control Center; Devices is one nav step away.
  await page.waitForFunction(
    () => document.querySelector("h1")?.textContent?.trim() === "Control Center",
    undefined,
    { timeout: 20_000 },
  );
  console.log("ok signed in and landed on Control Center");
  await clickFirst(page, "[data-testid='nav-devices']", "Devices");
  await page.waitForFunction(
    () => document.querySelector("h1")?.textContent?.trim() === "Devices",
    undefined,
    { timeout: 20_000 },
  );
  const body = (await page.locator("body").innerText()) ?? "";
  assert(body.includes("No devices yet") || body.includes("Search devices"), body.slice(0, 400));
  assert(body.includes("Access"), "Devices page is missing the Access nav item");
  console.log("ok opened Devices");

  await clickFirst(
    page,
    "[data-testid='nav-acls'], nav[aria-label='Console'] a[href='/acls']",
    "Access",
  );
  await page.waitForFunction(
    () => document.querySelector("h1")?.textContent?.trim() === "Access",
    undefined,
    { timeout: 15_000 },
  );
  const access = (await page.locator("body").innerText()) ?? "";
  for (const needle of ["Groups", "Rules", "Save access policy"]) {
    assert(access.includes(needle), `Access page missing ${needle}`);
  }
  console.log("ok opened Access");

  const groupName = `ui${Date.now().toString(36).slice(-6)}`;
  await fillField(page, "input[placeholder='rangers']", groupName);
  await selectFirstPerson(page, "select[name='group-member'], .acl-add-group select");
  await clickButton(page, "Add group", "acl-add-group");
  const afterGroup = await page.evaluate(() => document.body.innerText);
  assert(
    afterGroup.includes(groupName),
    `Add group did not create ${groupName}: ${afterGroup.slice(0, 800)}`,
  );
  await clickButton(page, "Add rule", "acl-add-rule");
  await page.evaluate(
    ({ nextGroup, nextTag }) => {
      const rule = document.querySelector(".acl-rule:last-child") ?? document.body;
      const check = (legend, labelText) => {
        const fieldset = [...rule.querySelectorAll("fieldset")].find((node) =>
          node.querySelector("legend")?.textContent?.includes(legend),
        );
        const label = [...(fieldset?.querySelectorAll("label") ?? [])].find((node) =>
          node.textContent?.includes(labelText),
        );
        const box = label?.querySelector("input[type='checkbox']");
        if (!(box instanceof HTMLInputElement)) {
          throw new Error(`missing ${legend} / ${labelText}`);
        }
        if (!box.checked) box.click();
      };
      check("From groups", nextGroup);
      check("To tags", nextTag);
    },
    { nextGroup: groupName, nextTag: "store" },
  );
  await clickButton(page, "Save access policy", "acl-save");
  await page.waitForFunction(
    () => {
      const text = document.body.innerText;
      return (
        text.includes("Access policy saved on the coordinator.") ||
        Boolean(document.querySelector(".error")?.textContent)
      );
    },
    undefined,
    { timeout: 15_000 },
  );
  const afterSave = await page.evaluate(() => document.body.innerText);
  assert(
    afterSave.includes("Access policy saved on the coordinator."),
    `ACL save failed: ${afterSave.slice(-500)}`,
  );
  console.log(`ok saved access group ${groupName}`);

  await page.reload({ waitUntil: "load" });
  await page.waitForFunction(
    () => document.querySelector("h1")?.textContent?.trim() === "Access",
    undefined,
    { timeout: 15_000 },
  );
  const afterReload = (await page.locator("body").innerText()) ?? "";
  assert(afterReload.includes(groupName), `saved group ${groupName} did not persist`);
  console.log("ok Access reload kept the group");
}

async function main() {
  const baseUrl = requiredEnv("CONSOLE_URL");
  const email = requiredEnv("CONSOLE_EMAIL");
  const password = await readPassword();
  const tunnel = process.env.CONSOLE_SSH_TUNNEL?.trim()
    ? startSshTunnel(process.env.CONSOLE_SSH_TUNNEL.trim(), baseUrl)
    : null;
  const { url, child } = await startLightpanda();
  let browser;
  try {
    if (tunnel) await waitForLoopback(`${baseUrl.replace(/\/$/u, "")}/sign-in`);
    browser = await chromium.connectOverCDP({ endpointURL: url });
    const context = await browser.newContext({
      baseURL: baseUrl,
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();
    try {
      await runUi(page, baseUrl, email, password);
    } finally {
      await page.close();
      await context.close();
    }
    console.log("lightpanda_ui passed");
  } finally {
    await browser?.close().catch(() => undefined);
    child?.kill("SIGTERM");
    tunnel?.close();
  }
}

void main().catch((error) => {
  process.stderr.write(
    `lightpanda UI failed: ${error instanceof Error ? error.message : error}\n`,
  );
  process.exitCode = 1;
});
