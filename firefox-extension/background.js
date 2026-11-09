// FidoParole for Firefox — background.
//
// Talks to the FidoParole app through the native-messaging relay
// "com.token2.fidoparole". The app keeps the vault; this extension never
// stores anything. A password is fetched only when the user picks a login,
// right before it is put into the page, and only for the page's own origin.
"use strict";

const HOST = "com.token2.fidoparole";

/** One request to the app. Failures to reach the relay become { ok: false, error: "no_host" }. */
async function ask(op, args = {}) {
  try {
    const r = await browser.runtime.sendNativeMessage(HOST, { v: 1, op, ...args });
    return r && typeof r === "object" ? r : { ok: false, error: "bad_reply", message: "Unexpected answer from FidoParole." };
  } catch (e) {
    return { ok: false, error: "no_host", message: String((e && e.message) || e) };
  }
}

/** The tab's origin, for http(s) pages only. Always from the browser, never from page content. */
function originOf(tab) {
  try {
    const u = new URL(tab.url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : null;
  } catch {
    return null;
  }
}

async function activeTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

/** What the popup shows: the app's state and the logins for the active tab. */
async function overview() {
  const status = await ask("status");
  if (!status.ok || status.state !== "unlocked") return { status };
  const tab = await activeTab();
  const origin = tab && originOf(tab);
  if (!origin) return { status, noPage: true };
  const list = await ask("list", { origin });
  return { status, origin, tabId: tab.id, list };
}

// ------------------------------------------------- injected into the page --
// These run inside the page (scripting.executeScript) and must be
// self-contained.

/** Does this frame have login fields? Reports its own origin. */
function probeLoginForm() {
  const usable = (el) => {
    if (el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
  };
  const textual = (el) => ["text", "email", "tel", ""].includes((el.getAttribute("type") || "").toLowerCase());
  const userish = (el) => {
    const ac = (el.autocomplete || "").toLowerCase();
    if (ac.includes("username") || ac.includes("email") || el.type === "email") return true;
    return /user|login|e-?mail|account|ident/i.test(`${el.name} ${el.id} ${el.placeholder}`);
  };
  const passwords = [...document.querySelectorAll('input[type="password"]')].filter(usable).length;
  const users = [...document.querySelectorAll("input")].filter((e) => textual(e) && userish(e) && usable(e)).length;
  return { origin: location.origin, passwords, users };
}

/** Put the login into the form. Refuses if this frame is not `origin`. Never submits. */
function fillLoginForm(origin, username, password) {
  if (location.origin !== origin) return 0;
  const usable = (el) => {
    if (el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
  };
  const textual = (el) => ["text", "email", "tel", ""].includes((el.getAttribute("type") || "").toLowerCase());
  const userish = (el) => {
    const ac = (el.autocomplete || "").toLowerCase();
    if (ac.includes("username") || ac.includes("email") || el.type === "email") return true;
    return /user|login|e-?mail|account|ident/i.test(`${el.name} ${el.id} ${el.placeholder}`);
  };
  const skip = (el) => /search|query|captcha|otp|totp|code|token/i.test(`${el.name} ${el.id} ${el.autocomplete}`);
  // The native setter, so pages built on React & co. notice the new value.
  const setValue = (el, v) => {
    el.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const pws = [...document.querySelectorAll('input[type="password"]')].filter(usable);
  // Change-password and sign-up forms have several: fill the current one only.
  const pw = pws.find((e) => e.autocomplete === "current-password") || pws[0] || null;
  let user = null;
  if (pw) {
    // The nearest text-like field before the password field, in its form.
    const scope = pw.form || document;
    user = [...scope.querySelectorAll("input")]
      .filter((e) => textual(e) && usable(e) && !skip(e) && e.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING)
      .pop() || null;
  } else {
    // Username-only step of a two-step login.
    const cands = [...document.querySelectorAll("input")].filter((e) => textual(e) && usable(e) && !skip(e) && userish(e));
    user = cands.find((e) => (e.autocomplete || "").includes("username")) || cands[0] || null;
  }
  let n = 0;
  if (user && username) { setValue(user, username); n++; }
  if (pw && password) { setValue(pw, password); n++; }
  if (pw && n) pw.focus();
  return n;
}

// -------------------------------------------------------------------- fill --

/** Frames of `tabId` with login fields on `origin`. */
async function loginFrames(tabId, origin) {
  let results;
  try {
    results = await browser.scripting.executeScript({ target: { tabId, allFrames: true }, func: probeLoginForm });
  } catch {
    // Frames we may not touch: try the top frame alone.
    results = await browser.scripting.executeScript({ target: { tabId }, func: probeLoginForm });
  }
  return results
    .filter((r) => r.result && r.result.origin === origin && (r.result.passwords || r.result.users))
    .map((r) => r.frameId);
}

/** Fill login `id` into tab `tabId`, listed for `origin`. */
async function fill(tabId, id, origin) {
  const tab = await browser.tabs.get(tabId);
  // The page may have navigated since the list was shown.
  if (originOf(tab) !== origin) return { ok: false, message: "The page changed. Open FidoParole again." };
  let frameIds;
  try {
    frameIds = await loginFrames(tabId, origin);
  } catch {
    return { ok: false, message: "Firefox doesn't let extensions fill this page." };
  }
  // Ask for the password only when there is somewhere to put it.
  if (!frameIds.length) return { ok: false, message: "No login form found on this page." };
  const cred = await ask("fill", { origin, id });
  if (!cred.ok) return cred;
  let results;
  try {
    results = await browser.scripting.executeScript({
      target: { tabId, frameIds },
      func: fillLoginForm,
      args: [origin, cred.username || "", cred.password || ""],
    });
  } catch {
    return { ok: false, message: "Firefox doesn't let extensions fill this page." };
  } finally {
    cred.username = cred.password = null;
  }
  return results.some((r) => r.result > 0) ? { ok: true } : { ok: false, message: "No login fields to fill on this page." };
}

// --------------------------------------------------------------- messaging --

// Set by the keyboard shortcut; the popup it opens fills a single match at once.
let shortcutAt = 0;

browser.commands.onCommand.addListener((command) => {
  if (command !== "fill-login") return;
  shortcutAt = Date.now();
  // Must be called right away: Firefox only allows it while handling the key press.
  browser.action.openPopup().catch(() => {});
});

browser.runtime.onMessage.addListener((msg, sender) => {
  // Only this extension's own pages (the popup), never a page script.
  if (sender.id !== browser.runtime.id || sender.tab) return undefined;
  switch (msg && msg.cmd) {
    case "overview":
      return overview();
    case "fill":
      return fill(msg.tabId, String(msg.id), String(msg.origin));
    case "takeShortcut": {
      const recent = Date.now() - shortcutAt < 5000;
      shortcutAt = 0;
      return Promise.resolve(recent);
    }
    default:
      return undefined;
  }
});
