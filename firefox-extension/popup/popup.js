// FidoParole popup: the app's state and the logins for this page.
// Passwords never come here — filling happens in the background script.
"use strict";

const $ = (s) => document.querySelector(s);

function show(state, detail = "") {
  $("#state").textContent = state;
  $("#detail").textContent = detail;
  $("#detail").hidden = !detail;
}

function showError(msg) {
  $("#error").textContent = msg || "";
  $("#error").hidden = !msg;
}

/** Text for an app state or error code. */
function explain(r) {
  switch (r.error || r.state) {
    case "no_host":
      return ["FidoParole isn't set up for Firefox yet.",
        "In the FidoParole app: Settings → Firefox autofill → Register with Firefox. Then try again."];
    case "not_running":
      return ["FidoParole is not running.", "Start the app and unlock your vault."];
    case "disabled":
      return ["Firefox autofill is off.", "Turn it on in the FidoParole app: Settings → Firefox autofill."];
    case "locked":
      return ["Your vault is locked.", "Unlock it in the FidoParole app (PIN or fingerprint, then touch the key)."];
    default:
      return [r.message || "FidoParole couldn't answer.", ""];
  }
}

function initial(title) {
  const m = (title || "").match(/[A-Za-z0-9]/);
  return m ? m[0].toUpperCase() : "?";
}

async function fillEntry(o, e, buttons) {
  buttons.forEach((b) => (b.disabled = true));
  showError("");
  const r = await browser.runtime.sendMessage({ cmd: "fill", tabId: o.tabId, id: e.id, origin: o.origin });
  if (r && r.ok) {
    window.close();
    return;
  }
  showError((r && r.message) || "Couldn't fill this page.");
  buttons.forEach((b) => (b.disabled = false));
}

function renderList(o) {
  const entries = o.list.entries || [];
  const host = o.list.host || new URL(o.origin).host;
  if (!entries.length) {
    show(`No login for ${host}.`, `Add the site's address to an entry's Website field in FidoParole${o.status.vault ? ` (vault “${o.status.vault}”)` : ""}.`);
    return [];
  }
  show(entries.length === 1 ? `1 login for ${host}` : `${entries.length} logins for ${host}`);
  const list = $("#list");
  list.replaceChildren();
  const buttons = entries.map((e) => {
    const b = document.createElement("button");
    b.className = "ent";
    b.title = `Fill ${e.title || "this login"}`;
    const av = document.createElement("span");
    av.className = "av";
    av.textContent = initial(e.title);
    const t = document.createElement("span");
    t.className = "t";
    const name = document.createElement("b");
    name.textContent = e.title || "(untitled)";
    const user = document.createElement("small");
    user.textContent = e.username || "no username";
    t.append(name, user);
    b.append(av, t);
    list.append(b);
    return b;
  });
  buttons.forEach((b, i) => (b.onclick = () => fillEntry(o, entries[i], buttons)));
  list.hidden = false;
  buttons[0].focus();
  return buttons;
}

async function main() {
  let o;
  try {
    o = await browser.runtime.sendMessage({ cmd: "overview" });
  } catch (e) {
    show("Something went wrong.", String((e && e.message) || e));
    return;
  }
  const st = o.status;
  if (!st.ok || st.state !== "unlocked") {
    show(...explain(st));
    return;
  }
  if (st.vault) {
    $("#vault").textContent = st.vault;
    $("#vault").hidden = false;
  }
  if (o.noPage) {
    show("Nothing to fill here.", "FidoParole fills logins on web pages (http and https) only.");
    return;
  }
  if (!o.list.ok) {
    show(...explain(o.list));
    return;
  }
  const buttons = renderList(o);
  // Opened with the keyboard shortcut and only one match: fill it right away.
  const viaShortcut = await browser.runtime.sendMessage({ cmd: "takeShortcut" });
  if (viaShortcut && buttons.length === 1) buttons[0].click();
}

main();
