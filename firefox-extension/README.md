# FidoParole for Firefox

Fills logins from the FidoParole vault into web pages. The extension never touches
the security key: it asks the FidoParole app, which must be running with a vault
unlocked and **Firefox autofill** turned on (gear icon → *Firefox autofill*). See
[Firefox autofill](../README.md#firefox-autofill) in the main README for setup, which
logins are offered, and the Linux snap / Flatpak notes.

## Using it

- Click the FidoParole button in the toolbar, or press **Alt+Shift+F**.
- The popup lists the logins whose website matches the page (title and username;
  never passwords). Click one to fill the username and password.
- With the shortcut and exactly one matching login, it is filled straight away.
- Nothing is submitted for you. On a username-only step (two-step sign-ins), only the
  username is filled.

To change the shortcut: `about:addons` → gear menu → *Manage Extension Shortcuts*.

## Permissions

| Permission | Used for |
|---|---|
| `nativeMessaging` | Talking to `fidoparole-bridge`, the relay that forwards requests to the app. |
| `activeTab` | Access to the current tab, and only after you click the button or press the shortcut. |
| `scripting` | Finding the login form in that tab and filling it. |

No host permissions (it can't read or change pages on its own), no storage, no
network access. The extension keeps nothing: each popup asks the app afresh.

## What happens on a fill

1. The page's origin is taken from the tab's address, never from the page itself.
2. Before asking for a password, the extension checks the tab is still on the same
   origin and that it has a login form, in the page or in a frame of the **same**
   origin.
3. The app checks again that the entry matches that origin, then returns the
   username and password.
4. They are filled only into frames of that origin, through the native value setter
   with `input` / `change` events, so script-driven forms (React and the like) see
   them.

## Loading it during development

`about:debugging` → *This Firefox* → *Load Temporary Add-on…* → pick
`firefox-extension/manifest.json`. It stays until Firefox restarts.

Then, in the app, press **Register with Firefox** once (it tells Firefox where the
relay is). The extension id `fidoparole@token2.com` is fixed in `manifest.json`;
the app's registration allows only this id, so keep it if you fork the extension.

Check the code with Mozilla's linter:

```sh
cd firefox-extension
npx web-ext lint
```

## Installing it permanently

Release and Beta Firefox install only add-ons signed by Mozilla. Sign it as an
**unlisted** (self-distributed) add-on: it is not published on addons.mozilla.org,
and you get a signed `.xpi` back.

1. Create API credentials at <https://addons.mozilla.org/developers/addon/api/key/>.
2. Raise `version` in `manifest.json` (each signed upload needs a new one).
3. Sign:

   ```sh
   cd firefox-extension
   npx web-ext sign --channel=unlisted --api-key=$AMO_JWT_ISSUER --api-secret=$AMO_JWT_SECRET
   ```

4. Install the `.xpi` from `web-ext-artifacts/`: drag it into Firefox, or
   `about:addons` → gear menu → *Install Add-on From File…*.

Firefox Developer Edition, Nightly and ESR can also run it unsigned: set
`xpinstall.signatures.required` to `false` in `about:config`, then install a zip of
this folder (`npx web-ext build`).

## Files

```
manifest.json      MV3; Firefox 128 or later (current ESR)
background.js      talks to the relay; finds and fills login forms
popup/             the toolbar popup (light and dark)
icons/mark.svg     copy of assets/logo/mark.svg
```
