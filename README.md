# Keymaster SSH Agent — Google Chrome™ Extension

Do you use [Keymaster](https://github.com/Cloud-Foundations/keymaster) for short-lived ssh certificates?
Do you want to use [Chrome](https://www.google.com/chrome/) with [hterm](https://chromewebstore.google.com/detail/secure-shell/iodihamcpbpeioajjeobimgagajmlibd) and short-lived ssh certificates?

This is a Chrome extension that operates as a standalone **SSH Agent**. It integrates with a **Keymaster** server to fetch short-lived SSH user certificates, handles multi-factor authentication (TOTP & U2F / Security Keys), tracks certificate expiration, and serves the standard SSH Agent wire protocol to Chrome's official Secure Shell extension.

---

## ✨ Features

- **Expose Standalone SSH Agent**: Implements the SSH Agent protocol natively in Javascript and exposes it to Chrome Secure Shell via `externally_connectable` port connections.
- **Keymaster Integration**: Supports standard credentials login and conditionally prompts for TOTP (multi-factor authentication) code when requested by the server.
- **U2F & WebAuthn (Security Keys) Support**: Fully supports hardware keys (e.g. YubiKeys) by fetching the assertion challenge from `/webauthn/AuthBegin/`, invoking the browser's native security key prompt using `navigator.credentials.get()`, and submitting the signed assertion to `/webauthn/AuthFinish/`.
- **Hybrid MFA Switch**: If the server permits both security keys (U2F) and authenticator codes (TOTP), the popup provides buttons to toggle between the verification screens seamlessly.
- **Local Key Generation**: Uses the browser's native **Web Crypto API** to generate secure Ed25519 key pairs locally (private keys never leave the extension).
- **Expiration Countdown & Badge**:
  - Displays a color-coded indicator badge on the extension icon showing the hours left until expiration (e.g., `15h` (green), `4h` (orange), `0h` (red)), turning to `x` when expired.
  - A background `chrome.alarms` timer updates this countdown once per minute even when the popup is closed.
- **Premium Glassmorphism Dashboard**:
  - Features an obsidian dark mode UI with soft glows, pulsing security key prompt animations, and responsive input transitions.
  - Visual circular progress ring and ticking countdown timer indicating remaining certificate validity (based on a default 16-hour duration).
- **CSRF Bypass Rules**: Automatically bypasses Keymaster server-side CSRF validation by registering a `declarativeNetRequest` header rule that strips `Origin` and `Referer` headers from cross-origin fetch requests initiated by the extension.
- **Frictionless Renewal**: A **"Renew Certificate"** action that requests a new certificate in 1 second by reusing the active session cookies stored in the browser.

---

## 🚀 Getting Started

### 1. Load the Extension in Chrome
1.  Open Google Chrome and navigate to `chrome://extensions/`.
2.  Toggle **Developer mode** in the top-right corner.
3.  Click the **Load unpacked** button in the top-left corner.
4.  Select the extension directory:
    `chrome-keymaster-agent`
5.  Pin the **Keymaster SSH Agent** to your Chrome toolbar.

### 2. Authenticate
1.  Click the extension icon in your toolbar.
2.  Input your Keymaster **Server URL** (e.g., `https://keymaster.example.com`) and **Username**.
3.  Input your **Password** and click **Connect & Authenticate**.
4.  If prompted, tap your hardware **Security Key** or click the option to use your **MFA Security Code (TOTP)** from your authenticator app.
5.  Upon successful login, the popup will transition to the dashboard showing a countdown timer, and your extension icon will display the remaining hours (e.g., `15h`).

### 3. Configure Secure Shell (hterm)
To route authentication requests from the **Secure Shell** extension to this agent:
1.  Open the connection profile settings in **Secure Shell**.
2.  Copy your Keymaster SSH Agent's extension **ID** from `chrome://extensions/` (a 32-character string like `oalgkcnfjnajfhgimadimbjhmpaeohhln`).
3.  Add the following argument to the **SSH Arguments** (or **SSH Relay Server Options**) field:
    ```bash
    --ssh-agent=<EXTENSION_ID>
    ```
4.  Establish your SSH connection. Secure Shell will automatically request identities and sign authentication challenges using this extension.

---

## 🔒 Security Considerations

- **Private Key Isolation**: Private keys are generated on-device, stored in Chrome's sandboxed local storage, and never transmitted over the network or exposed via the agent protocol.
- **Agent Signing Only**: The extension strictly processes signatures using the private key and refuses any key exports or modifications from external ports.
- **Short-Lived Certs**: Keymaster certificates expire automatically (typically in 16 hours), after which the agent will deny sign requests and the extension icon will display an `x` until renewed.
