// Keymaster SSH Agent - Background Service Worker

// --- SSH Agent Wire Protocol Helper Classes & Functions ---

class SSHBuffer {
  constructor(uint8array) {
    this.array = uint8array;
    this.buffer = new DataView(uint8array.buffer, uint8array.byteOffset, uint8array.byteLength);
    this.offset = 0;
  }
  
  readUint8() {
    const val = this.buffer.getUint8(this.offset);
    this.offset += 1;
    return val;
  }
  
  readUint32() {
    const val = this.buffer.getUint32(this.offset, false);
    this.offset += 4;
    return val;
  }
  
  readUint64() {
    const high = this.buffer.getUint32(this.offset, false);
    const low = this.buffer.getUint32(this.offset + 4, false);
    this.offset += 8;
    return high * 0x100000000 + low;
  }
  
  readString() {
    const len = this.readUint32();
    if (this.offset + len > this.array.byteLength) {
      throw new Error("SSHBuffer: String length out of bounds: " + len);
    }
    const val = new Uint8Array(this.array.buffer, this.array.byteOffset + this.offset, len);
    this.offset += len;
    return val;
  }
  
  hasMore() {
    return this.offset < this.array.byteLength;
  }
}

class SSHWriter {
  constructor() {
    this.chunks = [];
    this.size = 0;
  }
  
  writeUint8(val) {
    const buf = new Uint8Array(1);
    buf[0] = val;
    this.chunks.push(buf);
    this.size += 1;
  }
  
  writeUint32(val) {
    const buf = new Uint8Array(4);
    const view = new DataView(buf.buffer);
    view.setUint32(0, val, false);
    this.chunks.push(buf);
    this.size += 4;
  }
  
  writeString(bytes) {
    this.writeUint32(bytes.length);
    this.chunks.push(bytes);
    this.size += bytes.length;
  }
  
  toUint8Array() {
    const res = new Uint8Array(this.size);
    let offset = 0;
    for (const chunk of this.chunks) {
      res.set(chunk, offset);
      offset += chunk.length;
    }
    return res;
  }
}



function base64ToBytes(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function base64UrlToBytes(base64url) {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return base64ToBytes(base64);
}

// --- Key Management and OpenSSH formatting ---

async function getStoredPrivateKey() {
  try {
    const data = await chrome.storage.local.get(['privateKeyJwk']);
    if (!data.privateKeyJwk) return null;
    if (data.privateKeyJwk.kty !== "OKP") {
      console.warn("Stored key is not Ed25519, discarding");
      return null;
    }
    return await crypto.subtle.importKey(
      "jwk",
      data.privateKeyJwk,
      { name: "Ed25519" },
      true,
      ["sign"]
    );
  } catch (err) {
    console.warn("Failed to import stored private key:", err);
    return null;
  }
}

async function getOrCreateKeyPair() {
  const stored = await getStoredPrivateKey();
  if (stored) {
    try {
      const data = await chrome.storage.local.get(['publicKeyJwk']);
      if (data.publicKeyJwk && data.publicKeyJwk.kty === "OKP") {
        const publicKey = await crypto.subtle.importKey(
          "jwk",
          data.publicKeyJwk,
          { name: "Ed25519" },
          true,
          ["verify"]
        );
        return { privateKey: stored, publicKey };
      }
    } catch (err) {
      console.warn("Failed to import stored public key:", err);
    }
  }
  
  console.log("Generating new Ed25519 key pair...");
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  );
  
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  
  // Clear any old certificate matching the old/non-existent keys
  await chrome.storage.local.remove(['certText', 'validBefore', 'authenticated', 'lastUpdated']);
  await updateBadge();
  
  await chrome.storage.local.set({ privateKeyJwk, publicKeyJwk });
  
  return keyPair;
}

async function getSshPublicKeyString(publicKey, comment = "keymaster-agent") {
  const rawKey = await crypto.subtle.exportKey("raw", publicKey);
  const keyBytes = new Uint8Array(rawKey);
  
  const typeBytes = new TextEncoder().encode("ssh-ed25519");
  
  const writer = new SSHWriter();
  writer.writeString(typeBytes);
  writer.writeString(keyBytes);
  
  const blob = writer.toUint8Array();
  const base64Blob = btoa(String.fromCharCode(...blob));
  return `ssh-ed25519 ${base64Blob} ${comment}`;
}

function getCertValidBefore(certBytes) {
  try {
    const buf = new SSHBuffer(certBytes);
    const type = new TextDecoder().decode(buf.readString());
    
    buf.readString(); // nonce
    
    if (type.startsWith("ecdsa-sha2-")) {
      buf.readString(); // curve name
      buf.readString(); // public key point Q
    } else if (type.startsWith("ssh-rsa")) {
      buf.readString(); // e
      buf.readString(); // n
    } else if (type.startsWith("ssh-ed25519")) {
      buf.readString(); // public key
    } else {
      throw new Error("Unsupported certificate type: " + type);
    }
    
    buf.readUint64(); // serial number
    buf.readUint32(); // certificate type
    buf.readString(); // key ID
    buf.readString(); // valid principals
    buf.readUint64(); // valid after
    const validBefore = buf.readUint64();
    return validBefore;
  } catch (e) {
    console.error("Error parsing certificate expiration:", e);
    return null;
  }
}

// --- SSH Agent Response Builders ---

function buildIdentitiesAnswer(certBytes, commentStr) {
  const writer = new SSHWriter();
  writer.writeUint8(12); // SSH_AGENTS_IDENTITIES_ANSWER
  writer.writeUint32(1); // 1 key
  writer.writeString(certBytes);
  writer.writeString(new TextEncoder().encode(commentStr));
  return writer.toUint8Array();
}

function buildEmptyIdentitiesAnswer() {
  const writer = new SSHWriter();
  writer.writeUint8(12); // SSH_AGENTS_IDENTITIES_ANSWER
  writer.writeUint32(0); // 0 keys
  return writer.toUint8Array();
}

function buildFailureAnswer() {
  const writer = new SSHWriter();
  writer.writeUint8(5); // SSH_AGENT_FAILURE
  return writer.toUint8Array();
}

function buildSignatureAnswer(signatureBytes) {
  const writer = new SSHWriter();
  writer.writeUint8(14); // SSH_AGENTS_SIGN_RESPONSE
  writer.writeString(signatureBytes);
  return writer.toUint8Array();
}



// --- Badge Countdown Updating ---

async function updateBadge() {
  const data = await chrome.storage.local.get(['certText', 'validBefore']);
  if (!data.certText || !data.validBefore) {
    chrome.action.setBadgeText({ text: "x" });
    chrome.action.setBadgeBackgroundColor({ color: "#D32F2F" }); // Red
    return;
  }
  
  const now = Date.now();
  const timeLeftMs = (data.validBefore * 1000) - now; // validBefore is in seconds
  if (timeLeftMs <= 0) {
    chrome.action.setBadgeText({ text: "x" });
    chrome.action.setBadgeBackgroundColor({ color: "#D32F2F" }); // Red
  } else {
    const hours = Math.floor(timeLeftMs / (3600 * 1000));
    chrome.action.setBadgeText({ text: hours + "h" });
    if (hours >= 8) {
      chrome.action.setBadgeBackgroundColor({ color: "#10B981" }); // Emerald Green
    } else if (hours >= 2) {
      chrome.action.setBadgeBackgroundColor({ color: "#F59E0B" }); // Amber Orange
    } else {
      chrome.action.setBadgeBackgroundColor({ color: "#EF4444" }); // Crimson Red
    }
  }
}

// --- SSH Agent External Connection Handler ---

async function handleAgentRequest(data) {
  const reader = new SSHBuffer(data);
  const type = reader.readUint8();
  
  if (type === 11) { // SSH_AGENTC_REQUEST_IDENTITIES
    console.log("SSH Agent: Received identities request");
    const certData = await chrome.storage.local.get(['certText', 'validBefore']);
    
    if (!certData.certText) {
      return buildEmptyIdentitiesAnswer();
    }
    
    // Check if certificate is expired
    const now = Date.now();
    if (certData.validBefore && (certData.validBefore * 1000) <= now) {
      console.warn("Loaded certificate is expired, returning empty identities");
      return buildEmptyIdentitiesAnswer();
    }
    
    const parts = certData.certText.trim().split(/\s+/);
    if (parts.length < 2) {
      return buildEmptyIdentitiesAnswer();
    }
    
    try {
      const certBytes = base64ToBytes(parts[1]);
      const comment = parts[2] || "keymaster-agent";
      return buildIdentitiesAnswer(certBytes, comment);
    } catch (err) {
      console.error("Failed to parse certificate for identities:", err);
      return buildEmptyIdentitiesAnswer();
    }
  }
  
  if (type === 13) { // SSH_AGENTC_SIGN_REQUEST
    console.log("SSH Agent: Received sign request");
    const keyBlob = reader.readString();
    const dataToSign = reader.readString();
    const flags = reader.readUint32();
    
    const certData = await chrome.storage.local.get(['certText', 'validBefore']);
    if (!certData.certText) {
      console.warn("No certificate loaded, failing sign request");
      return buildFailureAnswer();
    }
    
    const now = Date.now();
    if (certData.validBefore && (certData.validBefore * 1000) <= now) {
      console.warn("Certificate is expired, failing sign request");
      return buildFailureAnswer();
    }
    
    const parts = certData.certText.trim().split(/\s+/);
    if (parts.length < 2) {
      console.warn("Invalid certificate format, failing sign request");
      return buildFailureAnswer();
    }
    
    const storedCertBytes = base64ToBytes(parts[1]);
    
    // Verify key blobs match
    let matches = true;
    if (keyBlob.length !== storedCertBytes.length) {
      matches = false;
    } else {
      for (let i = 0; i < keyBlob.length; i++) {
        if (keyBlob[i] !== storedCertBytes[i]) {
          matches = false;
          break;
        }
      }
    }
    
    if (!matches) {
      console.warn("Signature request key blob does not match loaded certificate");
      return buildFailureAnswer();
    }
    
    const keyPair = await getOrCreateKeyPair();
    if (!keyPair || !keyPair.privateKey) {
      console.error("Private key not found, failing sign request");
      return buildFailureAnswer();
    }
    
    const signatureBuffer = await crypto.subtle.sign(
      { name: "Ed25519" },
      keyPair.privateKey,
      dataToSign
    );
    
    const signatureBytes = new Uint8Array(signatureBuffer);
    const formatBytes = new TextEncoder().encode("ssh-ed25519");
    const writer = new SSHWriter();
    writer.writeString(formatBytes);
    writer.writeString(signatureBytes);
    const outerSigBlob = writer.toUint8Array();
    return buildSignatureAnswer(outerSigBlob);
  }
  
  console.warn("Unsupported SSH agent command:", type);
  return buildFailureAnswer();
}

chrome.runtime.onConnectExternal.addListener((port) => {
  console.log("External Secure Shell client connected:", port.sender?.id);
  
  port.onMessage.addListener(async (msg) => {
    try {
      if (!msg.data || msg.type !== "auth-agent@openssh.com") {
        console.warn("Received invalid message structure:", msg);
        return;
      }
      
      const responseBytes = await handleAgentRequest(new Uint8Array(msg.data));
      if (responseBytes) {
        port.postMessage({
          type: "auth-agent@openssh.com",
          data: Array.from(responseBytes)
        });
      }
    } catch (err) {
      console.error("Error processing agent request:", err);
      port.postMessage({
        type: "auth-agent@openssh.com",
        data: Array.from(buildFailureAnswer())
      });
    }
  });
});

// --- Keymaster Client Operations ---

async function fetchWithTimeout(resource, options = {}) {
  const { timeout = 10000 } = options;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

async function requestCertificate(server, username) {
  try {
    const keyPair = await getOrCreateKeyPair();
    const sshPubKeyString = await getSshPublicKeyString(keyPair.publicKey, `keymaster-${username}`);
    
    // Keymaster URL: POST /certgen/<username>?type=ssh
    const requestURL = `${server}/certgen/${username}?type=ssh`;
    
    const formData = new FormData();
    const pubkeyFile = new Blob([sshPubKeyString], { type: 'text/plain' });
    formData.append('pubkeyfile', pubkeyFile, 'somefilename.pub');
    formData.append('duration', '16h0m0s'); // 16 hours default
    
    console.log("Requesting certificate from keymaster at:", requestURL);
    const response = await fetchWithTimeout(requestURL, {
      method: 'POST',
      body: formData,
      credentials: 'include'
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Certificate request failed: ${response.status} ${response.statusText}. ${errorText}`);
    }
    
    const certText = await response.text();
    const parts = certText.trim().split(/\s+/);
    if (parts.length < 2) {
      throw new Error("Invalid certificate format returned by server");
    }
    
    const certBytes = base64ToBytes(parts[1]);
    const validBefore = getCertValidBefore(certBytes);
    
    if (!validBefore) {
      throw new Error("Could not parse validity period from the certificate");
    }
    
    await chrome.storage.local.set({
      certText,
      validBefore, // unix timestamp in seconds
      authenticated: true,
      lastUpdated: Date.now()
    });
    
    await updateBadge();
    return { success: true, validBefore };
  } catch (err) {
    console.error("Error in requestCertificate:", err);
    throw err;
  }
}

// --- Popup Message Listener ---

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_STATUS") {
    chrome.storage.local.get(['authenticated', 'username', 'server', 'validBefore', 'certText']).then((data) => {
      const now = Date.now();
      const timeLeftMs = data.validBefore ? (data.validBefore * 1000) - now : 0;
      
      sendResponse({
        authenticated: !!data.authenticated && timeLeftMs > 0,
        username: data.username || "",
        server: data.server || "",
        validBefore: data.validBefore || 0,
        timeLeftMs: timeLeftMs,
        certText: data.certText || ""
      });
    });
    return true; // Keep response channel open
  }
  
  if (request.type === "LOGIN") {
    const { server, username, password } = request;
    
    (async () => {
      try {
        await chrome.storage.local.set({ server, username });
        
        // POST to /api/v0/login
        const loginURL = `${server}/api/v0/login`;
        const form = new URLSearchParams();
        form.append("username", username);
        form.append("password", password);
        
        console.log("Logging in to keymaster at:", loginURL);
        const loginResp = await fetchWithTimeout(loginURL, {
          method: "POST",
          body: form,
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
          },
          credentials: 'include'
        });
        
        if (!loginResp.ok) {
          if (loginResp.status === 401) {
            throw new Error("Unauthorized. Please check your username and password.");
          }
          throw new Error(`Login failed with status: ${loginResp.status} ${loginResp.statusText}`);
        }
        
        const loginData = await loginResp.json();
        console.log("Login response:", loginData);
        
        // Check if 2FA is needed
        let mfaRequired = false;
        if (loginData.auth_backend && loginData.auth_backend.length > 0) {
          // If the list of backends contains anything other than "password", 2FA is required.
          const backends = loginData.auth_backend;
          if (backends.includes("TOTP") || backends.includes("SymantecVIP") || backends.includes("Okta2FA") || backends.includes("U2F") || backends.includes("webauthn")) {
            mfaRequired = true;
          }
        }
        
        if (mfaRequired) {
          sendResponse({ success: true, mfaRequired: true, backends: loginData.auth_backend });
        } else {
          // Password only, request cert directly
          const certResult = await requestCertificate(server, username);
          sendResponse({ success: true, mfaRequired: false, validBefore: certResult.validBefore });
        }
      } catch (err) {
        console.error("Login process error:", err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }
  
  if (request.type === "SUBMIT_MFA") {
    const { otpCode } = request;
    
    (async () => {
      try {
        const data = await chrome.storage.local.get(['server', 'username']);
        const server = data.server;
        const username = data.username;
        
        // POST to /api/v0/TOTPAuth
        const totpURL = `${server}/api/v0/TOTPAuth`;
        const form = new URLSearchParams();
        form.append("OTP", otpCode);
        
        console.log("Submitting TOTP code to:", totpURL);
        const totpResp = await fetchWithTimeout(totpURL, {
          method: "POST",
          body: form,
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
          },
          credentials: 'include'
        });
        
        if (!totpResp.ok) {
          throw new Error(`MFA authentication failed: ${totpResp.status} ${totpResp.statusText}`);
        }
        
        // Success! Request certificate
        const certResult = await requestCertificate(server, username);
        sendResponse({ success: true, validBefore: certResult.validBefore });
      } catch (err) {
        console.error("MFA process error:", err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }
  
  if (request.type === "LOGOUT") {
    chrome.storage.local.remove(['certText', 'validBefore', 'authenticated', 'lastUpdated']).then(() => {
      updateBadge();
      sendResponse({ success: true });
    });
    return true;
  }
  
  if (request.type === "RENEW") {
    (async () => {
      try {
        const data = await chrome.storage.local.get(['server', 'username']);
        if (!data.server || !data.username) {
          throw new Error("No existing configuration found. Please authenticate first.");
        }
        const certResult = await requestCertificate(data.server, data.username);
        sendResponse({ success: true, validBefore: certResult.validBefore });
      } catch (err) {
        console.error("Renewal failed:", err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }
  
  if (request.type === "FETCH_CERT") {
    const { server, username } = request;
    (async () => {
      try {
        const certResult = await requestCertificate(server, username);
        sendResponse({ success: true, validBefore: certResult.validBefore });
      } catch (err) {
        console.error("Certificate fetch failed:", err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }
});

// --- CSRF Bypass Rules (declarativeNetRequest) ---

async function registerNetRules() {
  const rules = [
    {
      id: 1,
      priority: 1,
      action: {
        type: "modifyHeaders",
        requestHeaders: [
          { header: "origin", operation: "remove" },
          { header: "referer", operation: "remove" }
        ]
      },
      condition: {
        initiatorDomains: [chrome.runtime.id],
        resourceTypes: ["xmlhttprequest"]
      }
    }
  ];
  
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [1],
      addRules: rules
    });
    console.log("Successfully registered declarativeNetRequest CSRF bypass rules");
  } catch (err) {
    console.error("Failed to register declarativeNetRequest rules:", err);
  }
}

// Run rules registration immediately on service worker startup
registerNetRules();

// --- Lifecycle Event Handlers ---

chrome.runtime.onInstalled.addListener(() => {
  console.log("Keymaster SSH Agent Extension Installed");
  chrome.alarms.create("update-badge", { periodInMinutes: 1 });
  updateBadge();
  getOrCreateKeyPair(); // Warm up the keypair
  registerNetRules();
});

chrome.runtime.onStartup.addListener(() => {
  console.log("Keymaster SSH Agent Extension Started");
  chrome.alarms.create("update-badge", { periodInMinutes: 1 });
  updateBadge();
  registerNetRules();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "update-badge") {
    updateBadge();
  }
});
