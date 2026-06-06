// Keymaster SSH Agent - Popup Logic

// Screen elements
const loadingScreen = document.getElementById("loading-screen");
const loginScreen = document.getElementById("login-screen");
const dashboardScreen = document.getElementById("dashboard-screen");

// Form elements
const loginForm = document.getElementById("login-form");
const serverInput = document.getElementById("server-input");
const usernameInput = document.getElementById("username-input");
const credentialsContainer = document.getElementById("credentials-container");
const passwordInput = document.getElementById("password-input");
const togglePasswordBtn = document.getElementById("toggle-password-btn");
const eyeIcon = document.getElementById("eye-icon");

// MFA (TOTP) elements
const mfaContainer = document.getElementById("mfa-container");
const otpInput = document.getElementById("otp-input");
const switchToU2fBtn = document.getElementById("switch-to-u2f-btn");

// U2F elements
const u2fContainer = document.getElementById("u2f-container");
const switchToTotpBtn = document.getElementById("switch-to-totp-btn");
const u2fToggle = document.getElementById("u2f-toggle");

// Webauth elements
const webauthContainer = document.getElementById("webauth-container");
const webauthLaunchBtn = document.getElementById("webauth-launch-btn");
const webauthWaiting = document.getElementById("webauth-waiting");

// General login controls
const loginBtn = document.getElementById("login-btn");
const loginBtnText = loginBtn.querySelector("span");
const statusMsg = document.getElementById("status-msg");
const statusText = document.getElementById("status-text");

// Dashboard elements
const progressRing = document.getElementById("countdown-progress-ring");
const timeDisplay = document.getElementById("time-display");
const timeLabel = document.getElementById("time-label");
const expiredIcon = document.getElementById("expired-icon");
const metaServer = document.getElementById("meta-server");
const metaUsername = document.getElementById("meta-username");
const renewBtn = document.getElementById("renew-btn");
const logoutBtn = document.getElementById("logout-btn");

let countdownInterval = null;
let currentValidBefore = 0; // Unix timestamp in seconds
let isMfaState = false;
let u2fAborted = false;
let availableBackends = [];

// Ring configuration
const RING_CIRCUMFERENCE = 477.5; // 2 * PI * r (76)
progressRing.style.strokeDasharray = `${RING_CIRCUMFERENCE} ${RING_CIRCUMFERENCE}`;

// --- Base64URL and Buffer Converters ---

function base64UrlToBuffer(base64url) {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// --- Screen Transitions ---

function showScreen(screen) {
  [loadingScreen, loginScreen, dashboardScreen].forEach(s => {
    s.classList.remove("active");
  });
  screen.classList.add("active");
}

// --- Status/Error Message Helper ---

function showError(msg) {
  if (msg) {
    statusText.textContent = msg;
    statusMsg.style.display = "flex";
  } else {
    statusMsg.style.display = "none";
  }
}

// --- Password Visibility Toggle ---

togglePasswordBtn.addEventListener("click", () => {
  const isPassword = passwordInput.getAttribute("type") === "password";
  passwordInput.setAttribute("type", isPassword ? "text" : "password");
  
  if (isPassword) {
    eyeIcon.innerHTML = `
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
      <line x1="1" y1="1" x2="23" y2="23"/>
    `;
  } else {
    eyeIcon.innerHTML = `
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
      <circle cx="12" cy="12" r="3"/>
    `;
  }
});

// --- Real-time Countdown Timer ---

function startCountdown(validBeforeSec) {
  if (countdownInterval) clearInterval(countdownInterval);
  currentValidBefore = validBeforeSec;
  
  const updateTimer = () => {
    const now = Date.now();
    const targetTime = currentValidBefore * 1000;
    const timeLeftMs = targetTime - now;
    
    if (timeLeftMs <= 0) {
      clearInterval(countdownInterval);
      progressRing.style.strokeDashoffset = RING_CIRCUMFERENCE;
      expiredIcon.classList.add("active");
      timeLabel.textContent = "Expired";
      chrome.runtime.sendMessage({ type: "GET_STATUS" });
      return;
    }
    
    expiredIcon.classList.remove("active");
    timeLabel.textContent = "Time Remaining";
    
    const totalSeconds = Math.floor(timeLeftMs / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    
    if (hours > 0) {
      timeDisplay.textContent = `${hours}h ${minutes}m`;
    } else {
      timeDisplay.textContent = `${minutes}m ${seconds}s`;
    }
    
    const MAX_DURATION_MS = 16 * 3600 * 1000;
    const fraction = timeLeftMs / MAX_DURATION_MS;
    const clampedFraction = Math.max(0, Math.min(1, fraction));
    const offset = RING_CIRCUMFERENCE * (1 - clampedFraction);
    progressRing.style.strokeDashoffset = offset;
  };
  
  updateTimer();
  countdownInterval = setInterval(updateTimer, 1000);
}

// --- Initialize / Get Status ---

let isWebauthSupported = false;
let probeTimeout = null;

function probeWebauthSupport(server) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "PROBE_WEBAUTH", server }, (response) => {
      resolve(!!response && response.supported);
    });
  });
}

async function checkServerCapabilities() {
  const server = serverInput.value.trim().replace(/\/$/, "");
  if (!server) {
    webauthContainer.style.display = "none";
    credentialsContainer.style.display = "block";
    loginBtn.style.display = "inline-flex";
    return;
  }
  
  isWebauthSupported = await probeWebauthSupport(server);
  
  if (isWebauthSupported) {
    webauthContainer.style.display = "block";
    credentialsContainer.style.display = "none";
    loginBtn.style.display = "none";
  } else {
    webauthContainer.style.display = "none";
    credentialsContainer.style.display = "block";
    loginBtn.style.display = "inline-flex";
  }
}

function init() {
  showScreen(loadingScreen);
  
  // Load U2F toggle state and setup change listener
  chrome.storage.local.get(['u2fEnabled']).then((data) => {
    u2fToggle.checked = data.u2fEnabled !== false;
  });
  
  u2fToggle.addEventListener("change", () => {
    chrome.storage.local.set({ u2fEnabled: u2fToggle.checked });
  });

  serverInput.addEventListener("blur", checkServerCapabilities);
  serverInput.addEventListener("input", () => {
    if (probeTimeout) clearTimeout(probeTimeout);
    probeTimeout = setTimeout(checkServerCapabilities, 500);
  });

  chrome.runtime.sendMessage({ type: "GET_STATUS" }, (response) => {
    if (response && response.authenticated) {
      metaServer.textContent = response.server;
      metaUsername.textContent = response.username;
      startCountdown(response.validBefore);
      showScreen(dashboardScreen);
    } else {
      if (response && (response.server || response.username)) {
        serverInput.value = response.server || "";
        usernameInput.value = response.username || "";
        checkServerCapabilities();
      } else {
        chrome.storage.local.get(['server', 'username']).then((data) => {
          serverInput.value = data.server || "";
          usernameInput.value = data.username || "";
          checkServerCapabilities();
        });
      }
      resetFormToLoginState();
      showScreen(loginScreen);
    }
  });
}

function resetFormToLoginState() {
  isMfaState = false;
  credentialsContainer.style.display = "block";
  passwordInput.required = true;
  mfaContainer.style.display = "none";
  otpInput.required = false;
  otpInput.value = "";
  u2fContainer.style.display = "none";
  loginBtn.style.display = "inline-flex";
  loginBtnText.textContent = "Connect & Authenticate";
  loginBtn.disabled = false;
  showError(null);
  u2fAborted = false;
  
  webauthWaiting.style.display = "none";
  webauthLaunchBtn.disabled = false;
  checkServerCapabilities();
}

function setToMfaState() {
  isMfaState = true;
  u2fAborted = true; // Stop any pending WebAuthn calls
  credentialsContainer.style.display = "none";
  passwordInput.required = false;
  passwordInput.value = "";
  
  // Show TOTP container
  mfaContainer.style.display = "block";
  otpInput.required = true;
  otpInput.value = "";
  
  // Hide U2F container
  u2fContainer.style.display = "none";
  
  // Update login button
  loginBtn.style.display = "inline-flex";
  loginBtnText.textContent = "Verify Security Code";
  loginBtn.disabled = false;
  
  // Configure switch buttons
  const u2fEnabled = u2fToggle.checked;
  const hasU2f = availableBackends.includes("U2F") || availableBackends.includes("webauthn");
  if (u2fEnabled && hasU2f) {
    switchToU2fBtn.style.display = "block";
  } else {
    switchToU2fBtn.style.display = "none";
  }
  
  otpInput.focus();
}

function setToU2fState() {
  isMfaState = true;
  u2fAborted = false;
  credentialsContainer.style.display = "none";
  passwordInput.required = false;
  passwordInput.value = "";
  
  // Hide TOTP container
  mfaContainer.style.display = "none";
  otpInput.required = false;
  
  // Show U2F container
  u2fContainer.style.display = "block";
  
  // Hide standard login button since WebAuthn prompts automatically
  loginBtn.style.display = "none";
  
  // Configure switch buttons
  const hasOtp = availableBackends.includes("TOTP") || availableBackends.includes("SymantecVIP") || availableBackends.includes("Okta2FA");
  if (hasOtp) {
    switchToTotpBtn.style.display = "block";
  } else {
    switchToTotpBtn.style.display = "none";
  }
}

// --- WebAuthn Flow Implementation ---

async function doWebAuthn(server) {
  try {
    // 1. Fetch challenge options from /webauthn/AuthBegin/
    const beginURL = `${server}/webauthn/AuthBegin/`;
    console.log("Fetching WebAuthn challenge from:", beginURL);
    const beginResp = await fetch(beginURL, {
      method: "GET",
      credentials: "include"
    });
    if (!beginResp.ok) {
      throw new Error(`Failed to get WebAuthn challenge: ${beginResp.status} ${beginResp.statusText}`);
    }
    const assertionData = await beginResp.json();
    console.log("Received WebAuthn challenge:", assertionData);
    
    if (u2fAborted) return; // Exit if user switched away
    
    // 2. Parse base64url parameters into ArrayBuffers for WebAuthn API
    const originalOptions = assertionData.publicKey;
    const parsedOptions = {
      challenge: base64UrlToBuffer(originalOptions.challenge),
      rpId: originalOptions.rpId,
      allowCredentials: originalOptions.allowCredentials.map(cred => ({
        type: cred.type,
        id: base64UrlToBuffer(cred.id)
      })),
      userVerification: originalOptions.userVerification || "preferred",
      timeout: originalOptions.timeout || 60000
    };
    
    // 3. Prompt WebAuthn Hardware Key
    console.log("Requesting security key assertion via WebAuthn API...");
    const assertion = await navigator.credentials.get({ publicKey: parsedOptions });
    if (!assertion) {
      throw new Error("No hardware credentials assertion returned by browser");
    }
    
    if (u2fAborted) return;
    
    // 4. Format signature response back to base64url
    const finishPayload = {
      id: assertion.id,
      rawId: bufferToBase64Url(assertion.rawId),
      type: "public-key",
      response: {
        authenticatorData: bufferToBase64Url(assertion.response.authenticatorData),
        clientDataJSON: bufferToBase64Url(assertion.response.clientDataJSON),
        signature: bufferToBase64Url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufferToBase64Url(assertion.response.userHandle) : ""
      }
    };
    
    // 5. POST back assertion response to /webauthn/AuthFinish/
    const finishURL = `${server}/webauthn/AuthFinish/`;
    console.log("Submitting assertion to:", finishURL);
    const finishResp = await fetch(finishURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(finishPayload),
      credentials: "include"
    });
    
    if (!finishResp.ok) {
      throw new Error(`WebAuthn authentication failed: ${finishResp.status} ${finishResp.statusText}`);
    }
    
    console.log("WebAuthn verification complete.");
    return true;
  } catch (err) {
    console.error("WebAuthn execution error:", err);
    throw err;
  }
}

async function runWebAuthnFlow() {
  const server = serverInput.value.trim().replace(/\/$/, "");
  const username = usernameInput.value.trim();
  
  setToU2fState();
  
  try {
    const success = await doWebAuthn(server);
    if (success && !u2fAborted) {
      // Authenticated successfully! Fetch the signed certificate via background.
      chrome.runtime.sendMessage({
        type: "FETCH_CERT",
        server,
        username
      }, (response) => {
        if (response && response.success) {
          metaServer.textContent = server;
          metaUsername.textContent = username;
          startCountdown(response.validBefore);
          showScreen(dashboardScreen);
        } else {
          showError(response ? response.error : "Failed to generate certificate after security key validation.");
          resetFormToLoginState();
        }
      });
    }
  } catch (err) {
    if (!u2fAborted) {
      showError(`Security key validation failed: ${err.message}`);
      // If OTP is an option, fall back to it, otherwise reset
      const hasOtp = availableBackends.includes("TOTP") || availableBackends.includes("SymantecVIP") || availableBackends.includes("Okta2FA");
      if (hasOtp) {
        setToMfaState();
      } else {
        resetFormToLoginState();
      }
    }
  }
}

// --- Form Submissions ---

loginForm.addEventListener("submit", (e) => {
  e.preventDefault();
  showError(null);
  
  const server = serverInput.value.trim().replace(/\/$/, "");
  const username = usernameInput.value.trim();
  
  if (!isMfaState) {
    const password = passwordInput.value;
    
    // Save server and username immediately on form submission
    chrome.storage.local.set({ server, username });
    
    loginBtn.disabled = true;
    loginBtnText.textContent = "Authenticating...";
    
    chrome.runtime.sendMessage({
      type: "LOGIN",
      server,
      username,
      password
    }, (response) => {
      if (response && response.success) {
        if (response.mfaRequired) {
          availableBackends = response.backends || [];
          const u2fEnabled = u2fToggle.checked;
          const hasU2f = availableBackends.includes("U2F") || availableBackends.includes("webauthn");
          const hasOtp = availableBackends.includes("TOTP") || availableBackends.includes("SymantecVIP") || availableBackends.includes("Okta2FA");
          
          if (u2fEnabled && hasU2f) {
            runWebAuthnFlow();
          } else if (hasOtp) {
            setToMfaState();
          } else {
            loginBtn.disabled = false;
            loginBtnText.textContent = "Connect & Authenticate";
            showError("Security Keys (U2F) is required by server, but disabled in settings.");
          }
        } else {
          metaServer.textContent = server;
          metaUsername.textContent = username;
          startCountdown(response.validBefore);
          showScreen(dashboardScreen);
        }
      } else {
        loginBtn.disabled = false;
        loginBtnText.textContent = "Connect & Authenticate";
        showError(response ? response.error : "Connection failed. Please check server URL and credentials.");
      }
    });
  } else {
    const otpCode = otpInput.value.trim();
    if (!otpCode) {
      showError("Please enter the MFA security code.");
      return;
    }
    
    loginBtn.disabled = true;
    loginBtnText.textContent = "Verifying...";
    
    chrome.runtime.sendMessage({
      type: "SUBMIT_MFA",
      otpCode
    }, (response) => {
      if (response && response.success) {
        metaServer.textContent = serverInput.value.trim();
        metaUsername.textContent = usernameInput.value.trim();
        startCountdown(response.validBefore);
        showScreen(dashboardScreen);
      } else {
        loginBtn.disabled = false;
        loginBtnText.textContent = "Verify Security Code";
        showError(response ? response.error : "Invalid MFA code. Please try again.");
      }
    });
  }
});

// --- MFA Switch Toggles ---

switchToU2fBtn.addEventListener("click", () => {
  showError(null);
  runWebAuthnFlow();
});

switchToTotpBtn.addEventListener("click", () => {
  showError(null);
  setToMfaState();
});

// --- Dashboard actions ---

renewBtn.addEventListener("click", () => {
  const originalText = renewBtn.querySelector("span").textContent;
  renewBtn.disabled = true;
  renewBtn.querySelector("span").textContent = "Renewing...";
  
  chrome.runtime.sendMessage({ type: "RENEW" }, (response) => {
    renewBtn.disabled = false;
    renewBtn.querySelector("span").textContent = originalText;
    
    if (response && response.success) {
      startCountdown(response.validBefore);
      const originalBg = renewBtn.style.background;
      renewBtn.style.background = "var(--success)";
      setTimeout(() => {
        renewBtn.style.background = originalBg;
      }, 1000);
    } else {
      showError(response ? response.error : "Session expired. Please log in again.");
      resetFormToLoginState();
      showScreen(loginScreen);
    }
  });
});

logoutBtn.addEventListener("click", () => {
  logoutBtn.disabled = true;
  chrome.runtime.sendMessage({ type: "LOGOUT" }, (response) => {
    logoutBtn.disabled = false;
    if (countdownInterval) clearInterval(countdownInterval);
    
    // Ensure server and username persist in the fields after logout
    chrome.storage.local.get(['server', 'username']).then((data) => {
      serverInput.value = data.server || "";
      usernameInput.value = data.username || "";
      resetFormToLoginState();
      showScreen(loginScreen);
    });
  });
});

// --- Webauth Actions ---

webauthLaunchBtn.addEventListener("click", () => {
  showError(null);
  const server = serverInput.value.trim().replace(/\/$/, "");
  const username = usernameInput.value.trim();
  
  if (!username) {
    showError("Please enter your Username first.");
    return;
  }
  
  // Save credentials immediately
  chrome.storage.local.set({ server, username });
  
  webauthLaunchBtn.disabled = true;
  webauthWaiting.style.display = "block";
  
  chrome.runtime.sendMessage({
    type: "START_WEBAUTH",
    server,
    username
  }, (response) => {
    webauthLaunchBtn.disabled = false;
    webauthWaiting.style.display = "none";
    
    if (response && response.success) {
      metaServer.textContent = server;
      metaUsername.textContent = username;
      startCountdown(response.validBefore);
      showScreen(dashboardScreen);
    } else {
      showError(response ? response.error : "Authentication failed or timed out.");
    }
  });
});

// Start the popup
init();
