/* QR Shield – decision support for QR codes. Vanilla JS, no backend, memory-only history. */
"use strict";

/* ================= 1. CONFIG ================= */
const SAMPLES = {
  safe: "https://www.wikipedia.org/",
  suspicious: "http://bit.ly/secure-login-verify?user=reward",
  dangerous: "upi://pay?pa=fraudster@upi&pn=Unknown%20Payee&tn=Scan%20to%20receive%20your%20refund"
};

const THRESHOLDS = { suspicious: 1, dangerous: 6 };

const LIVE_CHECK_ENDPOINT = "/.netlify/functions/check-url";
const LIVE_THREAT_POINTS = 5;

const RESOLVE_ENDPOINT = "/.netlify/functions/resolve-url";

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co",
  "is.gd", "cutt.ly", "rb.gy", "shorturl.at"
];

const SUSPICIOUS_TLDS = ["xyz", "top", "buzz", "click", "loan", "work", "gq", "tk"];

const SUSPICIOUS_WORDS = [
  "verify", "urgent", "reward", "login", "password",
  "otp", "refund", "kyc", "winner"
];

const BRANDS = [
  { name: "Google", keys: ["google"], official: ["google.com", "google.co.in"] },
  { name: "Amazon", keys: ["amazon"], official: ["amazon.com", "amazon.in"] },
  { name: "Flipkart", keys: ["flipkart"], official: ["flipkart.com"] },
  { name: "Paytm", keys: ["paytm"], official: ["paytm.com"] },
  { name: "PhonePe", keys: ["phonepe"], official: ["phonepe.com"] },
  { name: "Google Pay", keys: ["googlepay", "gpay"], official: ["pay.google.com", "gpay.app.goo.gl"] },
  { name: "SBI", keys: ["sbi"], official: ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"], shortKey: true },
  { name: "HDFC Bank", keys: ["hdfcbank", "hdfc"], official: ["hdfcbank.com"] },
  { name: "ICICI Bank", keys: ["icicibank", "icici"], official: ["icicibank.com"] },
  { name: "Axis Bank", keys: ["axisbank"], official: ["axisbank.com"] }
];

const UPI_RECEIVE_RE = /\b(receive|refund|cashback|win|prize|claim|reward)\b|get money/i;

const ADVICE = {
  safe: "No obvious warning signs were detected. Still check the website address and recipient details before entering personal or payment information.",
  suspicious: "Do not enter passwords, OTPs, card details, or UPI PINs. Verify the sender or website through an official app or website before continuing.",
  dangerous: "Do not open this link or approve any payment. If this appeared in a message, verify it independently and report or block the sender if appropriate.",
  unknown: "This QR type is not automatically analyzed. Check the content carefully before opening it, sharing information, or making a payment."
};

const LABELS = {
  safe: "Safe",
  suspicious: "Suspicious",
  dangerous: "Dangerous",
  unknown: "Unknown / Review"
};

/* ================= 2. PARSING ================= */
function detectType(text) {
  const t = text.trim().toLowerCase();

  if (t.startsWith("http://") || t.startsWith("https://")) return "url";
  if (t.startsWith("upi://")) return "upi";

  return "other";
}

function parseUrl(text) {
  try {
    const u = new URL(text.trim());
    return {
      ok: true,
      u,
      host: u.hostname.toLowerCase(),
      authority: u.host
    };
  } catch {
    return { ok: false };
  }
}

function parseUpi(text) {
  const query = text.trim().split("?")[1] || "";
  const p = new URLSearchParams(query);

  return {
    vpa: p.get("pa") || "",
    name: p.get("pn") || "",
    amount: p.get("am") || "",
    note: p.get("tn") || ""
  };
}

function registrableLen(parts) {
  const sld = ["co", "com", "org", "net", "ac", "gov", "edu"];
  return parts.length >= 3 &&
    parts[parts.length - 1].length === 2 &&
    sld.includes(parts[parts.length - 2])
    ? 3
    : 2;
}

/* ================= 3. RISK RULES ================= */
const flag = (rule, points, why) => ({ rule, points, why });

function matchedWords(text) {
  let decoded = text;

  try {
    decoded = decodeURIComponent(text);
  } catch {
    /* keep raw */
  }

  return SUSPICIOUS_WORDS.filter(word =>
    new RegExp(`\\b${word}\\b`, "i").test(decoded)
  );
}

function urlFlags(text, info) {
  const flags = [];
  const { u, host, authority } = info;
  const parts = host.split(".");

  if (SHORTENERS.some(domain => host === domain || host.endsWith("." + domain))) {
    flags.push(flag(
      "Shortened link",
      2,
      "This link hides its real destination behind a link-shortening service."
    ));
  }

  if (u.protocol === "http:") {
    flags.push(flag(
      "HTTP instead of HTTPS",
      2,
      "The website connection is not encrypted."
    ));
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    flags.push(flag(
      "IP address instead of domain",
      2,
      "The link uses a raw IP address instead of a normal website domain."
    ));
  }

  const flat = host.replace(/-/g, "");

  const fake = BRANDS.find(brand => {
    const mentions = brand.keys.some(key =>
      brand.shortKey
        ? parts.join(".").split(/[.-]/).includes(key)
        : flat.includes(key)
    );

    const official = brand.official.some(domain =>
      host === domain || host.endsWith("." + domain)
    );

    return mentions && !official;
  });

  if (fake) {
    flags.push(flag(
      "Look-alike domain",
      3,
      `The domain may imitate a trusted brand (${fake.name}).`
    ));
  }

  const words = matchedWords(text);

  if (words.length) {
    flags.push(flag(
      "Suspicious words",
      words.length >= 2 ? 2 : 1,
      `The content contains pressure or credential-related words (${words.join(", ")}).`
    ));
  }

  if (SUSPICIOUS_TLDS.includes(parts[parts.length - 1])) {
    flags.push(flag(
      "Suspicious TLD",
      2,
      "This domain extension is commonly associated with risky or low-trust websites."
    ));
  }

  if (authority.includes("@")) {
    flags.push(flag(
      "@ symbol in URL",
      2,
      "An @ symbol can hide the actual destination website from the visible URL."
    ));
  }

  if (
    parts.length - registrableLen(parts) >= 3 ||
    text.trim().length > 120
  ) {
    flags.push(flag(
      "Too many subdomains or very long URL",
      1,
      "The URL has many subdomains or is unusually long, which can make it harder to inspect."
    ));
  }

  if (host.includes("xn--")) {
    flags.push(flag(
      "Punycode / look-alike characters",
      3,
      "The domain uses Punycode, which can imitate familiar website names using similar-looking characters."
    ));
  }

  return flags;
}

function upiFlags(text, data) {
  const flags = [];
  const words = matchedWords(text);

  if (words.length) {
    flags.push(flag(
      "Suspicious words",
      words.length >= 2 ? 2 : 1,
      `The content contains pressure or credential-related words (${words.join(", ")}).`
    ));
  }

  if (UPI_RECEIVE_RE.test(data.name) || UPI_RECEIVE_RE.test(data.note)) {
    flags.push(flag(
      "UPI asks you to receive money",
      4,
      "A genuine incoming payment does not require you to scan a QR code or enter a UPI PIN."
    ));
  }

  if (!data.vpa) {
    flags.push(flag(
      "Missing payee address",
      2,
      "The UPI link does not clearly identify the payment recipient."
    ));
  }

  return flags;
}

/* ================= 4. ANALYZER ================= */
const verdictFor = score =>
  score >= THRESHOLDS.dangerous ? "dangerous"
  : score >= THRESHOLDS.suspicious ? "suspicious"
  : "safe";

function analyze(text) {
  const type = detectType(text);
  const base = {
    text,
    type,
    flags: [],
    details: [],
    score: 0
  };

  if (type === "url") {
    const info = parseUrl(text);

    if (!info.ok) {
      return {
        ...base,
        type: "other",
        verdict: "unknown",
        typeLabel: "Unknown / Review (malformed link)"
      };
    }

    const { u } = info;

    base.details = [
      ["Full URL", u.href],
      ["Protocol", u.protocol.replace(":", "")],
      ["Domain", info.host],
      [
        "Path / query",
        (u.pathname + u.search) === "/" ? "None" : u.pathname + u.search
      ]
    ];

    base.flags = urlFlags(text, info);
    base.typeLabel = "Web URL";
  } else if (type === "upi") {
    const data = parseUpi(text);

    base.details = [
      ["Payee address (VPA)", data.vpa || "Not provided"],
      ["Payee name", data.name || "Not provided"],
      ["Amount", data.amount || "Not specified"],
      ["Transaction note", data.note || "None"]
    ];

    base.flags = upiFlags(text, data);
    base.typeLabel = "UPI payment link";
  } else {
    return {
      ...base,
      verdict: "unknown",
      typeLabel: "Unknown / Review"
    };
  }

  base.score = base.flags.reduce((total, item) => total + item.points, 0);
  base.verdict = verdictFor(base.score);

  return base;
}

/* ================= 5. RENDERING ================= */
const $ = id => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);

  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;

  return node;
}

function renderResult(result) {
  const panel = $("result");
  const body = $("result-body");

  panel.dataset.verdict = result.verdict;
  body.replaceChildren();

  const unknown = result.verdict === "unknown";

  const strip = el("div", "verdict-strip");
  const gauge = el("div", "gauge");

  gauge.style.setProperty("--p", Math.min(result.score, 10) * 10 + "%");
  gauge.append(
    el("b", "", unknown ? "?" : String(result.score)),
    el("small", "", unknown ? "review" : "points")
  );

  const info = el("div", "vs-info");

  info.append(
    el("span", "badge big " + result.verdict, LABELS[result.verdict]),
    el(
      "div",
      "score",
      unknown
        ? "Manual review needed"
        : `Risk score: ${result.score} point${result.score === 1 ? "" : "s"}`
    ),
    el("div", "hint", "Detected content type: " + result.typeLabel)
  );

  if (result.dest) {
    info.append(el("div", "live-status " + result.dest.status, destText(result.dest)));
  }

  if (result.live) {
    info.append(el("div", "live-status " + result.live.status, liveText(result.live)));
  }

  strip.append(gauge, info);
  body.append(strip);

  body.append(
    el("h4", "", "Decoded content"),
    el("div", "mono", result.text)
  );

  if (result.details.length) {
    const details = el("dl", "details");

    result.details.forEach(([key, value]) => {
      details.append(el("dt", "", key), el("dd", "", value));
    });

    body.append(details);
  }

  if (result.verdict !== "unknown") {
    body.append(el("h4", "", "Triggered reasons"));

    if (!result.flags.length) {
      body.append(el("p", "hint", "No risk rules were triggered."));
    } else {
      const reasons = el("ul", "reasons");

      result.flags.forEach(item => {
        const listItem = el("li");
        const title = el("strong", "", item.rule);

        title.append(
          el("span", "", `+${item.points} point${item.points === 1 ? "" : "s"}`)
        );

        listItem.append(title, el("p", "", item.why));
        reasons.append(listItem);
      });

      body.append(reasons);
    }
  }

  body.append(
    el("div", "advice", "Recommended action: " + ADVICE[result.verdict])
  );

  if (result.type === "url" && result.details.length) {
    const openButton = el("button", "btn", "Open link ");
    openButton.style.marginTop = "12px";

    openButton.addEventListener("click", () => {
      const confirmed = confirm(
        "Open this link in a new tab?\n\n" + result.text
      );

      if (confirmed) {
        window.open(result.text.trim(), "_blank", "noopener,noreferrer");
      }
    });

    body.append(openButton);
  }
}

function showEmpty() {
  $("result").dataset.verdict = "empty";

  const emptyState = el("div", "empty-state");

  emptyState.append(
    el("div", "big", "🔍"),
    el(
      "p",
      "",
      "No result yet. Upload an image, scan with the camera, paste text, or try a sample."
    )
  );

  $("result-body").replaceChildren(emptyState);
}

/* ================= 6. HISTORY ================= */
const history = [];
const MAX_HISTORY = 50;

function renderHistory() {
  const tbody = $("hist-body");
  tbody.replaceChildren();

  history.forEach(item => {
    const row = el("tr");
    const verdictCell = el("td");

    verdictCell.append(
      el("span", "badge " + item.verdict, LABELS[item.verdict])
    );

    const shortText =
      item.text.length > 70
        ? item.text.slice(0, 70) + "…"
        : item.text;

    row.append(
      el("td", "", item.time),
      el("td", "", item.method),
      el("td", "", item.typeLabel),
      verdictCell,
      el("td", "", item.verdict === "unknown" ? "–" : String(item.score)),
      el("td", "", shortText)
    );

    tbody.append(row);
  });

  $("hist-empty").hidden = history.length > 0;
}

/* ================= 7. MAIN FLOW ================= */
async function liveCheck(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);

  try {
    const response = await fetch(LIVE_CHECK_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    if (!response.ok) return { status: "unavailable" };

    const data = await response.json();

    return data.flagged
      ? { status: "flagged", threats: data.threats || [] }
      : { status: "clear" };
  } catch {
    return { status: "unavailable" };
  } finally {
    clearTimeout(timeout);
  }
}

function liveText(live) {
  if (live.status === "checking") {
    return "🔄 Live check: asking Google Safe Browsing…";
  }

  if (live.status === "flagged") {
    return "🚨 Google Safe Browsing lists this link as a known threat (" +
      live.threats.join(", ") + ").";
  }

  if (live.status === "clear") {
    return "✅ Google Safe Browsing: no known threat found. This does not guarantee the link is safe.";
  }

  return "⚪ Live check unavailable (offline or not set up). Local rules only.";
}

function applyLive(result, live) {
  result.live = live;

  if (live.status === "flagged") {
    result.flags.push(flag(
      "Known malicious link (Google Safe Browsing)",
      LIVE_THREAT_POINTS,
      "Google Safe Browsing reports this link as unsafe: " +
        live.threats.join(", ") + "."
    ));

    result.score += LIVE_THREAT_POINTS;
    result.verdict = verdictFor(result.score);
  }
}

async function resolveShort(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(RESOLVE_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    if (!response.ok) return { status: "unavailable" };

    const data = await response.json();

    return data.final
      ? {
          status: "resolved",
          final: data.final,
          chain: data.chain || [data.final],
          truncated: Boolean(data.truncated)
        }
      : { status: "unavailable" };
  } catch {
    return { status: "unavailable" };
  } finally {
    clearTimeout(timeout);
  }
}

function destText(destination) {
  if (destination.status === "checking") {
    return "🔄 Following the short link to find the real website…";
  }

  if (destination.status === "resolved") {
    return destination.chain.length > 1
      ? "🔗 Real destination found (" +
        (destination.chain.length - 1) +
        " redirect" +
        (destination.chain.length > 2 ? "s" : "") +
        (destination.truncated ? ", stopped early" : "") +
        "). See details."
      : "🔗 No redirect found for this short link.";
  }

  return "⚪ This link hides its real destination, and it could not be followed (offline or not set up).";
}

function applyDest(result, destination) {
  result.dest = destination;

  if (
    destination.status !== "resolved" ||
    destination.final === result.text
  ) {
    return;
  }

  result.details.push(
    ["Real destination", destination.final],
    [
      "Redirect hops",
      String(destination.chain.length - 1) + (destination.truncated ? "+" : "")
    ]
  );

  const destinationAnalysis = analyze(destination.final);

  if (destinationAnalysis.type !== "url") return;

  destinationAnalysis.flags
    .filter(item =>
      item.rule !== "Shortened link" &&
      !result.flags.some(existing => existing.rule === item.rule)
    )
    .forEach(item => {
      result.flags.push(flag(
        "Destination: " + item.rule,
        item.points,
        item.why
      ));

      result.score += item.points;
    });

  result.verdict = verdictFor(result.score);
}

let scanSequence = 0;

function handleContent(text, method) {
  $("input-error").textContent = "";

  if (!text || !text.trim()) {
    $("input-error").textContent =
      "Nothing to analyze. Enter or scan some QR content first.";
    return;
  }

  $("result").dataset.verdict = "empty";
  $("result-body").replaceChildren(
    el("p", "loading", "Analyzing content…")
  );

  const sequence = ++scanSequence;

  setTimeout(() => {
    const result = analyze(text.trim());

    const entry = {
      time: new Date().toLocaleTimeString(),
      method,
      typeLabel: result.typeLabel,
      verdict: result.verdict,
      score: result.score,
      text: result.text
    };

    const checkable = result.type === "url" && result.details.length > 0;

    if (checkable) result.live = { status: "checking" };

    if (
      checkable &&
      result.flags.some(item => item.rule === "Shortened link")
    ) {
      result.dest = { status: "checking" };
    }

    renderResult(result);

    history.unshift(entry);

    if (history.length > MAX_HISTORY) {
      history.length = MAX_HISTORY;
    }

    renderHistory();
    $("result").scrollIntoView({
      behavior: "smooth",
      block: "start"
    });

    if (checkable) runChecks(result, entry, sequence);
  }, 250);
}

async function runChecks(result, entry, sequence) {
  const isCurrent = () => sequence === scanSequence;

  const refresh = () => {
    if (!isCurrent()) return;

    Object.assign(entry, {
      verdict: result.verdict,
      score: result.score
    });

    renderHistory();
    renderResult(result);
  };

  const targets = [result.text];

  if (result.dest) {
    const destination = await resolveShort(result.text);

    if (!isCurrent()) return;

    applyDest(result, destination);

    if (
      destination.status === "resolved" &&
      destination.final !== result.text &&
      /^https?:/i.test(destination.final)
    ) {
      targets.push(destination.final);
    }

    refresh();
  }

  const results = await Promise.all(
    targets.map(target => liveCheck(target))
  );

  if (!isCurrent()) return;

  const selected =
    results.find(item => item.status === "flagged") ||
    results.find(item => item.status === "clear") ||
    { status: "unavailable" };

  applyLive(result, selected);
  refresh();
}

/* ================= 8. INPUT METHODS ================= */
$("file-input").addEventListener("change", async event => {
  const file = event.target.files[0];

  if (!file) return;

  if (!/^image\/(png|jpeg)$/.test(file.type)) {
    $("input-error").textContent = "Please choose a JPG or PNG image.";
    return;
  }

  $("input-error").textContent = "";

  try {
    const scanner = new Html5Qrcode("file-reader");
    const text = await scanner.scanFile(file, false);

    handleContent(text, "Uploaded image");
  } catch {
    $("input-error").textContent =
      "No QR code was found in this image. Try a clearer, closer, well-lit picture.";
  }

  event.target.value = "";
});

let cameraScanner = null;
let cameraRunning = false;
let cameraStarting = false;

const setCameraMessage = text => {
  $("cam-msg").textContent = text;
};

function setCameraUi(isRunning) {
  cameraRunning = isRunning;
  $("cam-start").disabled = isRunning;
  $("cam-stop").disabled = !isRunning;
}

async function stopCamera() {
  if (!cameraScanner || !cameraRunning) return;

  try {
    await cameraScanner.stop();
    cameraScanner.clear();
  } catch {
    /* already stopped */
  }

  setCameraUi(false);
}

$("cam-start").addEventListener("click", async () => {
  if (cameraStarting || cameraRunning) return;

  $("input-error").textContent = "";
  setCameraMessage("Requesting camera permission…");
  setCameraUi(true);
  cameraStarting = true;

  try {
    cameraScanner = new Html5Qrcode("reader");

    await cameraScanner.start(
      { facingMode: "environment" },
      { fps: 10, qrbox: { width: 220, height: 220 } },
      async text => {
        await stopCamera();
        setCameraMessage("QR code detected. Camera stopped.");
        handleContent(text, "Live camera");
      },
      () => {
        /* Per-frame no-QR events are normal. */
      }
    );

    setCameraMessage("Point the camera at a QR code.");
  } catch (error) {
    setCameraUi(false);

    const message = String(error);

    if (/NotAllowed|Permission|denied/i.test(message)) {
      setCameraMessage(
        "Camera permission was denied. Allow camera access in your browser settings and try again."
      );
    } else if (/NotFound|no camera|Requested device/i.test(message)) {
      setCameraMessage(
        "No camera was found on this device. Try uploading an image instead."
      );
    } else {
      setCameraMessage(
        "Could not start the camera. Make sure the page is opened over HTTPS or localhost."
      );
    }
  } finally {
    cameraStarting = false;
  }
});

$("cam-stop").addEventListener("click", async () => {
  await stopCamera();
  setCameraMessage("Camera stopped.");
});

$("paste-btn").addEventListener("click", () => {
  handleContent($("paste-text").value, "Pasted text");
});

/* New Clear button under Analyze pasted content */
$("paste-clear-btn").addEventListener("click", () => {
  $("paste-text").value = "";
  $("input-error").textContent = "";
  $("paste-text").focus();
  showEmpty();
});

document.querySelectorAll("[data-sample]").forEach(button => {
  button.addEventListener("click", () => {
    handleContent(SAMPLES[button.dataset.sample], "Sample");
  });
});

$("clear-btn").addEventListener("click", () => {
  history.length = 0;
  renderHistory();
});

document.addEventListener("click", event => {
  const button = event.target.closest(".btn");

  if (!button || button.disabled) return;

  const rect = button.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);

  const ripple = document.createElement("span");
  ripple.className = "ripple";

  ripple.style.cssText = `
    width:${size}px;
    height:${size}px;
    left:${event.clientX - rect.left - size / 2}px;
    top:${event.clientY - rect.top - size / 2}px;
  `;

  button.appendChild(ripple);
  setTimeout(() => ripple.remove(), 650);
});

/* ================= 9. INIT ================= */
showEmpty();
renderHistory();

/* ================= 10. THEME + LOGIN ================= */
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;

  try {
    localStorage.setItem("qrs_theme", theme);
  } catch {
    /* storage unavailable */
  }

  document.querySelectorAll(".theme-toggle").forEach(button => {
    button.textContent = theme === "dark" ? "☀️ Light" : "🌙 Dark";
  });
}

setTheme(
  document.documentElement.dataset.theme === "dark" ? "dark" : "light"
);

document.querySelectorAll(".theme-toggle").forEach(button => {
  button.addEventListener("click", () => {
    const nextTheme =
      document.documentElement.dataset.theme === "dark" ? "light" : "dark";

    setTheme(nextTheme);
  });
});

function showApp(isSignedIn) {
  $("login").hidden = isSignedIn;
  $("app").hidden = !isSignedIn;

  if (isSignedIn) {
    let username = "";

    try {
      username = sessionStorage.getItem("qrs_user") || "";
    } catch {
      /* ignore */
    }

    $("who").textContent = username ? "👤 " + username : "";
  }
}

let signedIn = false;

try {
  signedIn = sessionStorage.getItem("qrs_auth") === "1";
} catch {
  /* ignore */
}

showApp(signedIn);

const USERS_KEY = "qrs_users";

const loadUsers = () => {
  try {
    return JSON.parse(localStorage.getItem(USERS_KEY)) || {};
  } catch {
    return {};
  }
};

const saveUsers = users => {
  try {
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
    return true;
  } catch {
    return false;
  }
};

const toHex = buffer =>
  [...new Uint8Array(buffer)]
    .map(value => value.toString(16).padStart(2, "0"))
    .join("");

const fromHex = hex =>
  new Uint8Array(hex.match(/../g).map(value => parseInt(value, 16)));

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: fromHex(saltHex),
      iterations: 100000
    },
    key,
    256
  );

  return toHex(derivedBits);
}

const hasCrypto = () =>
  Boolean(window.crypto && crypto.subtle);

function switchTab(selectedTab) {
  const registerSelected = selectedTab === "register";

  $("login-form").hidden = registerSelected;
  $("register-form").hidden = !registerSelected;

  $("tab-signin").setAttribute("aria-selected", String(!registerSelected));
  $("tab-register").setAttribute("aria-selected", String(registerSelected));

  $("login-error").textContent = "";
  $("register-error").textContent = "";
  $("auth-info").textContent = "";
}

$("tab-signin").addEventListener("click", () => switchTab("signin"));
$("tab-register").addEventListener("click", () => switchTab("register"));

document.querySelectorAll(".show-pw input").forEach(checkbox => {
  checkbox.addEventListener("change", () => {
    checkbox
      .closest("form")
      .querySelectorAll("input[data-pw]")
      .forEach(input => {
        input.type = checkbox.checked ? "text" : "password";
      });
  });
});

$("reg-pass").addEventListener("input", () => {
  const password = $("reg-pass").value;

  const points = [
    password.length >= 8,
    /[a-z]/i.test(password),
    /\d/.test(password),
    /[A-Z]/.test(password) && /[a-z]/.test(password),
    /[^a-z0-9]/i.test(password) || password.length >= 12
  ].filter(Boolean).length;

  const level = !password ? 0 : points <= 2 ? 1 : points <= 4 ? 2 : 3;

  $("pw-bar").style.width = [0, 33, 66, 100][level] + "%";
  $("pw-bar").style.background =
    ["", "var(--bad)", "#f59e0b", "var(--safe)"][level];

  $("pw-hint").textContent = [
    "Use 8+ characters with a letter and a number.",
    "Weak password",
    "Okay password",
    "Strong password"
  ][level];
});

$("register-form").addEventListener("submit", async event => {
  event.preventDefault();

  const fail = message => {
    $("register-error").textContent = message;
  };

  const name = $("reg-name").value.trim();
  const username = $("reg-user").value.trim().toLowerCase();
  const password = $("reg-pass").value;

  if (!hasCrypto()) {
    return fail(
      "Registration needs HTTPS or localhost (secure browser features)."
    );
  }

  if (name.length < 2) return fail("Please enter your name.");

  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return fail("Username: 3 to 20 letters, numbers or underscores.");
  }

  if (
    password.length < 8 ||
    !/[a-z]/i.test(password) ||
    !/\d/.test(password)
  ) {
    return fail(
      "Password needs 8+ characters with at least one letter and one number."
    );
  }

  if (password !== $("reg-pass2").value) {
    return fail("Passwords do not match.");
  }

  const users = loadUsers();

  if (users[username]) {
    return fail("That username is already taken.");
  }

  const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));

  users[username] = {
    name,
    salt,
    hash: await hashPassword(password, salt)
  };

  if (!saveUsers(users)) {
    return fail("Could not save the account (browser storage is blocked).");
  }

  event.target.reset();
  $("pw-bar").style.width = "0";

  switchTab("signin");
  $("login-user").value = username;
  $("auth-info").textContent = "Account created. Please sign in.";
  $("login-pass").focus();
});

$("login-form").addEventListener("submit", async event => {
  event.preventDefault();

  const username = $("login-user").value.trim().toLowerCase();
  const password = $("login-pass").value;

  let name = null;
  const account = loadUsers()[username];

  if (
    account &&
    hasCrypto() &&
    await hashPassword(password, account.salt) === account.hash
  ) {
    name = account.name;
  }

  if (name) {
    try {
      sessionStorage.setItem("qrs_auth", "1");
      sessionStorage.setItem("qrs_user", name);
    } catch {
      /* ignore */
    }

    $("login-error").textContent = "";
    $("auth-info").textContent = "";
    $("login-pass").value = "";

    showApp(true);
    window.scrollTo(0, 0);
  } else {
    $("login-error").textContent =
      "Incorrect username or password. New here? Use the Register tab.";
  }
});

$("logout-btn").addEventListener("click", async () => {
  await stopCamera();

  try {
    sessionStorage.removeItem("qrs_auth");
    sessionStorage.removeItem("qrs_user");
  } catch {
    /* ignore */
  }

  history.length = 0;
  renderHistory();
  showEmpty();
  showApp(false);
});