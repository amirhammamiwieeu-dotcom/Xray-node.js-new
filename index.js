"use strict";
/*
 * Minimal VLESS + WebSocket / XHTTP server on Xray-core, for web-style hosts like Pella
 * (where the platform terminates TLS and forwards plain HTTP to your app).
 * No panel, no npm dependencies.
 *
 * Defaults for this version: plain HTTP inside the container (TLS=0) and WebSocket only.
 * The public link is built from PUBLIC_HOST (the domain your host gives you) on port 443 with TLS.
 *
 * Env vars:
 *   PUBLIC_HOST    REQUIRED on Pella: the domain the host gives your app (used in the client link)
 *   PUBLIC_PORT    port in the client link          (default 443)
 *   PUBLIC_TLS     "0" if the public side is plain  (default on)
 *   TRANSPORT      "ws" | "xhttp" | "both"          (default ws)
 *   TLS            "1" to make Xray do TLS itself   (default off; for raw-port hosts like Katabump)
 *   WS_PATH, XHTTP_PATH, UUID   fixed identity      (default: random, saved in data/state.json)
 *   XHTTP_MODE     mode in client link              (default packet-up)
 *   DOMAIN         SNI / Host when PUBLIC_HOST unset (default qy.manob.ir)
 *   ADDRESS        address in the link when PUBLIC_HOST unset (default: server public IP)
 *   CERT_FILE, KEY_FILE   own certificate (only with TLS=1)
 *   XRAY_VERSION, XRAY_URL, XRAY_BIN, DATA_DIR, LINK_NAME
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const net = require("net");
const { spawn, spawnSync } = require("child_process");

const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || "8080", 10);
const DOMAIN = process.env.DOMAIN || "qy.manob.ir";
const MODE = process.env.XHTTP_MODE || "packet-up";
const LINK_NAME = process.env.LINK_NAME || "";
const USE_TLS = process.env.TLS === "1";
const PUBLIC_HOST = process.env.PUBLIC_HOST || "";
const PUBLIC_PORT = parseInt(process.env.PUBLIC_PORT || "443", 10);
const PUBLIC_TLS = process.env.PUBLIC_TLS !== "0";
const TRANSPORT = (process.env.TRANSPORT || "ws").toLowerCase();
if (!["both", "xhttp", "ws"].includes(TRANSPORT)) {
  console.error('Fatal: TRANSPORT must be "both", "xhttp" or "ws"');
  process.exit(1);
}
const WANT_XHTTP = TRANSPORT !== "ws";
const WANT_WS = TRANSPORT !== "xhttp";

// Random identity, generated once and saved in data/state.json (override with env if you like).
const DEFAULT_UUID = crypto.randomUUID();
const DEFAULT_PATH = "/" + crypto.randomBytes(8).toString("hex");

const log = (...a) => console.log(new Date().toISOString(), ...a);

function pickDataDir() {
  const candidates = [process.env.DATA_DIR, path.join(process.cwd(), "data"), path.join(os.tmpdir(), "xhttp-data")].filter(Boolean);
  for (const dir of candidates) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.accessSync(dir, fs.constants.W_OK);
      return dir;
    } catch {}
  }
  throw new Error("No writable data directory found");
}

const DATA_DIR = pickDataDir();
const BIN_DIR = path.join(DATA_DIR, "bin");
const CERT_DIR = path.join(DATA_DIR, "cert");
const STATE_FILE = path.join(DATA_DIR, "state.json");
const CONFIG_FILE = path.join(DATA_DIR, "config.json");
const XRAY_BIN = process.env.XRAY_BIN || path.join(BIN_DIR, os.platform() === "win32" ? "xray.exe" : "xray");

// ---------- identity ----------
function loadState() {
  let st = {};
  try { st = JSON.parse(fs.readFileSync(STATE_FILE, "utf8")); } catch {}
  st.uuid = process.env.UUID || st.uuid || DEFAULT_UUID;
  let p = process.env.XHTTP_PATH || st.path || DEFAULT_PATH;
  st.path = p.startsWith("/") ? p : "/" + p;
  let wp = process.env.WS_PATH || st.wsPath || "/" + crypto.randomBytes(8).toString("hex");
  st.wsPath = wp.startsWith("/") ? wp : "/" + wp;
  fs.writeFileSync(STATE_FILE, JSON.stringify(st, null, 2), { mode: 0o600 });
  return st;
}

// ---------- public IP ----------
function isPrivateIp(ip) {
  return !ip || /^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || ip === "::" || ip === "::1";
}

async function resolveAddress() {
  if (PUBLIC_HOST) return PUBLIC_HOST;
  if (process.env.ADDRESS) return process.env.ADDRESS;
  if (!isPrivateIp(process.env.SERVER_IP)) return process.env.SERVER_IP;
  for (const url of ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
      const ip = (await r.text()).trim();
      if (r.ok && /^[0-9a-f.:]+$/i.test(ip)) return ip;
    } catch {}
  }
  log("WARNING: could not detect public IP, falling back to DOMAIN. Set ADDRESS manually if needed.");
  return DOMAIN;
}

// ---------- xray download (SHA256-verified when .dgst exists) ----------
async function download(url, dest) {
  const res = await fetch(url, { redirect: "follow", headers: { "User-Agent": "xhttp-server/1.0" } });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
}

async function expectedSha256(url) {
  try {
    const res = await fetch(url + ".dgst", { redirect: "follow" });
    if (!res.ok) return null;
    const m = (await res.text()).match(/SHA2?-?256\s*=\s*([0-9a-f]{64})/i);
    return m ? m[1].toLowerCase() : null;
  } catch { return null; }
}

function extractZip(zip, outDir) {
  const attempts = [
    ["unzip", ["-o", zip, "-d", outDir]],
    ["bsdtar", ["-xf", zip, "-C", outDir]],
    ["tar", ["-xf", zip, "-C", outDir]],
    ["python3", ["-m", "zipfile", "-e", zip, outDir]],
  ];
  for (const [cmd, args] of attempts) {
    if (spawnSync(cmd, args, { stdio: "ignore" }).status === 0) return;
  }
  throw new Error("Could not extract zip (need unzip, bsdtar or python3 on the host)");
}

async function ensureXray() {
  if (fs.existsSync(XRAY_BIN) && fs.statSync(XRAY_BIN).size > 1024 * 1024) return;
  fs.mkdirSync(BIN_DIR, { recursive: true });
  const arch = ["arm64", "aarch64"].includes(os.arch()) ? "arm64-v8a" : "64";
  const osName = os.platform() === "win32" ? "windows" : "linux";
  const zipName = `Xray-${osName}-${arch}.zip`;
  const ver = process.env.XRAY_VERSION;
  const url = process.env.XRAY_URL || (ver
    ? `https://github.com/XTLS/Xray-core/releases/download/v${ver.replace(/^v/, "")}/${zipName}`
    : `https://github.com/XTLS/Xray-core/releases/latest/download/${zipName}`);

  log(`Downloading Xray-core (${zipName})...`);
  const zipPath = path.join(BIN_DIR, zipName);
  await download(url, zipPath);

  const want = await expectedSha256(url);
  if (want) {
    const got = crypto.createHash("sha256").update(fs.readFileSync(zipPath)).digest("hex");
    if (got !== want) { fs.unlinkSync(zipPath); throw new Error("SHA256 mismatch for Xray download"); }
    log("Xray SHA256 verified.");
  } else {
    log("WARNING: no .dgst found, download not verified.");
  }

  const tmp = path.join(BIN_DIR, "extract_" + Date.now());
  fs.mkdirSync(tmp, { recursive: true });
  extractZip(zipPath, tmp);
  for (const f of fs.readdirSync(tmp)) fs.copyFileSync(path.join(tmp, f), path.join(BIN_DIR, f));
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.unlinkSync(zipPath);
  if (os.platform() !== "win32") fs.chmodSync(XRAY_BIN, 0o755);
  log("Xray installed.");
}

// ---------- TLS certificate ----------
function ensureCert() {
  if (process.env.CERT_FILE && process.env.KEY_FILE) {
    return { crt: process.env.CERT_FILE, key: process.env.KEY_FILE, selfSigned: false };
  }
  fs.mkdirSync(CERT_DIR, { recursive: true });
  const crt = path.join(CERT_DIR, "server.crt");
  const key = path.join(CERT_DIR, "server.key");
  if (!fs.existsSync(crt) || !fs.existsSync(key)) {
    log(`Generating self-signed certificate for ${DOMAIN}...`);
    spawnSync(XRAY_BIN, ["tls", "cert", `-domain=${DOMAIN}`, "-name=" + DOMAIN, "-org=" + DOMAIN, "-expire=87600h", `-file=${path.join(CERT_DIR, "server")}`], { stdio: "ignore" });
    if (!fs.existsSync(crt) || !fs.existsSync(key)) {
      const r = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "3650", "-subj", `/CN=${DOMAIN}`, "-addext", `subjectAltName=DNS:${DOMAIN}`], { stdio: "ignore" });
      if (r.status !== 0) throw new Error("Could not generate a certificate (xray tls cert and openssl both failed)");
    }
  }
  return { crt, key, selfSigned: true };
}

function certPin(crtPath) {
  try { return new crypto.X509Certificate(fs.readFileSync(crtPath)).fingerprint256.replace(/:/g, "").toLowerCase(); } catch { return null; }
}

// ---------- internal ports ----------
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
}

// ---------- config + link ----------
function buildConfig(st, cert, ports) {
  const clients = [{ id: st.uuid }];
  const xhttpStream = () => ({ network: "xhttp", security: "none", xhttpSettings: { path: st.path, mode: "auto" } });
  const wsStream = () => ({ network: "ws", security: "none", wsSettings: { path: st.wsPath } });
  const withTls = (stream) => {
    if (cert) {
      stream.security = "tls";
      stream.tlsSettings = { alpn: ["h2", "http/1.1"], certificates: [{ certificateFile: cert.crt, keyFile: cert.key }] };
    }
    return stream;
  };

  const inbounds = [];
  if (TRANSPORT === "both") {
    // Public port: VLESS over TCP(+TLS) that only acts as a path router (fallbacks).
    const fallbacks = [{ dest: ports.xhttp }];
    if (cert) fallbacks.push({ alpn: "h2", dest: ports.xhttp });
    fallbacks.push({ path: st.wsPath, dest: ports.ws });
    fallbacks.push({ path: st.path, dest: ports.xhttp });
    inbounds.push({
      tag: "front",
      listen: "0.0.0.0",
      port: PORT,
      protocol: "vless",
      settings: { clients, decryption: "none", fallbacks },
      streamSettings: withTls({ network: "tcp", security: "none" }),
    });
    inbounds.push({
      tag: "vless-xhttp", listen: "127.0.0.1", port: ports.xhttp, protocol: "vless",
      settings: { clients, decryption: "none" }, streamSettings: xhttpStream(),
    });
    inbounds.push({
      tag: "vless-ws", listen: "127.0.0.1", port: ports.ws, protocol: "vless",
      settings: { clients, decryption: "none" }, streamSettings: wsStream(),
    });
  } else {
    inbounds.push({
      tag: TRANSPORT === "ws" ? "vless-ws" : "vless-xhttp",
      listen: "0.0.0.0",
      port: PORT,
      protocol: "vless",
      settings: { clients, decryption: "none" },
      streamSettings: withTls(TRANSPORT === "ws" ? wsStream() : xhttpStream()),
    });
  }

  return {
    log: { loglevel: "warning" },
    inbounds,
    outbounds: [
      { tag: "direct", protocol: "freedom" },
      { tag: "block", protocol: "blackhole" },
    ],
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [{ type: "field", ip: ["geoip:private"], outboundTag: "block" }],
    },
  };
}

function buildLink(st, address, cert, kind) {
  const viaProxy = !!PUBLIC_HOST;                 // host terminates TLS for us
  const sniHost = PUBLIC_HOST || DOMAIN;
  const port = viaProxy ? PUBLIC_PORT : PORT;
  const q = { encryption: "none", type: kind, host: sniHost };
  if (kind === "xhttp") { q.path = st.path; q.mode = MODE; }
  else { q.path = st.wsPath; }
  if (viaProxy ? PUBLIC_TLS : cert) {
    q.security = "tls";
    q.sni = sniHost;
    q.fp = "chrome";
    if (kind === "ws") q.alpn = "http/1.1";
    if (!viaProxy && cert && cert.selfSigned) {
      q.allowInsecure = "1";
      const pin = certPin(cert.crt);
      if (pin) q.pcs = pin;
    }
  } else {
    q.security = "none";
  }
  const h = address.includes(":") ? `[${address}]` : address;
  const name = (LINK_NAME ? LINK_NAME + "-" : "") + kind.toUpperCase();
  return `vless://${st.uuid}@${h}:${port}?${new URLSearchParams(q).toString()}#${encodeURIComponent(name)}`;
}

// ---------- run + supervise ----------
let child = null, stopping = false, fails = 0;

function start() {
  const started = Date.now();
  child = spawn(XRAY_BIN, ["run", "-c", CONFIG_FILE], {
    stdio: "inherit",
    env: { ...process.env, XRAY_LOCATION_ASSET: path.dirname(XRAY_BIN) },
  });
  child.on("exit", (code, sig) => {
    if (stopping) return;
    fails = Date.now() - started > 30000 ? 0 : fails + 1;
    const wait = Math.min(30000, 1000 * 2 ** Math.min(fails, 5));
    log(`Xray exited (code=${code} signal=${sig}). Restarting in ${wait / 1000}s...`);
    setTimeout(start, wait);
  });
}

function shutdown() {
  stopping = true;
  if (child) child.kill("SIGTERM");
  setTimeout(() => process.exit(0), 1500);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

(async () => {
  const st = loadState();
  await ensureXray();
  const cert = USE_TLS ? ensureCert() : null;
  const ports = TRANSPORT === "both" ? { xhttp: await freePort(), ws: await freePort() } : null;
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(buildConfig(st, cert, ports), null, 2), { mode: 0o600 });
  if (!PUBLIC_HOST) log("NOTE: PUBLIC_HOST is not set; the printed link uses the server IP and the internal port, which will not work behind Pella. Set PUBLIC_HOST to your Pella domain.");
  const address = await resolveAddress();
  start();
  const links = [];
  if (WANT_XHTTP) links.push(buildLink(st, address, cert, "xhttp"));
  if (WANT_WS) links.push(buildLink(st, address, cert, "ws"));
  fs.writeFileSync(path.join(DATA_DIR, "link.txt"), links.join("\n") + "\n", { mode: 0o600 });
  log(`${TRANSPORT.toUpperCase()} listening on 0.0.0.0:${PORT} (${cert ? "TLS" : "plain"}), address ${address}`);
  log("Client link(s):");
  for (const l of links) console.log(l);
})().catch((err) => {
  console.error("Fatal:", err.message);
  process.exit(1);
});
