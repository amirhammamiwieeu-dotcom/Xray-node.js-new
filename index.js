"use strict";
/*
 * Pure Node.js VLESS server: WebSocket + XHTTP on ONE port.
 * No npm packages, no Xray binary, no downloads, nothing written to disk.
 *
 * - Works behind any host that gives you a domain and forwards HTTP(S) to your app
 *   (Pella, Render, Railway, Koyeb, Fly, Cloudflare in front, ...). The host's proxy
 *   terminates TLS; this server speaks plain HTTP on the port the host gives it.
 * - You do NOT need to know the domain in advance. The server learns it from the first
 *   request it receives (or from the host's env vars) and prints ready-made links
 *   in the console. You can also open  https://YOUR-DOMAIN/link/<UUID>  at any time.
 * - UUID and paths are fixed below on purpose, so a new deploy / new domain gives you
 *   the same identity (only the domain part of the link changes). Keep this file private.
 *
 * XHTTP modes understood by the server: packet-up, stream-up, stream-one.
 * (Behind most proxies/CDNs use mode=packet-up in the client; it is the default in the links.)
 * TCP only: no UDP, no Mux. Keep Mux turned off in your client.
 *
 * Optional env vars: PUBLIC_HOST, PUBLIC_PORT, PUBLIC_TLS(0/1), TRANSPORT(both|ws|xhttp),
 *                    UUID, WS_PATH, XHTTP_PATH, XHTTP_MODE, LINK_NAME
 */

const http = require("http");
const net = require("net");
const dns = require("dns");
const crypto = require("crypto");

// ---------------- settings ----------------
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || "8080", 10);
const UUID = (process.env.UUID || "f7fbc28d-a20b-47b7-99bc-f0f5c3bc25b3").toLowerCase();
const WS_PATH = normPath(process.env.WS_PATH || "/0a765f845a3e1c8c");
const XHTTP_PATH = normPath(process.env.XHTTP_PATH || "/4b1de93a27c0f6e5");
const XHTTP_MODE = process.env.XHTTP_MODE || "packet-up";
const LINK_NAME = process.env.LINK_NAME || "Node";
const TRANSPORT = (process.env.TRANSPORT || "both").toLowerCase();
const FORCE_PORT = process.env.PUBLIC_PORT || "";
const FORCE_TLS = process.env.PUBLIC_TLS; // "0" or "1" or undefined
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === "1"; // local tests only

const WANT_WS = TRANSPORT !== "xhttp";
const WANT_XHTTP = TRANSPORT !== "ws";
const MAX_FRAME = 4 * 1024 * 1024;     // WebSocket frame / XHTTP POST size cap
const MAX_PENDING = 8 * 1024 * 1024;   // buffered downlink before the GET arrives
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

function normPath(p) {
  p = p.startsWith("/") ? p : "/" + p;
  return p.length > 1 && p.endsWith("/") ? p.slice(0, -1) : p;
}

if (!["both", "ws", "xhttp"].includes(TRANSPORT)) {
  console.error('Fatal: TRANSPORT must be "both", "ws" or "xhttp"');
  process.exit(1);
}
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(UUID)) {
  console.error("Fatal: UUID is not a valid UUID");
  process.exit(1);
}
const UUID_BUF = Buffer.from(UUID.replace(/-/g, ""), "hex");

const log = (...a) => console.log(new Date().toISOString(), ...a);
const pad = () => "X".repeat(100 + Math.floor(Math.random() * 900));

// ---------------- never let the tunnel reach private/internal addresses ----------------
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === "::" || l === "::1") return true;
    if (l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80")) return true;
    if (l.startsWith("::ffff:")) {
      const rest = l.slice(7);
      return net.isIPv4(rest) ? isPrivate(rest) : true;
    }
  }
  return false;
}

function safeLookup(hostname, options, cb) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return cb(err);
    if (Array.isArray(address)) {
      const ok = address.filter((a) => !isPrivate(a.address));
      return ok.length ? cb(null, ok) : cb(new Error("blocked address"));
    }
    return isPrivate(address) ? cb(new Error("blocked address")) : cb(null, address, family);
  });
}

// ---------------- VLESS request header ----------------
const NEED = Symbol("need-more-bytes");

function parseVless(b) {
  if (b.length < 18) return NEED;
  if (b[0] !== 0) return null;
  if (!crypto.timingSafeEqual(b.subarray(1, 17), UUID_BUF)) return null;
  let o = 18 + b[17]; // skip addons
  if (b.length < o + 4) return NEED;
  if (b[o++] !== 1) return null; // TCP only
  const port = b.readUInt16BE(o);
  o += 2;
  const atype = b[o++];
  let host;
  if (atype === 1) {
    if (b.length < o + 4) return NEED;
    host = `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
    o += 4;
  } else if (atype === 2) {
    if (b.length < o + 1) return NEED;
    const l = b[o++];
    if (!l) return null;
    if (b.length < o + l) return NEED;
    host = b.toString("utf8", o, o + l);
    o += l;
  } else if (atype === 3) {
    if (b.length < o + 16) return NEED;
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(b.readUInt16BE(o + 2 * i).toString(16));
    host = parts.join(":");
    o += 16;
  } else {
    return null;
  }
  return { ver: b[0], host, port, payload: b.subarray(o) };
}

// ---------------- transport-independent tunnel ----------------
// down = { write(buf) -> bool (false = backpressure), end() }
function createTunnel(down) {
  let acc = Buffer.alloc(0);
  let remote = null;
  let sentHeader = false;
  let dead = false;

  function open(v) {
    if (!ALLOW_PRIVATE && isPrivate(v.host)) return t.destroy();
    remote = net.connect({
      host: v.host,
      port: v.port,
      lookup: ALLOW_PRIVATE ? undefined : safeLookup,
    });
    remote.setNoDelay(true);
    remote.setTimeout(300000, () => remote.destroy());
    const respHeader = Buffer.from([v.ver, 0]);
    remote.on("data", (d) => {
      let out = d;
      if (!sentHeader) {
        out = Buffer.concat([respHeader, d]);
        sentHeader = true;
      }
      if (!down.write(out)) remote.pause();
    });
    remote.on("drain", () => { if (t.onDrain) t.onDrain(); });
    remote.on("error", () => {});
    remote.on("close", () => t.destroy());
    if (v.payload.length) remote.write(v.payload);
  }

  const t = {
    onDrain: null, // set by the transport: resume the uplink source
    // returns false when the uplink source should pause
    feed(chunk) {
      if (dead) return true;
      if (remote) return remote.write(chunk);
      acc = acc.length ? Buffer.concat([acc, chunk]) : chunk;
      const v = parseVless(acc);
      if (v === NEED) {
        if (acc.length > 8192) t.destroy();
        return true;
      }
      if (!v) {
        t.destroy();
        return true;
      }
      acc = Buffer.alloc(0);
      open(v);
      return true;
    },
    resumeDown() { if (remote) remote.resume(); },
    destroy() {
      if (dead) return;
      dead = true;
      if (remote) remote.destroy();
      down.end();
    },
  };
  return t;
}

// ---------------- WebSocket transport ----------------
function wsFrame(payload) {
  const len = payload.length;
  let h;
  if (len < 126) {
    h = Buffer.from([0x82, len]);
  } else if (len < 65536) {
    h = Buffer.alloc(4);
    h[0] = 0x82;
    h[1] = 126;
    h.writeUInt16BE(len, 2);
  } else {
    h = Buffer.alloc(10);
    h[0] = 0x82;
    h[1] = 127;
    h.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([h, payload]);
}

function handleWs(socket, head, early) {
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 30000);
  socket.setTimeout(0);

  let buf = Buffer.alloc(0);
  let frags = [];
  let fragSize = 0;
  let closed = false;

  const tunnel = createTunnel({
    write: (b) => socket.write(wsFrame(b)),
    end: () => closeWs(),
  });
  tunnel.onDrain = () => socket.resume();

  const ping = setInterval(() => {
    if (!closed && !socket.destroyed) socket.write(Buffer.from([0x89, 0x00]));
  }, 25000);

  function cleanup() {
    if (closed) return;
    closed = true;
    clearInterval(ping);
    tunnel.destroy();
  }
  function closeWs() {
    if (!socket.destroyed) {
      try { socket.end(Buffer.from([0x88, 0x00])); } catch {}
    }
    cleanup();
  }

  socket.on("close", cleanup);
  socket.on("error", cleanup);
  socket.on("drain", () => tunnel.resumeDown());

  function onMessage(msg) {
    if (!tunnel.feed(msg)) socket.pause();
  }

  function handleFrame(fin, op, payload) {
    if (op === 8) return closeWs();
    if (op === 9) {
      socket.write(Buffer.concat([Buffer.from([0x8a, payload.length]), payload]));
      return;
    }
    if (op === 10) return;
    if (op === 1 || op === 2) {
      frags = [payload];
      fragSize = payload.length;
    } else if (op === 0) {
      fragSize += payload.length;
      if (fragSize > MAX_FRAME) return closeWs();
      frags.push(payload);
    } else {
      return;
    }
    if (fin) {
      const msg = frags.length === 1 ? frags[0] : Buffer.concat(frags);
      frags = [];
      fragSize = 0;
      onMessage(msg);
    }
  }

  function onData(chunk) {
    if (closed) return;
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    for (;;) {
      if (closed || buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const op = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        const big = buf.readBigUInt64BE(2);
        if (big > BigInt(MAX_FRAME)) return closeWs();
        len = Number(big);
        off = 10;
      }
      if (len > MAX_FRAME) return closeWs();
      const hdr = off + (masked ? 4 : 0);
      if (buf.length < hdr + len) return;
      let payload = buf.subarray(hdr, hdr + len);
      if (masked) {
        const m = buf.subarray(off, off + 4);
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i++) payload[i] ^= m[i & 3];
      }
      buf = buf.subarray(hdr + len);
      handleFrame(fin, op, payload);
    }
  }

  socket.on("data", onData);
  if (early && early.length) onMessage(early);
  if (head && head.length) onData(head);
}

// ---------------- XHTTP transport ----------------
const sessions = new Map();

function dropSession(s) {
  clearTimeout(s.timer);
  if (sessions.get(s.id) === s) sessions.delete(s.id);
}

function getSession(sid) {
  let s = sessions.get(sid);
  if (s) return s;
  if (sessions.size >= 500) return null;
  s = { id: sid, res: null, pending: [], pendingSize: 0, queue: new Map(), next: 0, timer: null, tunnel: null };
  const down = {
    write(b) {
      if (s.res) return s.res.write(b);
      s.pending.push(b);
      s.pendingSize += b.length;
      if (s.pendingSize > MAX_PENDING) s.tunnel.destroy();
      return true;
    },
    end() {
      dropSession(s);
      if (s.res && !s.res.writableEnded) s.res.end();
    },
  };
  s.tunnel = createTunnel(down);
  s.timer = setTimeout(() => { if (!s.res) s.tunnel.destroy(); }, 30000);
  sessions.set(sid, s);
  return s;
}

function sseHeaders() {
  return {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-store",
    "X-Accel-Buffering": "no",
    "X-Padding": pad(),
  };
}

function deliver(s, seq, buf) {
  if (seq < s.next || s.queue.has(seq)) return;
  s.queue.set(seq, buf);
  if (s.queue.size > 100) return s.tunnel.destroy();
  while (s.queue.has(s.next)) {
    const b = s.queue.get(s.next);
    s.queue.delete(s.next);
    s.next++;
    if (b.length) s.tunnel.feed(b);
  }
}

// GET /path/<sid>  -> downlink (response body = raw bytes from the target)
function xhttpDownlink(req, res, sid) {
  const s = getSession(sid);
  if (!s || s.res) { res.writeHead(404); return res.end(); }
  res.writeHead(200, sseHeaders());
  res.flushHeaders();
  req.socket.setNoDelay(true);
  s.res = res;
  clearTimeout(s.timer);
  for (const b of s.pending) res.write(b);
  s.pending = [];
  s.pendingSize = 0;
  res.on("drain", () => s.tunnel.resumeDown());
  res.on("close", () => s.tunnel.destroy());
}

// POST /path/<sid>/<seq>  -> one uplink packet (packet-up)
function xhttpPacket(req, res, sid, seq) {
  const s = getSession(sid);
  if (!s) { res.writeHead(503); return res.end(); }
  const chunks = [];
  let size = 0;
  req.on("data", (c) => {
    size += c.length;
    if (size > MAX_FRAME) {
      res.writeHead(413);
      res.end();
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on("end", () => {
    res.writeHead(200, { "Cache-Control": "no-store", "X-Padding": pad() });
    res.end();
    deliver(s, seq, Buffer.concat(chunks));
  });
  req.on("error", () => {});
}

// POST /path/<sid>  -> streaming uplink (stream-up); downlink comes from the GET
function xhttpStreamUp(req, res, sid) {
  const s = getSession(sid);
  if (!s) { res.writeHead(503); return res.end(); }
  res.writeHead(200, sseHeaders());
  res.flushHeaders();
  s.tunnel.onDrain = () => req.resume();
  req.on("data", (c) => { if (!s.tunnel.feed(c)) req.pause(); });
  req.on("end", () => res.end());
  req.on("error", () => s.tunnel.destroy());
  req.on("close", () => { if (!req.complete) s.tunnel.destroy(); });
}

// POST /path  -> one request carries both directions (stream-one)
function xhttpStreamOne(req, res) {
  res.writeHead(200, sseHeaders());
  res.flushHeaders();
  req.socket.setNoDelay(true);
  const t = createTunnel({
    write: (b) => res.write(b),
    end: () => { if (!res.writableEnded) res.end(); },
  });
  t.onDrain = () => req.resume();
  res.on("drain", () => t.resumeDown());
  res.on("close", () => t.destroy());
  req.on("data", (c) => { if (!t.feed(c)) req.pause(); });
  req.on("error", () => t.destroy());
}

// returns true when the request was an XHTTP request (handled)
function handleXhttp(req, res, urlPath) {
  if (urlPath !== XHTTP_PATH && !urlPath.startsWith(XHTTP_PATH + "/")) return false;
  const parts = urlPath.slice(XHTTP_PATH.length).split("/").filter(Boolean);
  const method = req.method;
  if (method === "GET" && parts.length === 1) { xhttpDownlink(req, res, parts[0]); return true; }
  if (method === "POST" && parts.length === 2 && /^\d+$/.test(parts[1])) {
    xhttpPacket(req, res, parts[0], parseInt(parts[1], 10));
    return true;
  }
  if (method === "POST" && parts.length === 1) { xhttpStreamUp(req, res, parts[0]); return true; }
  if (method === "POST" && parts.length === 0) { xhttpStreamOne(req, res); return true; }
  res.writeHead(404);
  res.end();
  return true;
}

// ---------------- domain detection + links ----------------
const known = new Set();

function makeLink(kind, host, port, tls) {
  const q = new URLSearchParams({
    encryption: "none",
    type: kind,
    host,
    path: kind === "ws" ? WS_PATH : XHTTP_PATH,
  });
  if (kind === "xhttp") q.set("mode", XHTTP_MODE);
  q.set("security", tls ? "tls" : "none");
  if (tls) {
    q.set("sni", host);
    q.set("fp", "chrome");
    if (kind === "ws") q.set("alpn", "http/1.1");
  }
  const name = encodeURIComponent(LINK_NAME + "-" + kind.toUpperCase());
  return `vless://${UUID}@${host}:${port}?${q.toString()}#${name}`;
}

function linksFor(hostHeader, proto) {
  let host = hostHeader;
  let port = "";
  const m = hostHeader.match(/^(.*):(\d+)$/);
  if (m) { host = m[1]; port = m[2]; }
  let tls = proto ? proto === "https" : true;
  if (FORCE_TLS === "0") tls = false;
  if (FORCE_TLS === "1") tls = true;
  port = FORCE_PORT || port || (tls ? "443" : "80");
  const out = [];
  if (WANT_XHTTP) out.push(makeLink("xhttp", host, port, tls));
  if (WANT_WS) out.push(makeLink("ws", host, port, tls));
  return out;
}

function requestHost(req) {
  const h = String(req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim().toLowerCase();
  const proto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  return { host: h, proto };
}

function plausiblePublicHost(h) {
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d+)?$/.test(h)) return false;
  const bare = h.replace(/:\d+$/, "");
  return bare.includes(".") && bare !== "localhost" && !isPrivate(bare);
}

function announce(host, proto, why) {
  const key = host + "|" + proto;
  if (known.has(key)) return;
  known.add(key);
  log(`Domain ${host} (${why}). Client link(s):`);
  for (const l of linksFor(host, proto)) console.log(l);
}

function learnHost(req) {
  const { host, proto } = requestHost(req);
  if (host && plausiblePublicHost(host)) announce(host, proto, "seen in a request");
}

function envHosts() {
  const e = process.env;
  const list = [
    e.PUBLIC_HOST,
    e.RENDER_EXTERNAL_HOSTNAME,
    e.RAILWAY_PUBLIC_DOMAIN,
    e.KOYEB_PUBLIC_DOMAIN,
    e.SPACE_HOST,
    e.FLY_APP_NAME ? e.FLY_APP_NAME + ".fly.dev" : "",
  ];
  return list.filter(Boolean).map((h) => h.replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase());
}

// ---------------- HTTP server ----------------
const server = http.createServer((req, res) => {
  learnHost(req);
  const urlPath = (req.url || "/").split("?")[0];

  if (WANT_XHTTP && handleXhttp(req, res, urlPath)) return;

  // private page: your links for the domain you are visiting from
  if (req.method === "GET" && urlPath === "/link/" + UUID) {
    const { host, proto } = requestHost(req);
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    res.end(linksFor(host, proto).join("\n") + "\n");
    return;
  }

  res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
  res.end("OK");
});

server.requestTimeout = 0;      // stream-up / stream-one requests can stay open for hours
server.keepAliveTimeout = 65000;

server.on("upgrade", (req, socket, head) => {
  socket.on("error", () => {});
  learnHost(req);
  const urlPath = (req.url || "").split("?")[0];
  const key = req.headers["sec-websocket-key"];
  const isWs = String(req.headers.upgrade || "").toLowerCase() === "websocket";
  if (!WANT_WS || urlPath !== WS_PATH || !key || !isWs) {
    socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    return;
  }
  const accept = crypto.createHash("sha1").update(key + WS_GUID).digest("base64");
  let resp =
    "HTTP/1.1 101 Switching Protocols\r\n" +
    "Upgrade: websocket\r\n" +
    "Connection: Upgrade\r\n" +
    "Sec-WebSocket-Accept: " + accept + "\r\n";

  // Some clients send early data in the Sec-WebSocket-Protocol header (path ...?ed=2048).
  let early = null;
  const proto = req.headers["sec-websocket-protocol"];
  if (proto) {
    const first = proto.split(",")[0].trim();
    try {
      early = Buffer.from(first.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    } catch {}
    resp += "Sec-WebSocket-Protocol: " + first + "\r\n";
  }
  socket.write(resp + "\r\n");
  handleWs(socket, head, early);
});

process.on("uncaughtException", (e) => console.error("uncaught:", e && e.message));
process.on("unhandledRejection", (e) => console.error("unhandled:", e && e.message));

server.listen(PORT, "0.0.0.0", () => {
  log(`Listening on 0.0.0.0:${PORT} (plain HTTP). Transports: ${[WANT_XHTTP && "XHTTP(" + XHTTP_PATH + ")", WANT_WS && "WS(" + WS_PATH + ")"].filter(Boolean).join(" + ")}`);
  const hosts = envHosts();
  for (const h of hosts) announce(h, "", "from environment");
  if (!hosts.length) {
    log("Domain not known yet. Open your app's address once in a browser (https://YOUR-DOMAIN/) and the links will be printed here,");
    log(`or open  https://YOUR-DOMAIN/link/${UUID}  to see them in the browser.`);
  }
});
