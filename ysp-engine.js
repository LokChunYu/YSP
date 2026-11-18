#!/usr/bin/env node
/*
 * ysp-engine.js —— ysp-live Python 版的 Web 伴生引擎（Node 桥接层）
 *
 * 作用：把 nanoTV 插件 ysp-service_2.0.16.js 直接跑在 Node.js 里，
 *       对外提供  GET /live/<频道>.m3u8  ，供 ysp-live-v9.8.py 在自身解析
 *       失败时兜底取流（py 启动时会自动发现并拉起本脚本，端口默认 8787）。
 *
 * 也就是「让 py 用上 js 上面的东西」：BK(cKey)/JCE/Device 三套解析逻辑
 * 全部复用 JS 原版实现，本文件只做宿主环境(shim) + HTTP 输出。
 *
 * 依赖：仅 Node.js 内置模块（建议 Node 16+）。
 * 用法：node ysp-engine.js [端口]        # 默认 8787
 *       与 ysp-service_2.0.16.js 放同一目录（或用 YSP_SERVICE_JS 指定路径）。
 *
 * 调试接口：
 *   GET /health                     引擎状态
 *   GET /channels                   频道表
 *   GET /live/<id>.m3u8[?source=bk|jce|device|auto][&rate=xxx]
 */
"use strict";

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const zlib = require("zlib");
const crypto = require("crypto");
const { URL } = require("url");

// ---------------- 配置 ----------------
const PORT = parseInt(process.argv[2] || process.env.YSP_ENGINE_PORT || "8787", 10);
const SERVICE_JS = process.env.YSP_SERVICE_JS || path.join(__dirname, "ysp-service_2.0.16.js");
const STORAGE_FILE = process.env.YSP_ENGINE_STORAGE || path.join(__dirname, "ysp-engine-storage.json");

function log(...args) {
    console.log("[" + new Date().toISOString().slice(11, 19) + "]", "[engine]", ...args);
}

// ---------------- 持久化存储（identity / jce-guid） ----------------
let storageData = {};
try {
    storageData = JSON.parse(fs.readFileSync(STORAGE_FILE, "utf8"));
} catch (_) {
    storageData = {};
}
let storageTimer = null;
function persistStorage() {
    if (storageTimer) return;
    storageTimer = setTimeout(() => {
        storageTimer = null;
        try {
            fs.writeFileSync(STORAGE_FILE, JSON.stringify(storageData, null, 2));
        } catch (e) {
            log("storage write failed:", e.message);
        }
    }, 200);
}
const storage = {
    get: (key) => (key in storageData ? storageData[key] : null),
    set: (key, value) => {
        storageData[key] = value;
        persistStorage();
    },
};

// ---------------- bytes / crypto shim ----------------
function bytesConvert(value, from, to) {
    let buf;
    const s = String(value == null ? "" : value);
    if (from === "utf8") buf = Buffer.from(s, "utf8");
    else if (from === "hex") buf = Buffer.from(s.replace(/\s+/g, ""), "hex");
    else if (from === "base64") buf = Buffer.from(s, "base64");
    else throw new Error("bytes.convert: unsupported from=" + from);
    if (to === "utf8") return buf.toString("utf8");
    if (to === "hex") return buf.toString("hex");
    if (to === "base64") return buf.toString("base64");
    throw new Error("bytes.convert: unsupported to=" + to);
}

function digest(algo, text) {
    return crypto.createHash(algo).update(String(text), "utf8").digest("hex");
}

// AES-256-GCM：key/data 均为 base64；载荷 = nonce(12) + 密文 + tag(16)，整体 base64
function seal({ key, data }) {
    const keyBuf = Buffer.from(key, "base64");
    const plain = Buffer.from(data, "base64");
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf, nonce);
    const ct = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
    return Buffer.concat([nonce, ct]).toString("base64");
}
function open({ key, data }) {
    const keyBuf = Buffer.from(key, "base64");
    const raw = Buffer.from(data, "base64");
    if (raw.length <= 12 + 16) throw new Error("AES-GCM payload too short");
    const nonce = raw.slice(0, 12);
    const tag = raw.slice(raw.length - 16);
    const ct = raw.slice(12, raw.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("base64");
}

// RSA-OAEP-SHA256：publicKey 为 base64 SPKI(2048)，data 为 base64，返回 base64；超长自动分块
function rsaEncrypt({ publicKey, data }) {
    const der = Buffer.from(publicKey, "base64");
    const keyObj = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
    const plain = Buffer.from(data, "base64");
    const k = 2048 / 8;
    const chunkSize = k - 2 * 32 - 2;
    const out = [];
    for (let i = 0; i < plain.length; i += chunkSize) {
        out.push(
            crypto.publicEncrypt(
                { key: keyObj, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
                plain.slice(i, i + chunkSize),
            ),
        );
    }
    return Buffer.concat(out).toString("base64");
}

// gzip/gunzip：base64 进、base64 出（JCE QMF 报文用）
function gzipB64(s) {
    return zlib.gzipSync(Buffer.from(s, "base64")).toString("base64");
}
function gunzipB64(s) {
    return zlib.gunzipSync(Buffer.from(s, "base64")).toString("base64");
}

// ---------------- 网络 shim（native.http / host.http.request 共用底层） ----------------
function rawRequest({ url, method = "GET", headers = {}, body, bodyEncoding, responseEncoding, timeoutSeconds = 15 }) {
    return new Promise((resolve, reject) => {
        let target;
        try {
            target = new URL(url);
        } catch (e) {
            reject(new Error("invalid url"));
            return;
        }
        const mod = target.protocol === "https:" ? https : http;
        const reqHeaders = Object.assign({}, headers);
        const redirs = reqHeaders.__redirs || 0;
        delete reqHeaders.__redirs; // 仅内部使用，不发给上游
        let payload = null;
        if (body !== undefined && body !== null) {
            payload = bodyEncoding === "base64" ? Buffer.from(String(body), "base64") : Buffer.from(String(body), "utf8");
            if (!reqHeaders["Content-Length"] && !reqHeaders["content-length"]) {
                reqHeaders["Content-Length"] = String(payload.length);
            }
        }
        const req = mod.request(
            {
                protocol: target.protocol,
                hostname: target.hostname,
                port: target.port || (target.protocol === "https:" ? 443 : 80),
                path: target.pathname + target.search,
                method,
                headers: reqHeaders,
                timeout: Math.max(1, timeoutSeconds) * 1000,
            },
            (res) => {
                // 跟随重定向（最多 5 次）
                if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirs < 5) {
                    res.resume();
                    const next = new URL(res.headers.location, target).href;
                    const nextHeaders = Object.assign({}, headers, { __redirs: redirs + 1 });
                    rawRequest({ url: next, method, headers: nextHeaders, body, bodyEncoding, responseEncoding, timeoutSeconds })
                        .then(resolve, reject);
                    return;
                }
                const chunks = [];
                res.on("data", (c) => chunks.push(c));
                res.on("end", () => {
                    let buf = Buffer.concat(chunks);
                    const enc = String(res.headers["content-encoding"] || "").toLowerCase();
                    if (enc.includes("gzip")) {
                        try {
                            buf = zlib.gunzipSync(buf);
                        } catch (_) {}
                    } else if (enc.includes("deflate")) {
                        try {
                            buf = zlib.inflateSync(buf);
                        } catch (_) {}
                    }
                    const bodyOut = responseEncoding === "base64" ? buf.toString("base64") : buf.toString("utf8");
                    resolve({
                        ok: true,
                        status: res.statusCode,
                        reason: res.statusMessage || "",
                        headers: res.headers,
                        body: bodyOut,
                        url: res.responseUrl || target.href,
                    });
                });
                res.on("error", reject);
            },
        );
        req.on("timeout", () => req.destroy(new Error("operation timed out")));
        req.on("error", reject);
        if (payload) req.write(payload);
        req.end();
    });
}

// native.http(requestJSON, callback)：请求/响应均为 JSON 字符串
function nativeHttp(requestJSON, callback) {
    let request;
    try {
        request = JSON.parse(requestJSON);
    } catch (_) {
        callback(JSON.stringify({ ok: false, error: "invalid request json" }));
        return;
    }
    rawRequest(request).then(
        (resp) => callback(JSON.stringify(resp)),
        (err) => callback(JSON.stringify({ ok: false, error: String((err && err.message) || err) })),
    );
}

// ---------------- scheduler / media ----------------
const schedulerTimers = [];
const scheduler = {
    sleep: (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms))),
    every: (id, ms, fn) => {
        const t = setInterval(() => {
            try {
                Promise.resolve()
                    .then(fn)
                    .catch((e) => log("scheduler task " + id + " error: " + ((e && e.message) || e)));
            } catch (e) {
                log("scheduler task " + id + " error: " + ((e && e.message) || e));
            }
        }, Math.max(1000, ms));
        if (t.unref) t.unref();
        schedulerTimers.push(t);
        return id;
    },
};

const media = {
    openHLS: (options) => ({
        sessionID: "engine-" + Math.random().toString(36).slice(2, 10),
        url: "http://127.0.0.1:" + PORT + "/session/unused",
        manifestURL: options && options.manifestURL,
    }),
};

// ---------------- 组装宿主并载入 JS 服务 ----------------
if (!fs.existsSync(SERVICE_JS)) {
    console.error("[engine] 找不到服务脚本:", SERVICE_JS);
    process.exit(1);
}
globalThis.native = {
    http: nativeHttp,
    randomHex: (count) => crypto.randomBytes(count).toString("hex"),
    log: (...a) => log(...a),
};

require(SERVICE_JS); // 该脚本会设置 globalThis.nanoService
const service = globalThis.nanoService;
if (!service || typeof service.resolve !== "function") {
    console.error("[engine] ysp-service 未注册 nanoService");
    process.exit(1);
}

const host = {
    now: () => Date.now(),
    log: (...a) => log(...a),
    randomHex: (count) => crypto.randomBytes(count).toString("hex"),
    http: { request: (req) => rawRequest(req) },
    scheduler,
    storage,
    bytes: { convert: bytesConvert },
    crypto: { digest, seal, open, rsaEncrypt, gzip: gzipB64, gunzip: gunzipB64 },
    media,
};
service.start(host);
const modules = service.testing.modules;
log("ysp-service 已载入，版本", (service.manifest && service.manifest.version) || "?");

// ---------------- 解析：镜像 JS resolveSource 的 auto 顺序 ----------------
// 设备签名分片需要专用请求头 → 用 /segment 代理出口；JCE/BK 分片直连 CDN 即可
const segmentHeaderStore = new Map();
let segTokenSeq = 0;

function rememberSegmentHeaders(headers) {
    const token = "s" + (++segTokenSeq) + "-" + crypto.randomBytes(4).toString("hex");
    segmentHeaderStore.set(token, headers);
    if (segmentHeaderStore.size > 64) {
        const first = segmentHeaderStore.keys().next().value;
        segmentHeaderStore.delete(first);
    }
    return token;
}

async function resolveManifest(id, source, rate) {
    const ch = modules.channels.find(id);
    if (!ch) {
        const err = new Error("未知频道: " + id);
        err.status = 404;
        throw err;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const notes = [];
    const jceOnce = async () => modules.jce.resolve(ch, nowSec - 300, nowSec);
    const bkOnce = async () => {
        const r = await modules.bk.resolve(ch);
        if (!r || !r.ok || !r.url) throw new Error((r && r.error) || "BK 无可用地址");
        return r;
    };
    const deviceOnce = () => modules.device.resolve(ch, rate || "36p");
    const jceThenBk = async () => {
        if (modules.channels.catchup.has(ch.id)) {
            try {
                return await jceOnce();
            } catch (e) {
                notes.push("jce: " + ((e && e.message) || e));
            }
        }
        return bkOnce();
    };

    let result;
    if (source === "bk") result = await bkOnce();
    else if (source === "jce") result = await jceOnce();
    else if (source === "device") result = await deviceOnce();
    else if (modules.device.liveIDs[ch.id] && !modules.channels.forceBK.has(ch.id)) {
        try {
            result = await deviceOnce();
        } catch (e) {
            notes.push("device: " + ((e && e.message) || e));
            result = await jceThenBk();
        }
    } else {
        result = await jceThenBk();
    }
    return { channel: ch, result, notes };
}

// 拉取上游清单并把相对地址补全为绝对地址；主清单自动选最高码率变体
async function fetchAbsolutePlaylist(url, headers, depth) {
    const resp = await rawRequest({
        url,
        method: "GET",
        headers: Object.assign({ "User-Agent": "Mozilla/5.0", Referer: "https://live.cctv.cn/" }, headers || {}),
        timeoutSeconds: 15,
    });
    if (resp.status < 200 || resp.status >= 300) throw new Error("清单 HTTP " + resp.status);
    const base = resp.url || url;
    const lines = resp.body.split(/\r?\n/).filter((l) => l.trim() !== "");
    if (lines.some((l) => l.startsWith("#EXT-X-STREAM-INF")) && depth < 2) {
        let best = null;
        let bestBand = -1;
        for (let i = 0; i < lines.length; i++) {
            if (!lines[i].startsWith("#EXT-X-STREAM-INF")) continue;
            const m = /BANDWIDTH=(\d+)/.exec(lines[i]);
            const band = m ? parseInt(m[1], 10) : 0;
            let j = i + 1;
            while (j < lines.length && lines[j].startsWith("#")) j++;
            if (j < lines.length && band >= bestBand) {
                bestBand = band;
                best = lines[j];
            }
        }
        if (best) return fetchAbsolutePlaylist(new URL(best.trim(), base).href, headers, depth + 1);
    }
    const out = lines.map((l) => (l.startsWith("#") ? l : new URL(l.trim(), base).href));
    return out.join("\n") + "\n";
}

// ---------------- HTTP 服务 ----------------
const server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://127.0.0.1");
    const p = u.pathname;
    const send = (code, text, type) => {
        res.writeHead(code, { "Content-Type": type || "text/plain; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(text);
    };

    if (p === "/health") {
        send(200, JSON.stringify({ ok: true, service: (service.manifest && service.manifest.id) || "ysp-live", port: PORT }, null, 2), "application/json");
        return;
    }
    if (p === "/channels") {
        send(200, JSON.stringify(service.channels(), null, 2), "application/json");
        return;
    }
    if (p.startsWith("/segment")) {
        const target = u.searchParams.get("url") || "";
        const token = u.searchParams.get("t") || "";
        let safe = false;
        try {
            const host = new URL(target).hostname;
            const suffixes = [".cctv.cn", ".cctv.com", ".cctvpic.com", ".citvc.com", ".yangshipin.cn", ".cntv.cn", ".cntv.com", ".myqcloud.com", ".qqlive.com", ".gtimg.cn", ".smtcdns.net", ".smtcdns.com", ".tcdnlive.com", ".alicdn.com", ".alikunlun.com", ".wscdns.com", ".chinanetcenter.com", ".bdydns.com", ".ksyungslb.com", ".ks-cdn.com"];
            safe = /^https?:$/.test(new URL(target).protocol) && suffixes.some((s) => host === s.slice(1) || host.endsWith(s));
        } catch (_) {}
        if (!safe) return send(403, "forbidden url\n");
        const headers = segmentHeaderStore.get(token) || { "User-Agent": "Mozilla/5.0" };
        rawRequest({ url: target, method: "GET", headers, responseEncoding: "base64", timeoutSeconds: 15 }).then(
            (r) => {
                res.writeHead(r.status, { "Content-Type": (r.headers && r.headers["content-type"]) || "video/mp2t" });
                res.end(Buffer.from(r.body, "base64"));
            },
            (e) => send(502, "segment error: " + e.message + "\n"),
        );
        return;
    }

    let m = /^\/live\/([\w-]+)\.m3u8$/.exec(p) || /^\/([\w-]+)\.m3u8$/.exec(p);
    if (m) {
        const source = u.searchParams.get("source") || "auto";
        const rate = u.searchParams.get("rate") || "";
        resolveManifest(m[1], source, rate).then(
            async ({ channel, result, notes }) => {
                try {
                    let pl = await fetchAbsolutePlaylist(result.url, result.headers, 0);
                    if (result.source === "device") {
                        // 设备签名分片必须带专有请求头 → 改走 /segment 代理出口
                        const token = rememberSegmentHeaders(result.headers);
                        pl = pl
                            .split(/\r?\n/)
                            .map((l) =>
                                l.startsWith("#") || !l.trim()
                                    ? l
                                    : "http://127.0.0.1:" + PORT + "/segment?t=" + token + "&url=" + encodeURIComponent(l.trim()),
                            )
                            .join("\n");
                    }
                    log("resolve ok:", channel.id, "source=" + result.source, notes.length ? "(fallback: " + notes.join("; ") + ")" : "");
                    send(200, pl, "application/vnd.apple.mpegurl");
                } catch (e) {
                    log("清单拉取失败:", channel.id, e.message);
                    send(502, "playlist fetch failed: " + e.message + "\n");
                }
            },
            (e) => {
                log("解析失败:", m[1], (e && e.message) || e);
                send(502, "resolve failed: " + ((e && e.message) || e) + "\n");
            },
        );
        return;
    }
    send(404, "not found\n");
});

server.listen(PORT, "127.0.0.1", () => {
    log("ysp-engine 已启动: http://127.0.0.1:" + PORT + "/live/<频道>.m3u8");
});
