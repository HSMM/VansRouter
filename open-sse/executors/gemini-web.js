/**
 * gemini-web executor — talks to gemini.google.com with the user's own browser
 * session cookies over the WebChannel transport the Gemini 4 web app uses
 * (geminiweb-pa.clients6.google.com/v1/processSession, protobuf payloads).
 *
 * One request = one WebChannel session:
 *   1. GET gemini.google.com/app → WIZ_global_data (server token, api key, UI build id)
 *   2. POST handshake (count=0) → SID + x-http-session-id
 *   3. GET long-poll stream (TYPE=xmlhttp) — frames are `<len>\n[[aid,[base64 protobuf]]]`
 *   4. POST setup (field 1) + prompt (field 2) in one form
 *   5. read frames until the candidate carries the final flag, then
 *      POST end-of-turn (field 4) and TYPE=terminate.
 *
 * Models that need Google's browser attestation token (Gemini 4 Argon) are not
 * offered: the token is produced by client-side JS in a real browser and this
 * executor does not try to reproduce it.
 */
import { createHash } from "node:crypto";
import { BaseExecutor } from "./base.js";
import { PROVIDERS } from "../config/providers.js";
import { SSE_DONE, SSE_HEADERS_NO_BUFFER } from "../utils/sseConstants.js";
import { sseChunk } from "../utils/sse.js";
import { encodeMessage, decodeMessage, pick, pickText, pickNumber, toBase64, fromBase64 } from "../utils/geminiWebProtobuf.js";

const PROVIDER_ID = "gemini-web";
const GEMINI_ORIGIN = "https://gemini.google.com";
const GEMINI_APP_URL = `${GEMINI_ORIGIN}/app`;
const DEFAULT_CHANNEL_BASE = "https://geminiweb-pa.clients6.google.com";
const USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
const WIZ_TTL_MS = 5 * 60 * 1000;
const FIRST_FRAME_TIMEOUT_MS = 60_000;
const IDLE_AFTER_TEXT_MS = 20_000;
const IDLE_AFTER_FINAL_FLAG_MS = 5_000;
const REQUIRED_COOKIES = ["SAPISID", "__Secure-1PSID"];

// Thinking levels as the web UI encodes them (header field 16 / setup field 81).
export const THINKING_LEVEL = { low: 1, medium: 4, high: 2 };

// Model tickets observed in the Gemini web UI model picker (x-goog-ext-525001261-bin field 5)
// and MODE_CATEGORY (field 15 / setup field 80): 1 FAST, 3 PRO, 6 FLASH_LITE, 8 ULTRA.
export const MODEL_MAP = {
  "gemini-flash-lite": { ticket: "8c46e95b1a07cecc", mode: 6, think: THINKING_LEVEL.low, isThinking: false },
  "gemini-3.8-flash": { ticket: "56fdd199312815e2", mode: 1, think: THINKING_LEVEL.low, isThinking: false },
  "gemini-3.1-pro": { ticket: "e6fa609c3fa255c0", mode: 3, think: THINKING_LEVEL.medium, isThinking: true },
  "gemini-3.1-pro-low": { ticket: "e6fa609c3fa255c0", mode: 3, think: THINKING_LEVEL.low, isThinking: true },
  "gemini-3.1-pro-medium": { ticket: "e6fa609c3fa255c0", mode: 3, think: THINKING_LEVEL.medium, isThinking: true },
  "gemini-3.1-pro-high": { ticket: "e6fa609c3fa255c0", mode: 3, think: THINKING_LEVEL.high, isThinking: true },
};
const DEFAULT_MODEL = "gemini-3.8-flash";

// ---------------------------------------------------------------- cookies / auth

/** Accept "k=v; k=v" or {"cookie": "..."} and return an ordered map of cookie pairs. */
export function parseCookieString(raw) {
  if (!raw) return new Map();
  let s = String(raw).trim();
  if (s.startsWith("{")) {
    try { s = String(JSON.parse(s).cookie || ""); } catch { /* keep raw */ }
  }
  const jar = new Map();
  for (const part of s.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) jar.set(k, v);
  }
  return jar;
}

export function missingCookies(jar) {
  return REQUIRED_COOKIES.filter((k) => !jar.get(k));
}

export function cookieHeader(jar) {
  return Array.from(jar, ([k, v]) => `${k}=${v}`).join("; ");
}

/** SAPISIDHASH as the Gemini web client sends it (all three variants carry the same digest). */
export function sapisidHash(sapisid, origin = GEMINI_ORIGIN, now = Date.now()) {
  const ts = Math.floor(now / 1000);
  const digest = createHash("sha1").update(`${ts} ${sapisid} ${origin}`).digest("hex");
  return `SAPISIDHASH ${ts}_${digest} SAPISID1PHASH ${ts}_${digest} SAPISID3PHASH ${ts}_${digest}`;
}

// ---------------------------------------------------------------- page bootstrap

const wizCache = new Map();

// gemini.google.com answers the app page with far more header bytes than
// undici's 16 KB default allows (UND_ERR_HEADERS_OVERFLOW), so the page fetch
// goes through a dispatcher with a larger limit. Everything else uses the
// global fetch so proxy pools keep working.
const PAGE_MAX_HEADER_SIZE = 1024 * 1024;
let pageDispatcherPromise = null;
async function pageFetchOptions() {
  if (!pageDispatcherPromise) {
    pageDispatcherPromise = import("undici")
      .then(({ Agent }) => ({ dispatcher: new Agent({ maxHeaderSize: PAGE_MAX_HEADER_SIZE }) }))
      .catch(() => ({}));
  }
  return pageDispatcherPromise;
}

export function parseWizGlobalData(html) {
  const m = html.match(/WIZ_global_data\s*=\s*(\{.*?\});/s);
  if (!m) return null;
  let wiz;
  try { wiz = JSON.parse(m[1]); } catch { return null; }
  return {
    serverToken: wiz.PI9WOb || null,
    apiKey: wiz.d2zJAe || null,
    buildId: wiz.cfb2h || null,
    channelBase: wiz.GK6dn || DEFAULT_CHANNEL_BASE,
  };
}

async function fetchWiz(jar, signal) {
  const key = createHash("sha256").update(jar.get("__Secure-1PSID") || "").digest("hex");
  const cached = wizCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const res = await fetch(GEMINI_APP_URL, {
    headers: {
      "User-Agent": USER_AGENT,
      "Accept-Language": "en-US,en;q=0.9",
      Cookie: cookieHeader(jar),
    },
    redirect: "follow",
    signal,
    ...(await pageFetchOptions()),
  });
  if (!res.ok) throw new Error(`gemini.google.com returned HTTP ${res.status}`);
  const wiz = parseWizGlobalData(await res.text());
  if (!wiz || !wiz.serverToken || !wiz.apiKey) throw new Error("Could not read Gemini page bootstrap data");
  wizCache.set(key, { value: wiz, expiresAt: Date.now() + WIZ_TTL_MS });
  return wiz;
}

/**
 * Dashboard connection test: cookies must be complete, the Gemini page must
 * bootstrap, and a channel handshake (signed with SAPISIDHASH) must be accepted.
 * No message is generated.
 */
export async function validateGeminiWebConnection(rawCookie) {
  const jar = parseCookieString(rawCookie);
  const missing = missingCookies(jar);
  if (missing.length) {
    return { valid: false, error: `Cookie string is missing ${missing.join(", ")} — copy all cookies for gemini.google.com from DevTools → Application → Cookies` };
  }
  const signal = AbortSignal.timeout(20000);
  try {
    const wiz = await fetchWiz(jar, signal);
    const ticketHeader = buildTicketHeader({ ...MODEL_MAP[DEFAULT_MODEL], buildId: wiz.buildId });
    const session = new GeminiWebSession({ jar, wiz, authUser: "0", ticketHeader, signal });
    await session.handshake();
    await session.terminate();
    return { valid: true, error: null };
  } catch (err) {
    return { valid: false, error: err.message || "Gemini session check failed" };
  }
}

// ---------------------------------------------------------------- protobuf messages

export function buildTicketHeader({ ticket, mode, think, buildId }) {
  return toBase64(encodeMessage([
    [1, 1], [5, ticket], [8, 0], [9, Uint8Array.from([4, 5, 6, 8, 16, 19, 20])], [12, 2],
    [15, mode], [16, think], [17, crypto.randomUUID().toUpperCase()],
    [18, [[1, buildId]]],
  ]));
}

function buildClientSessionHeader() {
  return toBase64(encodeMessage([[1, crypto.randomUUID().toUpperCase()], [2, 1]]));
}

export function buildSetupMessage({ ticket, mode, think, requestId }) {
  return encodeMessage([[1, [
    [1, [[1, 1], [2, ticket], [3, [[14, ""]]], [4, requestId]]],
    [2, 0],
    [8, [[5, [
      [1, [
        [1, [[1, ""], [2, 0], [7, 0]]],
        [2, [[1, [[14, ""]]]]],
        [4, ""], [5, ""],
        [7, [[1, 1]]], [8, 1], [11, 1], [12, 0],
        [18, [[1, [[1, 0]]]]], [19, 0], [28, 1],
        [31, Uint8Array.from([4, 16, 19])], [42, [[1, 1]]], [50, 0], [54, 0],
        [60, requestId], [62, ""], [69, 2], [80, mode], [81, think],
        [92, 1], [97, 1], [99, 1],
      ]],
      [4, 1],
    ]]]],
  ]]]);
}

export function buildPromptMessage(text) {
  return encodeMessage([[2, [[1, 1], [9, [[1, text]]]]]]);
}

export function buildEndOfTurnMessage() {
  return encodeMessage([[4, [[1, 1]]]]);
}

/**
 * Interpret one decoded stream frame. Returns { seq, hasPayload, text, thinking, final }.
 *   seq        — per-turn sequence number (field 2.1)
 *   hasPayload — frame carries a response payload (conversation/response ids, candidate…)
 *   text       — candidate text so far (frames are cumulative: each one carries the whole answer)
 *   thinking   — thinking text so far (cumulative)
 *   final      — candidate carries the finished flag (field 9.1)
 * After the last text frame the server sends short payload frames without a candidate;
 * the turn runner treats the first of those as end of answer.
 */
export function interpretFrame(bytes) {
  const root = decodeMessage(bytes);
  const body = pick(root, [2]);
  const seq = pickNumber(body?.msg, [1]);
  const payload = pick(body?.msg, [7, 1, 4, 4])?.msg;
  if (!payload) return { seq, hasPayload: false, text: null, thinking: null, final: false };
  const candidate = pick(payload, [5])?.msg;
  const text = candidate ? pickText(candidate, [2, 1]) : null;
  const final = candidate ? pickNumber(candidate, [9, 1]) === 1 : false;
  const thinking = pickText(payload, [7, 6, 1]);
  return { seq, hasPayload: true, text, thinking, final };
}

// ---------------------------------------------------------------- WebChannel plumbing

function zx() {
  return Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]).join("");
}

function baseHeaders() {
  return {
    "User-Agent": USER_AGENT,
    Origin: GEMINI_ORIGIN,
    Referer: `${GEMINI_ORIGIN}/`,
    Accept: "*/*",
    "Accept-Language": "en-US,en;q=0.9",
  };
}

function channelUrl(base, params) {
  const u = new URL("/v1/processSession", base);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

export function buildHttpHeadersParam({ jar, authUser, apiKey, serverToken, ticketHeader }) {
  return [
    `Authorization:${sapisidHash(jar.get("SAPISID"))}`,
    `X-Goog-AuthUser:${authUser}`,
    `X-Goog-Api-Key:${apiKey}`,
    `X-Server-Token:${serverToken}`,
    `x-goog-ext-525001261-bin:${ticketHeader}`,
    `x-goog-ext-525005358-bin:${buildClientSessionHeader()}`,
    "x-goog-ext-73010989-bin:CAA=",
    "x-goog-ext-73010990-bin:CAAQABgA",
    "X-WebChannel-Content-Type:application/x-protobuf",
  ].join("\r\n") + "\r\n";
}

/** Parse `<len>\n<json>` framed WebChannel chunks; yields [aid, payload] pairs. */
export async function* readChannelFrames(body, signal) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      if (signal?.aborted) return;
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      while (true) {
        const m = buffer.match(/^(\d+)\n/);
        if (!m) break;
        const len = Number(m[1]);
        const start = m[0].length;
        // len counts UTF-16 code units of the JSON text, which is how the browser slices it.
        if (buffer.length < start + len) break;
        const frame = buffer.slice(start, start + len);
        buffer = buffer.slice(start + len);
        let arr;
        try { arr = JSON.parse(frame); } catch { continue; }
        for (const item of arr) yield item;
      }
    }
  } finally {
    reader.releaseLock();
  }
}

class GeminiWebSession {
  constructor({ jar, wiz, authUser, ticketHeader, signal, log }) {
    this.jar = jar; this.wiz = wiz; this.authUser = authUser; this.signal = signal; this.log = log;
    this.ticketHeader = ticketHeader;
    this.rid = 10000 + Math.floor(Math.random() * 80000);
    this.aid = 0; this.ofs = 0;
    this.sid = null; this.gsessionid = null;
  }

  async handshake() {
    const url = channelUrl(this.wiz.channelBase, {
      VER: "8", RID: String(this.rid), CVER: "22", "X-HTTP-Session-Id": "gsessionid",
      $httpHeaders: buildHttpHeadersParam({
        jar: this.jar, authUser: this.authUser, apiKey: this.wiz.apiKey,
        serverToken: this.wiz.serverToken, ticketHeader: this.ticketHeader,
      }),
      zx: zx(), t: "1",
    });
    const res = await fetch(url, {
      method: "POST",
      headers: { ...baseHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
      body: "count=0",
      signal: this.signal,
    });
    const text = await res.text();
    if (res.status === 401 || res.status === 403) throw new Error("Gemini rejected the session cookies — re-copy them from gemini.google.com");
    if (!res.ok) throw new Error(`Gemini channel handshake failed: HTTP ${res.status}`);
    const m = text.match(/\[\[0,\["c","([^"]+)"/);
    if (!m) throw new Error("Gemini channel handshake returned no session id");
    this.sid = m[1];
    this.gsessionid = res.headers.get("x-http-session-id") || "";
  }

  async openStream() {
    const url = channelUrl(this.wiz.channelBase, {
      VER: "8", gsessionid: this.gsessionid, SID: this.sid, RID: "rpc", AID: "0", CI: "0",
      TYPE: "xmlhttp", zx: zx(), t: "1",
    });
    const res = await fetch(url, { headers: baseHeaders(), signal: this.signal });
    if (!res.ok || !res.body) throw new Error(`Gemini channel stream failed: HTTP ${res.status}`);
    return res.body;
  }

  async post(messages) {
    this.rid += 1;
    const url = channelUrl(this.wiz.channelBase, {
      VER: "8", gsessionid: this.gsessionid, SID: this.sid, RID: String(this.rid), AID: String(this.aid), zx: zx(), t: "1",
    });
    const form = new URLSearchParams({ count: String(messages.length), ofs: String(this.ofs) });
    messages.forEach((m, i) => form.set(`req${i}___data__`, toBase64(m)));
    this.ofs += messages.length;
    const res = await fetch(url, {
      method: "POST",
      headers: { ...baseHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      signal: this.signal,
    });
    if (!res.ok) throw new Error(`Gemini channel post failed: HTTP ${res.status}`);
    await res.text();
  }

  async terminate() {
    try {
      this.rid += 1;
      const url = channelUrl(this.wiz.channelBase, {
        VER: "8", gsessionid: this.gsessionid, SID: this.sid, RID: String(this.rid), TYPE: "terminate", zx: zx(),
      });
      await fetch(url, { method: "POST", headers: baseHeaders(), body: "" });
    } catch { /* best effort */ }
  }
}

// ---------------------------------------------------------------- prompt flattening

export function parseOpenAIMessages(messages) {
  const extracted = [];
  for (const msg of messages) {
    let role = String(msg.role || "user");
    if (role === "developer") role = "system";
    let content = "";
    if (typeof msg.content === "string") content = msg.content;
    else if (Array.isArray(msg.content)) {
      content = msg.content.filter((c) => c?.type === "text" || c?.type === "input_text").map((c) => String(c.text || "")).join(" ");
    }
    if (!content.trim()) continue;
    extracted.push({ role, text: content });
  }
  let lastUserIdx = -1;
  for (let i = extracted.length - 1; i >= 0; i--) {
    if (extracted[i].role === "user") { lastUserIdx = i; break; }
  }
  return extracted.map(({ role, text }, i) => (i === lastUserIdx ? text : `${role}: ${text}`)).join("\n\n");
}

// ---------------------------------------------------------------- turn runner

/**
 * Run one turn and yield { thinkingDelta } / { delta } / { done } / { error } events.
 */
async function* runTurn({ jar, wiz, authUser, modelInfo, prompt, signal, log }) {
  const ticketHeader = buildTicketHeader({ ...modelInfo, buildId: wiz.buildId });
  const session = new GeminiWebSession({ jar, wiz, authUser, ticketHeader, signal, log });
  await session.handshake();
  const stream = await session.openStream();
  const requestId = crypto.randomUUID().toUpperCase();
  await session.post([buildSetupMessage({ ...modelInfo, requestId }), buildPromptMessage(prompt)]);

  let sentText = ""; let sentThinking = ""; let gotText = false; let sawFinalFlag = false; let finished = false;
  let timer = null;
  const frames = readChannelFrames(stream, signal);
  const armTimeout = (ms) => new Promise((resolve) => { timer = setTimeout(() => resolve({ timeout: true }), ms); });
  const idleBudget = () => {
    if (!gotText) return FIRST_FRAME_TIMEOUT_MS;
    return sawFinalFlag ? IDLE_AFTER_FINAL_FLAG_MS : IDLE_AFTER_TEXT_MS;
  };
  try {
    while (!finished) {
      const next = await Promise.race([frames.next(), armTimeout(idleBudget())]);
      clearTimeout(timer);
      if (next.timeout) {
        if (gotText) break;
        yield { error: "Gemini did not answer in time (model may require browser attestation or is rate limited)" };
        return;
      }
      if (next.done) break;
      const [aid, payload] = next.value;
      session.aid = Math.max(session.aid, aid);
      const p0 = Array.isArray(payload) ? payload[0] : payload;
      if (typeof p0 !== "string" || p0 === "noop") continue;
      let frame;
      try { frame = interpretFrame(fromBase64(p0)); } catch { continue; }
      if (frame.thinking && frame.thinking !== sentThinking) {
        const delta = frame.thinking.startsWith(sentThinking) ? frame.thinking.slice(sentThinking.length) : frame.thinking;
        sentThinking = frame.thinking;
        if (delta) yield { thinkingDelta: delta };
      }
      if (frame.text !== null && frame.text !== sentText) {
        const delta = frame.text.startsWith(sentText) ? frame.text.slice(sentText.length) : frame.text;
        sentText = frame.text; gotText = true;
        if (delta) yield { delta };
      }
      if (frame.final) sawFinalFlag = true;
      // Post-answer frames carry a payload but no candidate text: the answer is complete.
      if (gotText && frame.hasPayload && frame.text === null && !frame.thinking) finished = true;
    }
  } finally {
    clearTimeout(timer);
    try { await session.post([buildEndOfTurnMessage()]); } catch { /* best effort */ }
    await session.terminate();
    try { await frames.return(); } catch { /* ignore */ }
  }
  yield { done: true };
}

function errorResponse(status, message, type = "upstream_error") {
  return new Response(JSON.stringify({ error: { message, type } }), {
    status, headers: { "Content-Type": "application/json" },
  });
}

function chunk(cid, created, model, delta, finishReason = null) {
  return sseChunk({
    id: cid, object: "chat.completion.chunk", created, model, system_fingerprint: null,
    choices: [{ index: 0, delta, finish_reason: finishReason, logprobs: null }],
  });
}

function buildStreamingResponse(events, model, cid, created) {
  const encoder = new TextEncoder();
  return new ReadableStream({
    async start(controller) {
      try {
        controller.enqueue(encoder.encode(chunk(cid, created, model, { role: "assistant" })));
        for await (const ev of events) {
          if (ev.error) {
            controller.enqueue(encoder.encode(chunk(cid, created, model, { content: `[Error: ${ev.error}]` })));
            break;
          }
          if (ev.thinkingDelta) controller.enqueue(encoder.encode(chunk(cid, created, model, { reasoning_content: ev.thinkingDelta })));
          if (ev.delta) controller.enqueue(encoder.encode(chunk(cid, created, model, { content: ev.delta })));
          if (ev.done) break;
        }
        controller.enqueue(encoder.encode(chunk(cid, created, model, {}, "stop")));
        controller.enqueue(encoder.encode(SSE_DONE));
      } catch (err) {
        controller.enqueue(encoder.encode(chunk(cid, created, model, { content: `[Stream error: ${err.message || String(err)}]` }, "stop")));
        controller.enqueue(encoder.encode(SSE_DONE));
      } finally {
        controller.close();
      }
    },
  });
}

async function buildNonStreamingResponse(events, model, cid, created) {
  let content = ""; let reasoning = "";
  for await (const ev of events) {
    if (ev.error) return errorResponse(502, ev.error);
    if (ev.thinkingDelta) reasoning += ev.thinkingDelta;
    if (ev.delta) content += ev.delta;
    if (ev.done) break;
  }
  const message = { role: "assistant", content };
  if (reasoning) message.reasoning_content = reasoning;
  const completionTokens = Math.ceil(content.length / 4);
  return new Response(JSON.stringify({
    id: cid, object: "chat.completion", created, model, system_fingerprint: null,
    choices: [{ index: 0, message, finish_reason: "stop", logprobs: null }],
    usage: { prompt_tokens: 0, completion_tokens: completionTokens, total_tokens: completionTokens },
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

// ---------------------------------------------------------------- executor

export class GeminiWebExecutor extends BaseExecutor {
  constructor() {
    super(PROVIDER_ID, PROVIDERS[PROVIDER_ID]);
  }

  async execute({ model, body, stream, credentials, signal, log }) {
    const url = PROVIDERS[PROVIDER_ID]?.baseUrl || `${DEFAULT_CHANNEL_BASE}/v1/processSession`;
    const messages = body?.messages;
    if (!Array.isArray(messages) || messages.length === 0) {
      return { response: errorResponse(400, "Missing or empty messages array", "invalid_request"), url, headers: {}, transformedBody: body };
    }
    const prompt = parseOpenAIMessages(messages);
    if (!prompt.trim()) {
      return { response: errorResponse(400, "Empty query after processing", "invalid_request"), url, headers: {}, transformedBody: body };
    }
    const modelInfo = MODEL_MAP[model] || MODEL_MAP[DEFAULT_MODEL];
    if (!MODEL_MAP[model]) log?.info?.("GEMINI-WEB", `Unmapped model ${model}, defaulting to ${DEFAULT_MODEL}`);

    const jar = parseCookieString(credentials?.apiKey);
    const missing = missingCookies(jar);
    if (missing.length) {
      return { response: errorResponse(401, `Gemini cookie string is missing ${missing.join(", ")} — copy all cookies from gemini.google.com`), url, headers: {}, transformedBody: body };
    }
    const authUser = String(credentials?.providerSpecificData?.authUser ?? "0");

    let wiz;
    try {
      wiz = await fetchWiz(jar, signal);
    } catch (err) {
      log?.warn?.("GEMINI-WEB", `Bootstrap failed: ${err.message}`);
      return { response: errorResponse(401, err.message), url, headers: {}, transformedBody: body };
    }

    log?.info?.("GEMINI-WEB", `Query to ${model} (mode=${modelInfo.mode}, think=${modelInfo.think}), len=${prompt.length}`);
    const cid = `chatcmpl-gmw-${crypto.randomUUID().slice(0, 12)}`;
    const created = Math.floor(Date.now() / 1000);
    const events = runTurn({ jar, wiz, authUser, modelInfo, prompt, signal, log });

    let response;
    if (stream) {
      response = new Response(buildStreamingResponse(events, model, cid, created), { status: 200, headers: { ...SSE_HEADERS_NO_BUFFER } });
    } else {
      response = await buildNonStreamingResponse(events, model, cid, created);
    }
    return { response, url, headers: {}, transformedBody: { model, prompt } };
  }
}

export default GeminiWebExecutor;
