/**
 * Unit tests for the gemini-web executor (Gemini web app WebChannel transport).
 *
 * Covers:
 *  - cookie string parsing / required cookie check
 *  - SAPISIDHASH construction
 *  - WIZ_global_data bootstrap parsing (signed-in detection)
 *  - protobuf encode/decode round trip and message shapes
 *  - frame interpretation against frames captured from the real stream
 *  - WebChannel frame reader (`<len>\n[[aid,[payload]]]`)
 *  - message flattening
 *  - executor error paths (bad cookies, empty messages)
 */

import { describe, it, expect } from "vitest";
import { encodeMessage, decodeMessage, pickText, pickNumber, toBase64, fromBase64 } from "../../open-sse/utils/geminiWebProtobuf.js";
import {
  parseCookieString,
  missingCookies,
  sapisidHash,
  parseWizGlobalData,
  buildTicketHeader,
  buildSetupMessage,
  buildPromptMessage,
  buildEndOfTurnMessage,
  interpretFrame,
  readChannelFrames,
  parseOpenAIMessages,
  buildHttpHeadersParam,
  MODEL_MAP,
  THINKING_LEVEL,
  GeminiWebExecutor,
} from "../../open-sse/executors/gemini-web.js";

// Frames captured from a live Gemini 4 web session (ids are random per session, text is test data).
const FRAME_CONVERSATION_CREATED = "EkwIATpICkYIABImCiQ3Mjg2NDg0ZC1lZTE5LTQ0NmMtYTVkNS04MmJlMWQzMTNhZTUiGiIYEhYKEmNfZDMwY2Y5ZmQyZjM0Yjg1MRIA";
const FRAME_THINKING = "EmsIAzpnCmUIABIUChJyXzljOWY3YWVkMTdlOGNlODciSyJJEigKEmNfYmZjNTgzYzY3ZmViOTRkNRIScl85YzlmN2FlZDE3ZThjZTg3Oh0yGwoZQ29tcHJlaGVuZGluZyB0aGUgUmVxdWVzdA==";

function candidateFrame(text, { final = true, kind = 3 } = {}) {
  // Mirrors the shape of the live frame: 2 { 1: seq, 7 { 1 { 4 { 4 { 5 { 1: rc, 2 { 1: text }, 9 { 1: 1 } } } } } } }
  const candidate = [[1, "rc_test"], [2, [[1, text]]]];
  if (final) candidate.push([9, [[1, 1]]]);
  return toBase64(encodeMessage([[2, [[1, kind], [7, [[1, [[4, [[4, [[5, candidate]]]]]]]]]]]]));
}

describe("protobuf helpers", () => {
  it("round-trips varints, strings, bytes and nested messages", () => {
    const bytes = encodeMessage([[1, 300], [2, "héllo"], [3, Uint8Array.from([4, 16, 19])], [4, [[1, 1], [9, [[1, "inner"]]]]]]);
    const msg = decodeMessage(bytes);
    expect(pickNumber(msg, [1])).toBe(300);
    expect(pickText(msg, [2])).toBe("héllo");
    expect(Array.from(msg.fields.get(3)[0].bytes)).toEqual([4, 16, 19]);
    expect(pickNumber(msg, [4, 1])).toBe(1);
    expect(pickText(msg, [4, 9, 1])).toBe("inner");
  });

  it("skips null values and rejects unsupported ones", () => {
    expect(encodeMessage([[1, null], [2, undefined]]).length).toBe(0);
    expect(() => encodeMessage([[1, { a: 1 }]])).toThrow(TypeError);
  });

  it("base64 helpers are inverse", () => {
    const b = Uint8Array.from([0, 1, 2, 250]);
    expect(Array.from(fromBase64(toBase64(b)))).toEqual([0, 1, 2, 250]);
  });
});

describe("cookies and auth", () => {
  it("parses a pasted cookie string and keeps order", () => {
    const jar = parseCookieString("SID=a; HSID=b; SSID=c; APISID=d; SAPISID=e; __Secure-1PSID=f");
    expect(jar.get("SAPISID")).toBe("e");
    expect(jar.get("__Secure-1PSID")).toBe("f");
    expect(missingCookies(jar)).toEqual([]);
  });

  it("accepts the JSON cookie-file shape and reports missing cookies", () => {
    const jar = parseCookieString(JSON.stringify({ cookie: "SID=a; SAPISID=e" }));
    expect(jar.get("SID")).toBe("a");
    expect(missingCookies(jar)).toEqual(["__Secure-1PSID"]);
    expect(missingCookies(parseCookieString(""))).toEqual(["SAPISID", "__Secure-1PSID"]);
  });

  it("builds SAPISIDHASH with the gemini origin and one shared digest", () => {
    const h = sapisidHash("secret", "https://gemini.google.com", 1792060634000);
    const parts = h.split(" ");
    expect(parts[0]).toBe("SAPISIDHASH");
    expect(parts[1]).toMatch(/^1792060634_[0-9a-f]{40}$/);
    expect(parts[3]).toBe(parts[1]);
    expect(parts[5]).toBe(parts[1]);
  });

  it("puts every channel header into the $httpHeaders block", () => {
    const jar = parseCookieString("SAPISID=e; __Secure-1PSID=f");
    const block = buildHttpHeadersParam({ jar, authUser: "0", apiKey: "AIza", serverToken: "CAMS", ticketHeader: "QUJD" });
    const names = block.trim().split("\r\n").map((l) => l.split(":")[0]);
    expect(names).toEqual([
      "Authorization", "X-Goog-AuthUser", "X-Goog-Api-Key", "X-Server-Token",
      "x-goog-ext-525001261-bin", "x-goog-ext-525005358-bin", "x-goog-ext-73010989-bin",
      "x-goog-ext-73010990-bin", "X-WebChannel-Content-Type",
    ]);
    expect(block.endsWith("\r\n")).toBe(true);
  });
});

describe("page bootstrap", () => {
  const page = (extra = "") => `<html><script>window.WIZ_global_data = {"PI9WOb":"CAMStoken","d2zJAe":"AIzaKey","cfb2h":"boq_gemini-web-uiserver_20261014.09_p0","GK6dn":"https://geminiweb-pa.clients6.google.com"};</script>${extra}</html>`;

  it("extracts server token, api key, build id and channel base", () => {
    const wiz = parseWizGlobalData(page());
    expect(wiz).toEqual({
      serverToken: "CAMStoken", apiKey: "AIzaKey", buildId: "boq_gemini-web-uiserver_20261014.09_p0",
      channelBase: "https://geminiweb-pa.clients6.google.com",
    });
  });

  it("returns null when the page carries no bootstrap data", () => {
    expect(parseWizGlobalData("<html></html>")).toBeNull();
  });
});

describe("message shapes", () => {
  it("ticket header carries ticket, mode, thinking level and build id", () => {
    const msg = decodeMessage(fromBase64(buildTicketHeader({ ticket: "95a4c0abcba24364", mode: 8, think: 1, buildId: "boq_x" })));
    expect(pickText(msg, [5])).toBe("95a4c0abcba24364");
    expect(pickNumber(msg, [15])).toBe(8);
    expect(pickNumber(msg, [16])).toBe(1);
    expect(pickText(msg, [18, 1])).toBe("boq_x");
    expect(pickText(msg, [17])).toMatch(/^[0-9A-F-]{36}$/);
  });

  it("setup message places ticket, request id, mode and thinking where the web client does", () => {
    const msg = decodeMessage(buildSetupMessage({ ticket: "e6fa609c3fa255c0", mode: 3, think: 4, requestId: "REQ-1" }));
    expect(pickText(msg, [1, 1, 2])).toBe("e6fa609c3fa255c0");
    expect(pickText(msg, [1, 1, 4])).toBe("REQ-1");
    const inner = [1, 8, 5, 1];
    expect(pickNumber(msg, [...inner, 80])).toBe(3);
    expect(pickNumber(msg, [...inner, 81])).toBe(4);
    expect(pickText(msg, [...inner, 60])).toBe("REQ-1");
    expect(pickText(msg, [...inner, 4])).toBe("");
    expect(pickNumber(msg, [1, 8, 5, 4])).toBe(1);
  });

  it("prompt and end-of-turn messages use fields 2 and 4", () => {
    const prompt = decodeMessage(buildPromptMessage("Привет"));
    expect(pickNumber(prompt, [2, 1])).toBe(1);
    expect(pickText(prompt, [2, 9, 1])).toBe("Привет");
    const end = decodeMessage(buildEndOfTurnMessage());
    expect(pickNumber(end, [4, 1])).toBe(1);
  });

  it("model map covers the registry models with valid tickets and thinking levels", () => {
    for (const [id, info] of Object.entries(MODEL_MAP)) {
      expect(info.ticket, id).toMatch(/^[0-9a-f]{16}$/);
      expect([1, 3, 6]).toContain(info.mode);
      expect(Object.values(THINKING_LEVEL)).toContain(info.think);
    }
    expect(MODEL_MAP["gemini-3.1-pro-high"].think).toBe(THINKING_LEVEL.high);
  });
});

describe("frame interpretation", () => {
  it("reads the conversation-created frame as payload without text", () => {
    const f = interpretFrame(fromBase64(FRAME_CONVERSATION_CREATED));
    expect(f.seq).toBe(1);
    expect(f.hasPayload).toBe(true);
    expect(f.text).toBeNull();
    expect(f.final).toBe(false);
  });

  it("marks frames without a response payload", () => {
    const f = interpretFrame(encodeMessage([[1, ""]]));
    expect(f.hasPayload).toBe(false);
    expect(f.text).toBeNull();
  });

  it("reads thinking text from a live Pro frame", () => {
    const f = interpretFrame(fromBase64(FRAME_THINKING));
    expect(f.seq).toBe(3);
    expect(f.thinking).toBe("Comprehending the Request");
    expect(f.text).toBeNull();
  });

  it("reads candidate text and the final flag", () => {
    expect(interpretFrame(fromBase64(candidateFrame("42")))).toMatchObject({ seq: 3, text: "42", final: true });
    expect(interpretFrame(fromBase64(candidateFrame("partial", { final: false })))).toMatchObject({ text: "partial", final: false });
  });
});

describe("channel frame reader", () => {
  async function collect(chunks) {
    const stream = new ReadableStream({
      start(c) { for (const ch of chunks) c.enqueue(new TextEncoder().encode(ch)); c.close(); },
    });
    const out = [];
    for await (const item of readChannelFrames(stream)) out.push(item);
    return out;
  }

  it("parses length-prefixed frames even when split across chunks", async () => {
    const f1 = JSON.stringify([[1, ["noop"]]]);
    const f2 = JSON.stringify([[2, ["CgA="]], [3, ["EkwI"]]]);
    const wire = `${f1.length}\n${f1}${f2.length}\n${f2}`;
    const items = await collect([wire.slice(0, 7), wire.slice(7, 20), wire.slice(20)]);
    expect(items).toEqual([[1, ["noop"]], [2, ["CgA="]], [3, ["EkwI"]]]);
  });

  it("counts UTF-16 units like the browser does", async () => {
    const f = JSON.stringify([[1, ["Привет"]]]);
    const items = await collect([`${f.length}\n${f}`]);
    expect(items).toEqual([[1, ["Привет"]]]);
  });
});

describe("prompt flattening", () => {
  it("keeps the last user message bare and prefixes the rest with roles", () => {
    const text = parseOpenAIMessages([
      { role: "system", content: "Be brief" },
      { role: "user", content: [{ type: "text", text: "Q1" }] },
      { role: "assistant", content: "A1" },
      { role: "user", content: "Q2" },
    ]);
    expect(text).toBe("system: Be brief\n\nuser: Q1\n\nassistant: A1\n\nQ2");
  });
});

describe("executor guards", () => {
  const executor = new GeminiWebExecutor();

  it("rejects an empty messages array", async () => {
    const { response } = await executor.execute({ model: "gemini-3.8-flash", body: { messages: [] }, stream: false, credentials: { apiKey: "" } });
    expect(response.status).toBe(400);
  });

  it("rejects incomplete cookies before touching the network", async () => {
    const { response } = await executor.execute({
      model: "gemini-3.8-flash", body: { messages: [{ role: "user", content: "hi" }] }, stream: false,
      credentials: { apiKey: "SID=only" },
    });
    expect(response.status).toBe(401);
    const json = await response.json();
    expect(json.error.message).toContain("SAPISID");
  });
});
