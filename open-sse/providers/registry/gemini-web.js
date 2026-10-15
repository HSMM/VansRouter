export default {
  id: "gemini-web",
  priority: 150,
  alias: "gemini-web",
  aliases: [
    "gmw",
  ],
  uiAlias: "gmw",
  display: {
    name: "Gemini Web (Google account)",
    icon: "auto_awesome",
    color: "#4285F4",
    textIcon: "GW",
    website: "https://gemini.google.com",
  },
  category: "webCookie",
  authType: "cookie",
  authHint: "Paste the gemini.google.com cookie string: SID=…; HSID=…; SSID=…; APISID=…; SAPISID=…; __Secure-1PSID=…",
  transport: {
    baseUrl: "https://geminiweb-pa.clients6.google.com/v1/processSession",
    format: "gemini-web",
    authType: "cookie",
  },
  models: [
    { id: "gemini-flash-lite", name: "Gemini 3.5 Flash-Lite" },
    { id: "gemini-3.8-flash", name: "Gemini 3.8 Flash" },
    { id: "gemini-3.1-pro", name: "Gemini 3.1 Pro (thinking)" },
    { id: "gemini-3.1-pro-low", name: "Gemini 3.1 Pro (low thinking)" },
    { id: "gemini-3.1-pro-medium", name: "Gemini 3.1 Pro (medium thinking)" },
    { id: "gemini-3.1-pro-high", name: "Gemini 3.1 Pro (high thinking)" },
  ],
  passthroughModels: true,
};
