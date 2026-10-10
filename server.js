require("dotenv").config();
const express = require("express");
const cheerio = require("cheerio");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const MODEL = process.env.GROQ_MODEL || "llama-3.3-70b-versatile";
const MAX_CHARS = 12000; // keep prompt small for the free tier

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Basic safety: only http/https, and block obvious local/private hosts (SSRF)
function isSafeUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return false; }
  if (!["http:", "https:"].includes(u.protocol)) return false;
  const h = u.hostname;
  return !(
    h === "localhost" ||
    h.endsWith(".local") ||
    /^127\./.test(h) ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
    /^169\.254\./.test(h) ||
    h === "0.0.0.0" ||
    h === "[::1]"
  );
}

async function scrape(url) {
  const res = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; AISummarizerBot/1.0)" },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`Page returned status ${res.status}`);
  const type = res.headers.get("content-type") || "";
  if (!type.includes("text/html")) throw new Error("URL is not an HTML page");

  const $ = cheerio.load(await res.text());
  $("script, style, noscript, nav, footer, header, aside, form, iframe, svg").remove();

  const title = $("title").first().text().trim();
  const root = $("article").length ? $("article") : $("main").length ? $("main") : $("body");
  const text = root.text().replace(/\s+/g, " ").trim();

  if (text.length < 100) throw new Error("Not enough text found (page may need JavaScript to render)");
  return { title, text: text.slice(0, MAX_CHARS) };
}

async function summarize(title, text) {
  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${GROQ_API_KEY}`,
    },
    body: JSON.stringify({
      model: MODEL,
      temperature: 0.3,
      messages: [
        {
          role: "system",
          content:
            "You summarize web pages. Write a short summary (3-5 sentences) followed by 3 key takeaways as bullet points starting with '- '.",
        },
        { role: "user", content: `Title: ${title}\n\nContent:\n${text}` },
      ],
    }),
  });
    if (!res.ok) {
    const body = await res.text();
    console.error("Groq error:", res.status, body);
    throw new Error(`AI API error (${res.status})`);
  }
  const data = await res.json();
  return data.choices[0].message.content;
}

app.post("/api/summarize", async (req, res) => {
  const { url } = req.body || {};
  if (!url || !isSafeUrl(url)) {
    return res.status(400).json({ error: "Please provide a valid public http(s) URL." });
  }
  if (!GROQ_API_KEY) {
    return res.status(500).json({ error: "Server is missing GROQ_API_KEY." });
  }
  try {
    const { title, text } = await scrape(url);
    const summary = await summarize(title, text);
    res.json({ title, summary });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Something went wrong." });
  }
});

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
