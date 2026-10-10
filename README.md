# AI Web Summarizer

Paste a URL, the backend scrapes the page text, and a free AI model (Groq, Llama 3.3) returns a short summary.

**Live demo:** <PASTE YOUR DEPLOYED LINK HERE>

## Tech stack
- **Frontend:** plain HTML/CSS/JS (`public/index.html`)
- **Backend:** Node.js + Express (`server.js`)
- **Scraping:** Cheerio
- **AI:** Groq API (free tier)

## How it works
1. The frontend sends `POST /api/summarize` with `{ "url": "..." }`.
2. The backend fetches the page, strips scripts/nav/footer, and extracts the main text.
3. The text is sent to Groq, which returns a summary and key takeaways.
4. The frontend shows "Loading..." while waiting, then displays the result.

## Run locally

**Prerequisites:** Node.js 18+ and a free Groq API key from https://console.groq.com/keys

1. Clone and install:
   ```bash
   git clone <YOUR_REPO_URL>
   cd ai-web-summarizer
   npm install
   ```
2. Create the `.env` file **in the project root** (same folder as `package.json` and `server.js`):
   ```bash
   cp .env.example .env
   ```
   Open `.env` and set your key:
   ```
   GROQ_API_KEY=your_groq_api_key_here
   ```
3. Start the app:
   ```bash
   npm start
   ```
4. Open http://localhost:3000

The Express server runs the **backend** (`/api/summarize`) and also serves the **frontend** from the `public/` folder, so one command starts both.

## Deploy (Render)
1. Push this repo to GitHub.
2. On https://render.com create a **New > Web Service** and connect the repo.
3. Build command: `npm install` | Start command: `npm start`
4. Add an environment variable `GROQ_API_KEY` with your key.
5. Deploy, then paste the live URL at the top of this README.

## Limitations
- Only scrapes static HTML (no JavaScript-rendered pages, no bot-protection bypass).
- Very long pages are truncated to ~12,000 characters before summarizing.
