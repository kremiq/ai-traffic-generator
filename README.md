# AI Traffic Generator (Windows)

A Windows tool that sends traffic to AI applications such as ChatGPT, Claude,
Gemini, Copilot, Perplexity, DeepSeek, Grok, AI APIs, coding assistants and image
tools. Use it to test a secure web gateway or AI gateway (for example Cloudflare
Gateway with WARP): does it detect the apps, apply allow and block policies, and
catch sensitive prompts with DLP?

It is a single PowerShell script and needs nothing extra installed. It runs on the
built-in Windows PowerShell 5.1 (Windows 10/11) and on PowerShell 7.

## Start

Download the repository (**Code → Download ZIP**, or `git clone`) and double-click **`Start-AiTrafficGenerator.cmd`**.

Or run it from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\AiTrafficGenerator.ps1
```

If Windows blocks the downloaded files, run `Unblock-File .\*` in the folder first.

## Window

1. **AI applications**: tick the apps. The **All** and **None** buttons and the
   category list select several apps at once. Each line shows what the app supports,
   for example `[Chatbot, Web+Api]`.
2. **Send**:
   - **Web pages (GET)** loads the app's pages with a browser User-Agent. Apps with a
     prompt URL (ChatGPT, Claude, Copilot, Perplexity, Grok, Mistral, You.com) also get
     one request with the prompt in the URL, for example `https://chatgpt.com/?q=...`.
   - **API calls (POST prompt)** sends the prompt to the app's API in its real
     format (OpenAI, Anthropic, Gemini, Mistral, DeepSeek, xAI, Perplexity, Groq,
     Cohere, OpenRouter, Hugging Face, Together).
   - **Open in browser** opens the app in the default browser (with the prompt where
     the app supports it), for real browser traffic.
3. **Prompt**: pick a preset or type your own. Some presets contain test data for DLP:
   a test card number, IBAN and SSN, AWS example keys, a "confidential" document and a
   prompt injection. **Random preset per app** uses a different preset for each app.
4. **Repeat / Pace**: the number of rounds (0 = until you press Stop) or a duration
   in minutes, the delay between requests, the number of parallel requests and the
   timeout.
5. **Start**. Each request appears as a row: green means it reached the app, red
   means it was blocked. Double-click a row to see all its details (they are also
   copied to the clipboard). **Export CSV...** saves all results.

## Reading the results

| Result | Meaning |
| --- | --- |
| `Allowed` | The app answered, so the request passed the gateway. A `401`/`403` from an API without a key, or a bot challenge page from the app's site, still counts here, because the app itself answered. |
| `Blocked` | A block page was returned (its text matches `blockMarkers` in `ai-apps.json`), or the proxy refused the connection. |
| `Blocked?` | DNS lookup failed or the connection was reset or refused. This usually means a DNS or network policy blocked it. |
| `TLS error` | The certificate was not trusted. With TLS inspection, install the gateway's root certificate in *Trusted Root Certification Authorities*. |
| `Timeout` / `Error` | No answer in time, or another error (shown in Detail). |
| `Opened` | Opened in the browser. Check the result in the browser and the gateway logs. |

For **Web** rows, Detail shows the page title. When the request was redirected to
another host, for example to a block page, Detail also shows the new URL.

The script uses the Windows proxy settings, or the proxy you enter. With WARP or
another agent, the traffic goes through the gateway automatically.

## API keys (optional)

Without keys, API calls get a `401` from the provider. That is enough for app
detection and DLP tests, because the full prompt is in the request body that the
gateway inspects. To get real answers, set the environment variable named in
`ai-apps.json` before you start, for example:

```powershell
$env:OPENAI_API_KEY = 'sk-...'
$env:ANTHROPIC_API_KEY = 'sk-ant-...'
.\AiTrafficGenerator.ps1
```

| Provider | Variable |
| --- | --- |
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Google Gemini | `GEMINI_API_KEY` |
| Perplexity | `PERPLEXITY_API_KEY` |
| xAI | `XAI_API_KEY` |
| DeepSeek | `DEEPSEEK_API_KEY` |
| Mistral | `MISTRAL_API_KEY` |
| Hugging Face | `HF_TOKEN` |
| OpenRouter | `OPENROUTER_API_KEY` |
| Groq | `GROQ_API_KEY` |
| Cohere | `COHERE_API_KEY` |
| Together | `TOGETHER_API_KEY` |

## Console mode (scheduled or continuous traffic)

```powershell
# List the app IDs
.\AiTrafficGenerator.ps1 -List

# Three rounds to three apps, results saved to CSV
.\AiTrafficGenerator.ps1 -NoGui -Apps chatgpt,claude,gemini -Mode Web,Api -Rounds 3 -OutCsv results.csv

# All chatbots for 30 minutes, a random preset prompt per app, one request every 2 s
.\AiTrafficGenerator.ps1 -NoGui -Category Chatbot -RandomPrompt -DurationMinutes 30 -DelayMs 2000

# DLP test against all APIs
.\AiTrafficGenerator.ps1 -NoGui -Mode Api -Prompt "Card 4111 1111 1111 1111, CVV 123"
```

| Parameter | Default | |
| --- | --- | --- |
| `-Apps` | `all` | App IDs (see `-List`). |
| `-Category` | | Only apps in these categories, e.g. `Chatbot`, `"AI platform"`, `Coding`. |
| `-Mode` | `Web,Api` | `Web`, `Api` and/or `Browser`. |
| `-Rounds` | `1` | 0 = until Ctrl+C. |
| `-DurationMinutes` | `0` | Repeat rounds for this long (overrides `-Rounds`). |
| `-DelayMs` | `500` | Pause between the start of two requests. |
| `-Concurrency` | `4` | Parallel requests. |
| `-TimeoutSec` | `20` | Per request. |
| `-Prompt` | first preset | Prompt text. |
| `-RandomPrompt` | | A random preset per app and round. |
| `-Shuffle` | | Random order of requests. |
| `-Proxy` | Windows setting | e.g. `http://proxy:8080`. |
| `-OutCsv` | | Save the results. |
| `-Catalog` | `ai-apps.json` | Another catalogue file. |

The process exits when it is done, so it can run as a Windows scheduled task:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Tools\ai\AiTrafficGenerator.ps1 -NoGui -RandomPrompt -Rounds 1
```

## Adding apps and prompts

Everything is in `ai-apps.json`. In the window, use **Edit catalogue** and then
**Reload catalogue**.

```json
{
  "id": "myapp", "name": "My AI App", "vendor": "Example", "category": "Chatbot",
  "web": ["https://ai.example.com/"],
  "promptUrl": "https://ai.example.com/?q={{prompt}}",
  "api": {
    "url": "https://api.example.com/v1/chat/completions",
    "model": "example-model",
    "headers": { "x-extra": "value" },
    "auth": { "env": "EXAMPLE_API_KEY", "header": "Authorization", "prefix": "Bearer " },
    "body": { "model": "{{model}}", "messages": [ { "role": "user", "content": "{{prompt}}" } ] }
  }
}
```

`web`, `promptUrl` and `api` are all optional. `{{prompt}}` and `{{model}}` are
filled in automatically (URL-encoded in URLs, JSON-escaped in the body). Model
names change often, so update `model` if a provider rejects it (this matters only
when you use a key). Also in the file: `prompts` (presets), `userAgent`, and
`blockMarkers` (text that identifies your gateway's block page; add your custom
block page text here).

## Notes

- Only test networks and policies you are responsible for. Each request with an API
  key costs credits with that provider.
- Many AI sites protect their pages against scripts. A `403` challenge page from the
  site counts as `Allowed`. To see the gateway's view of real browser sessions, use
  **Open in browser**.
