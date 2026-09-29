# CVE Sentinel

**CVE Sentinel** is a lightweight Cyber Vulnerability Intelligence platform that automatically collects recent CVEs, enriches them with CISA KEV information, scores them with CVSS, sends Telegram/email alerts, and publishes a searchable static dashboard.

## Architecture

```text
                ┌───────────────┐
                │ NVD CVE 2.0   │
                └───────┬───────┘
                        │
                ┌───────▼───────┐
                │ CVE Sentinel  │
                │ Python engine │
                └───┬─────┬─────┘
                    │     │
          ┌─────────┘     └─────────┐
          ▼                         ▼
     CISA KEV                   Alerting
          │                  Telegram / Email
          ▼
   data/cves.json
          │
          ▼
 GitHub Pages Dashboard
```

The scheduled GitHub Actions workflow runs the collector, updates the data files, sends alerts, and commits the generated data back to the repository. GitHub supports scheduled workflows using POSIX cron and manual `workflow_dispatch` runs. Scheduled workflows use UTC unless a timezone is configured. See the official documentation: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows

## Features

- NVD CVE 2.0 collection
- CISA Known Exploited Vulnerabilities (KEV) enrichment
- CVSS 4.0 / 3.1 / 3.0 / 2.0 support
- Critical / High / Medium / Low severity classification
- Keyword filtering
- CISA KEV priority flag
- Telegram alerts
- Optional SMTP email alerts
- Deduplication state
- JSON data store suitable for GitHub Pages
- Responsive dark dashboard
- Search by CVE, vendor, product, description
- Severity and KEV filters
- No secrets in source code
- Manual "Run workflow" support

## Project tree

```text
cve-sentinel/
├── .github/
│   └── workflows/
│       └── sentinel.yml
├── dashboard/
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── data/
│   ├── cves.json
│   └── stats.json
├── sentinel/
│   ├── __init__.py
│   ├── cisa.py
│   ├── config.py
│   ├── database.py
│   ├── email.py
│   ├── nvd.py
│   ├── scoring.py
│   ├── telegram.py
│   └── main.py
├── .env.example
├── .gitignore
├── LICENSE
├── requirements.txt
└── README.md
```

## 1. Telegram

Open `@BotFather`:

1. `/newbot`
2. Create your bot.
3. Copy the bot token.
4. Send a message to the bot.
5. Open `https://api.telegram.org/botYOUR_TOKEN/getUpdates`
6. Copy `message.chat.id`.

Do not commit the token.

## 2. GitHub Secrets

Repository:

`Settings -> Secrets and variables -> Actions`

Create secrets:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

Optional email secrets:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `EMAIL_FROM`
- `EMAIL_TO`

Optional:

- `NVD_API_KEY`

NVD API keys are useful when you need higher request limits.

## 3. GitHub Variables

In:

`Settings -> Secrets and variables -> Actions -> Variables`

Optional variables:

- `MIN_CVSS` = `7`
- `MAX_CVES` = `30`
- `KEYWORDS` = `linux,microsoft,apache,fortinet,cisco,vmware`
- `SEND_EMPTY_REPORT` = `false`

If `KEYWORDS` is empty, all CVEs are considered.

## 4. Test locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export TELEGRAM_BOT_TOKEN="..."
export TELEGRAM_CHAT_ID="..."

python -m sentinel.main
```

For email, also export the SMTP variables.

## 5. GitHub Pages

After pushing the repository:

`Settings -> Pages`

Choose:

- Source: `GitHub Actions`

The included workflow deploys the `dashboard/` directory to GitHub Pages.

The dashboard reads `data/cves.json` from the same repository.

## 6. Run manually

Go to:

`Actions -> CVE Sentinel -> Run workflow`

This is useful immediately after configuring secrets.

## Security notes

- Never put API keys or Telegram tokens in Python files.
- Keep `.env` ignored.
- The generated `data/` files contain vulnerability information, not credentials.
- The dashboard is intentionally static: no exposed database credentials and no public backend required.
- GitHub Actions permissions are restricted to repository contents write for the data update/deployment workflow.

## Data sources

NVD:
https://nvd.nist.gov/

CISA KEV:
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## License

MIT
# cve_sentinel
