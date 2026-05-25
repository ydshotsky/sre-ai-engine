# SecureVault SRE AI Engine

SecureVault SRE AI Engine is a high-throughput webhook gateway that ingests incident alerts (such as those from Grafana), deduplicates them based on an error fingerprint, and automatically generates incident dockets using OpenAI's `gpt-4o-mini`. The engine then posts these detailed diagnostic runbooks directly to GitHub Issues as automated bug reports.

## Features

- **High-Throughput Webhook API**: Immediately accepts alerts returning a 202 Accepted status and dispatches tasks to background workers.
- **AI-Powered Diagnostics**: Uses OpenAI `gpt-4o-mini` to automatically analyze the alert title, message, and logs, returning a Markdown-formatted root cause breakdown and runbook.
- **Smart Deduplication**: Generates deterministic fingerprints by stripping out volatile data like timestamps and memory addresses to prevent duplicate GitHub issues.
- **GitHub Integration**: Automatically opens issues in a specified GitHub repository and subsequently tracks duplicate occurrences by commenting/updating a single thread.

## Prerequisites

- **Python**: Requires Python 3.8+ (The current local environment uses Python 3.14.2)
- **Redis Server**: Required for error deduplication caching and counter increments.

## Environment Variables

You must define the following environment variables before running the application:

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | Your OpenAI API Key for generating AI diagnostics. |
| `REDIS_URL` | Redis connection URL (e.g., `rediss://user:password@host:port`). Useful for managed services like Aiven. Overrides HOST/PORT if provided. |
| `REDIS_HOST` | Redis cache hostname (Defaults to `localhost`). Used if `REDIS_URL` is not set. |
| `REDIS_PORT` | Redis cache port (Defaults to `6379`). Used if `REDIS_URL` is not set. |
| `GITHUB_TOKEN` | Your GitHub Personal Access Token (PAT). |
| `GITHUB_REPO` | GitHub repository to post issues to (Format: `owner/repo`). |
| `GRAFANA_WEBHOOK_SECRET`| Secret expected in the `x-grafana-alert-id` header for authentication. |


## Installation & Setup

1. **Install dependencies**:
   Run the following command in the application directory:
   ```bash
   pip install '{dependency_name}'
   ```

2. **Ensure Redis is running**:
   Start a local Redis instance or configure `REDIS_HOST` and `REDIS_PORT` to point to a managed Redis cluster.

## Running the Application

To start the API gateway, use `uvicorn`:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Usage

Configure your Grafana alert webhook to POST to:
`http://<SERVER_HOST>:8000/api/v1/ai-webhook`

Ensure your webhook request contains the custom header:
`x-grafana-alert-id: <YOUR_GRAFANA_WEBHOOK_SECRET>`

The engine expects the following JSON payload structure:
```json
{
  "status": "firing",
  "title": "HTTP 5xx Error Spike Detected",
  "message": "SecureVault instance replica-a throwing NullPointerException.",
  "logs": "Caused by: java.lang.NullPointerException at SecurityFilter.java:42"
}
```