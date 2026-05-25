import os
import logging
import secrets
from fastapi import FastAPI, BackgroundTasks, HTTPException, Header, status
from pydantic import BaseModel, Field
from openai import OpenAI
import hashlib
import re
import requests
import redis 
from datetime import datetime
import json

# Initialize FastAPI app
app = FastAPI(title="SecureVault SRE AI Engine")

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SRE-AI-Engine")

# Grab Environment Configuration
AI_API_KEY = os.getenv("OPENAI_API_KEY")
AI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME")

redis_url = os.getenv("REDIS_URL")
if redis_url:
    cache = redis.from_url(redis_url, decode_responses=True)
else:
    cache = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True
    )

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO")

class GrafanaAlertPayload(BaseModel):
    status: str = Field(..., example="firing")
    title: str = Field(..., example="HTTP 5xx Error Spike Detected")
    message: str = Field(..., example="SecureVault instance replica-a throwing NullPointerException at core login filter.")
    logs: str = Field(default="No additional traceback available.", example="Caused by: java.lang.NullPointerException at SecurityFilter.java:42")



def generate_error_fingerprint(title: str, logs: str) -> str:
    """
    Scrubs dynamic runtime noise (timestamps, memory addresses) from 
    the raw error logs to generate a deterministic system signature.
    """
    # Regex out standard timestamps (e.g., 2026-05-25 13:58:21)
    scrubbed_logs = re.sub(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', logs)
    # Regex out hex memory pointer reference hashes (e.g., 0x7f98ab32)
    scrubbed_logs = re.sub(r'0x[0-9a-fA-F]+', '[MEM_ADDR]', scrubbed_logs)
    
    # Hash the normalized string signature
    raw_signature = f"{title}|||{scrubbed_logs}"
    return hashlib.sha256(raw_signature.encode('utf-8')).hexdigest()

def execute_intelligent_triage(alert: GrafanaAlertPayload):
    # 1. Compute the structural signature fingerprint
    error_hash = generate_error_fingerprint(alert.title, alert.logs)
    cache_key = f"incident:active:{error_hash}"
    existing_issue_id = cache.get(cache_key)
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    if existing_issue_id:
        try:
            comment_cache_key = f"incident:comment:{error_hash}"
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            existing_comment_meta = cache.get(comment_cache_key)
            
            if not existing_comment_meta:
                # First time seeing a duplicate! Create the single tracking comment.
                comment_url = f"https://api.github.com/repos/{GITHUB_REPO}/issues/{existing_issue_id}/comments"
                body_data = {
                    "body": f"🔄 **Deduplication Metrics**\n- **Total Occurrences:** `2`\n- **Last Detected Active:** `{current_time}`"
                }
                res = requests.post(comment_url, json=body_data, headers=headers)
                if res.status_code == 201:
                    comment_id = res.json().get("id")
                    # Save comment metadata: ID and set initial counter to 2
                    meta_payload = {"comment_id": comment_id, "count": 2}
                    cache.setex(comment_cache_key, 600, json.dumps(meta_payload))
                    logger.info("Initialized unified deduplication comment thread.")
            else:
                # Subsequent duplicates! Parse metadata, increment counter, and EDIT the comment.
                meta = json.loads(existing_comment_meta)
                target_comment_id = meta["comment_id"]
                new_count = meta["count"] + 1
            
                # Update GitHub in-place via PATCH request
                edit_url = f"https://api.github.com/repos/{GITHUB_REPO}/issues/comments/{target_comment_id}"
                updated_body = {
                    "body": f"🔄 **Deduplication Metrics**\n- **Total Occurrences:** `{new_count}`\n- **Last Detected Active:** `{current_time}`"
                }
                requests.patch(edit_url, json=updated_body, headers=headers)
            
                # Update local cache values with incremented metrics
                meta["count"] = new_count
                cache.setex(comment_cache_key, 600, json.dumps(meta))
                logger.info(f"In-place incremented duplicate metrics for comment #{target_comment_id}")
        except Exception as e:
            logger.error(f"Failed to update deduplication metrics: {str(e)}")
            
        return

    system_instruction = "You are an Elite Principal SRE." \
                        " Generate an Incident Triage Docket with Breakdown, Root Cause, and Runbook steps."\
                        " Strictly adhere to the provided alert details and logs. Do not hallucinate or fabricate information."\
                        " Your response should be in markdown format, suitable for direct posting to GitHub Issues."\
                        " Focus on technical precision and actionable insights for the engineering team."



    user_prompt = f"Title: {alert.title}\nMessage: {alert.message}\nLogs:\n{alert.logs}"
    
    try:
        ai_client = OpenAI(api_key=AI_API_KEY)
        completion = ai_client.chat.completions.create(
            model=AI_MODEL_NAME,
            messages=[{"role": "system", "content": system_instruction}, {"role": "user", "content": user_prompt}],
            temperature=0.1
        )
        ai_diagnostic_markdown = completion.choices[0].message.content
        
        # Build payload and ship to GitHub Issues API
        url = f"https://api.github.com/repos/{GITHUB_REPO}/issues"
        issue_data = {
            "title": f"🚨 [INCIDENT] {alert.title}",
            "body": f"### Fingerprint: `{error_hash}`\n\n{ai_diagnostic_markdown}",
            "labels": ["bug", "automated-triage"]
        }
        
        response = requests.post(url, json=issue_data, headers=headers)
        
        if response.status_code == 201:
            new_issue_id = response.json().get("number")
            # Cache the GitHub Issue ID with a 10-minute (600 seconds) cooling window
            cache.setex(cache_key, 600, str(new_issue_id))
            logger.info(f"New tracking issue #{new_issue_id} established and cached successfully.")
            
    except Exception as e:
        logger.error(f"SRE execution workflow failed: {str(e)}")




# 3. High-Throughput Edge Ingestion Webhook Gateway
@app.post("/api/v1/ai-webhook", status_code=status.HTTP_202_ACCEPTED)
async def receive_incident_alert(payload: GrafanaAlertPayload, 
                                 background_tasks: BackgroundTasks,
                                 x_grafana_alert_id: str = Header(None)
                                 ):
    """
    Ingests the telemetry metrics payload, validates data alignment against the schema contract,
    hands the workflow over to background thread pools, and instantly acknowledges with an HTTP 202.
    """
    expected_secret = os.getenv("GRAFANA_WEBHOOK_SECRET")
    
    # Fail-closed auth check using constant-time string comparison

    if not expected_secret or not x_grafana_alert_id or not secrets.compare_digest(x_grafana_alert_id, expected_secret):
        logger.warning("Received unauthorized webhook attempt with invalid or missing Grafana Alert ID.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Unauthorized: Invalid Grafana Alert ID."
        )
        
    # Defensive structural assertions
    if not AI_API_KEY or not GITHUB_TOKEN or not GITHUB_REPO:
        logger.critical("System misconfiguration: Environment secret parameters are missing.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Webhook server configuration failure."
        )
        
    # Dispatch execution work unit smoothly off the API worker threads
    background_tasks.add_task(execute_intelligent_triage, payload)
    
    # Instant non-blocking drop-back acknowledgement to the sender
    return {"status": "accepted", "message": "Incident payload queued for AI parsing."}

