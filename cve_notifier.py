import os
import sys
import json
import time
import html
import datetime
import argparse
import requests
import re

# Reconfigure stdout/stderr to use UTF-8 to prevent encoding errors on non-UTF-8 terminals (e.g., Windows cmd/powershell)
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    pass

# Constants
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"

SEVERITY_LEVELS = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def make_nvd_request(url, params, headers, max_retries=5):
    """
    Sends a GET request to the NVD API with exponential backoff retries.
    This is critical because the NVD API is prone to 503/403/429 errors.
    """
    delay = 10
    for attempt in range(max_retries):
        try:
            print(f"Querying NVD API (attempt {attempt + 1}/{max_retries})...")
            response = requests.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code in [403, 429, 503, 504]:
                print(f"Received status code {response.status_code}. Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2
            else:
                print(f"Error calling NVD API: {response.status_code} - {response.text}")
                response.raise_for_status()
        except requests.RequestException as e:
            print(f"Request exception: {e}. Retrying in {delay} seconds...")
            time.sleep(delay)
            delay *= 2
            
    raise Exception(f"Failed to fetch data from NVD API after {max_retries} attempts.")

def extract_cvss_info(cve_item):
    """
    Extracts CVSS score, severity, and version from a CVE item,
    preferring newer scoring systems (v4.0 -> v3.1 -> v3.0 -> v2.0).
    """
    metrics = cve_item.get("metrics", {})
    
    # CVSS V4.0
    if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
        metric = next((m for m in metrics["cvssMetricV40"] if m.get("type") == "Primary"), metrics["cvssMetricV40"][0])
        cvss_data = metric.get("cvssData", {})
        return cvss_data.get("baseScore"), cvss_data.get("baseSeverity", "UNKNOWN"), "CVSS v4.0"
        
    # CVSS V3.1
    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        metric = next((m for m in metrics["cvssMetricV31"] if m.get("type") == "Primary"), metrics["cvssMetricV31"][0])
        cvss_data = metric.get("cvssData", {})
        return cvss_data.get("baseScore"), cvss_data.get("baseSeverity", "UNKNOWN"), "CVSS v3.1"
        
    # CVSS V3.0
    if "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        metric = next((m for m in metrics["cvssMetricV30"] if m.get("type") == "Primary"), metrics["cvssMetricV30"][0])
        cvss_data = metric.get("cvssData", {})
        return cvss_data.get("baseScore"), cvss_data.get("baseSeverity", "UNKNOWN"), "CVSS v3.0"
        
    # CVSS V2.0
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        metric = next((m for m in metrics["cvssMetricV2"] if m.get("type") == "Primary"), metrics["cvssMetricV2"][0])
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = metric.get("baseSeverity", "UNKNOWN")
        if severity == "UNKNOWN" and score is not None:
            # Map legacy CVSS v2 score to general severity
            if score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        return score, severity, "CVSS v2.0"
        
    return None, "AWAITING_ANALYSIS", "N/A"

def format_message(cve_id, score, severity, version, published, description, references, old_severity=None):
    """
    Formats the CVE data into a clean, safe HTML message for Telegram.
    Supports highlighting severity updates (e.g. from AWAITING_ANALYSIS to HIGH).
    """
    # Escape dynamic text to prevent HTML formatting syntax crashes on Telegram
    escaped_cve_id = html.escape(cve_id)
    escaped_pub = html.escape(published)
    
    escaped_desc = html.escape(description)
    if len(escaped_desc) > 500:
        escaped_desc = escaped_desc[:500] + "..."
        
    score_str = f"{score} ({severity})" if score is not None else f"{severity}"
    version_str = f" [{version}]" if version and version != "N/A" else ""
    
    # Custom header depending on whether it's a new CVE or a severity upgrade
    if old_severity:
        escaped_old = html.escape(old_severity)
        header = f"<b>🔄 Actualización de CVE: {escaped_cve_id}</b>\n(Severidad cambió de <i>{escaped_old}</i> a <i>{score_str}</i>)\n\n"
    else:
        header = f"<b>🚨 Nuevo CVE Detectado: {escaped_cve_id}</b>\n\n"
        
    msg = (
        f"{header}"
        f"<b>• Severidad:</b> {score_str}{version_str}\n"
        f"<b>• Publicado:</b> {escaped_pub}\n\n"
        f"<b>Descripción:</b>\n"
        f"<i>{escaped_desc}</i>\n"
    )
    
    # Process reference URLs (limit to top 2 to keep message concise)
    ref_links = []
    for ref in references[:2]:
        url = ref.get("url")
        if url:
            ref_links.append(f"<a href=\"{html.escape(url)}\">Referencia</a>")
            
    ref_str = " | ".join(ref_links)
    if ref_str:
        msg += f"\n<b>Enlaces:</b> {ref_str}"
        
    # Always include a link back to NVD
    msg += f"\n\n<a href=\"https://nvd.nist.gov/vuln/detail/{escaped_cve_id}\">🔗 Ver Detalles Completos en NVD</a>"
    return msg

def send_telegram_message(token, chat_id, message):
    """
    Sends an HTML message to the specified Telegram Chat ID.
    Supports simple retries and handles rate limits (HTTP 429).
    """
    url = TELEGRAM_API_URL.format(token=token)
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": False
    }
    
    for attempt in range(3):
        try:
            # Using JSON payload to avoid url-encoding complications with HTML brackets
            response = requests.post(url, json=payload, timeout=15)
            if response.status_code == 200:
                return True
            elif response.status_code == 429:
                retry_after = response.json().get("parameters", {}).get("retry_after", 5)
                print(f"Telegram rate limit hit. Waiting {retry_after} seconds...")
                time.sleep(retry_after)
            else:
                # No registrar el cuerpo completo de la respuesta para evitar exponer datos innecesarios.
                print(f"Telegram returned status code {response.status_code}.")
                return False
        except requests.RequestException as e:
            # No imprimir la excepción completa: puede incluir la URL con el token del bot.
            print(f"Telegram request exception ({type(e).__name__}).")
            time.sleep(2)
            
    return False

def load_keywords(keywords_file="keywords.json"):
    """
    Loads list of include and exclude keywords from a JSON file.
    All keywords are converted to lowercase.
    """
    if not os.path.exists(keywords_file):
        return None, None
        
    try:
        with open(keywords_file, "r") as f:
            data = json.load(f)
        include = [k.lower() for k in data.get("include", []) if k.strip()]
        exclude = [k.lower() for k in data.get("exclude", []) if k.strip()]
        return include or None, exclude or None
    except Exception as e:
        print(f"Warning: Could not parse {keywords_file}: {e}")
        return None, None

def match_keywords(cve_item, include_keywords, exclude_keywords):
    """
    Checks if a CVE matches include_keywords and does not match exclude_keywords.
    Searches in descriptions and CPE criteria.
    """
    if not include_keywords and not exclude_keywords:
        return True

    cve = cve_item.get("cve", {})
    
    # Collect all searchable text from this CVE
    search_texts = []
    
    # Descriptions
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        val = desc.get("value")
        if val:
            search_texts.append(val.lower())
            
    # CPE Criteria (vendor and product details)
    configurations = cve.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                criteria = match.get("criteria")
                if criteria:
                    search_texts.append(criteria.lower())
                    
    combined_text = " | ".join(search_texts)
    
    def match_keyword(kw, text):
        pattern = rf"(?:^|[^a-zA-Z0-9]){re.escape(kw)}(?:$|[^a-zA-Z0-9])"
        return bool(re.search(pattern, text, re.IGNORECASE))

    # Check Exclusions first
    if exclude_keywords:
        for kw in exclude_keywords:
            if match_keyword(kw, combined_text):
                return False
                
    # Check Inclusions
    if include_keywords:
        for kw in include_keywords:
            if match_keyword(kw, combined_text):
                return True
        return False
        
    return True

def main():
    parser = argparse.ArgumentParser(description="Fetch recent modified CVEs and notify a Telegram Channel/Group.")
    parser.add_argument("--state-file", default="state.json", help="Path to state persistence JSON file.")
    parser.add_argument("--hours", type=int, help="Override state and fetch CVEs modified in the last N hours.")
    parser.add_argument("--dry-run", action="store_true", help="Print messages to stdout without sending to Telegram or updating state.")
    args = parser.parse_args()

    # Load configuration from environment variables
    telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    nvd_api_key = os.environ.get("NVD_API_KEY")
    min_severity = os.environ.get("MIN_SEVERITY", "MEDIUM").upper()
    report_unscored_str = os.environ.get("REPORT_UNSCORED", "true").lower()
    report_unscored = report_unscored_str in ["true", "1", "yes"]
    max_age_days_str = os.environ.get("MAX_PUBLISHED_AGE_DAYS", "14")
    try:
        max_age_days = int(max_age_days_str)
    except ValueError:
        max_age_days = 14

    # Load keywords filter
    include_keywords, exclude_keywords = load_keywords()
    if include_keywords or exclude_keywords:
        print(f"Loaded keywords filter: Include={include_keywords}, Exclude={exclude_keywords}")
    else:
        print("No keywords filter loaded. Processing all CVEs.")

    if not args.dry_run and (not telegram_token or not telegram_chat_id):
        print("Error: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required unless --dry-run is set.")
        sys.exit(1)

    # 1. Determine time window
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    pub_end_date = now_utc.strftime("%Y-%m-%dT%H:%M:%S.000")

    sent_cves = {}

    if args.hours:
        start_dt = now_utc - datetime.timedelta(hours=args.hours)
        pub_start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        print(f"Using manual time window: {pub_start_date} to {pub_end_date} (last {args.hours} hours)")
        # Load cache if file exists to avoid spamming updates during override run
        if os.path.exists(args.state_file):
            try:
                with open(args.state_file, "r") as f:
                    state_data = json.load(f)
                sent_cves = state_data.get("sent_cves", {})
                print(f"Loaded {len(sent_cves)} CVEs from sent cache.")
            except Exception:
                pass
    else:
        # Load last run and cache from state file
        if os.path.exists(args.state_file):
            try:
                with open(args.state_file, "r") as f:
                    state_data = json.load(f)
                pub_start_date = state_data.get("last_run_timestamp")
                sent_cves = state_data.get("sent_cves", {})
                if not pub_start_date:
                    raise ValueError("last_run_timestamp missing in state file")
                print(f"Found existing state. Checking updates since: {pub_start_date}")
                print(f"Loaded {len(sent_cves)} CVEs from sent cache.")
            except Exception as e:
                print(f"Warning: Could not parse state file ({e}). Defaulting to last 24 hours.")
                start_dt = now_utc - datetime.timedelta(hours=24)
                pub_start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        else:
            print("No state file found. Defaulting to last 24 hours.")
            start_dt = now_utc - datetime.timedelta(hours=24)
            pub_start_date = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    # 2. Fetch CVEs from NVD API v2 using lastModStartDate/lastModEndDate
    params = {
        "lastModStartDate": pub_start_date,
        "lastModEndDate": pub_end_date,
        "resultsPerPage": 2000,
        "startIndex": 0
    }
    
    headers = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key
        print("Using NVD API Key for query.")
    else:
        print("No NVD API Key detected. Using rate-limited access.")

    all_vulnerabilities = []
    
    while True:
        try:
            data = make_nvd_request(NVD_API_URL, params, headers)
        except Exception as e:
            print(f"Fatal error fetching from NVD API: {e}")
            sys.exit(1)
            
        vulns = data.get("vulnerabilities", [])
        all_vulnerabilities.extend(vulns)
        
        total_results = data.get("totalResults", 0)
        start_index = data.get("startIndex", 0)
        results_per_page = data.get("resultsPerPage", 0)
        
        print(f"Retrieved {len(vulns)} CVEs (Total results: {total_results}).")
        
        if start_index + results_per_page >= total_results or results_per_page == 0:
            break
            
        params["startIndex"] = start_index + results_per_page
        # Add a safety sleep between page requests to avoid hitting rate limits
        time.sleep(6 if not nvd_api_key else 1)

    print(f"Total CVEs collected: {len(all_vulnerabilities)}")

    # 3. Process and filter CVEs
    sent_count = 0
    skipped_count = 0
    
    # Sort CVEs chronologically by last modified date so notifications flow in order
    all_vulnerabilities.sort(key=lambda x: x.get("cve", {}).get("lastModified", ""))

    for item in all_vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        published = cve.get("published")
        vuln_status = cve.get("vulnStatus", "").upper()
        
        # Skip rejected CVEs to avoid spamming
        if vuln_status == "REJECTED":
            skipped_count += 1
            continue

        # Check publication age to filter out modifications of old CVEs (e.g. from months/years ago)
        try:
            pub_date_str = published.split(".")[0]
            pub_dt = datetime.datetime.strptime(pub_date_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
            age_days = (now_utc - pub_dt).days
            if age_days > max_age_days:
                skipped_count += 1
                continue
        except Exception as e:
            print(f"Warning: Could not parse publication date '{published}' for {cve_id}: {e}")

        # Extract CVSS details
        score, severity, version = extract_cvss_info(cve)
        cve_severity = severity.upper()

        # Check keyword inclusion and exclusion filters
        if not match_keywords(item, include_keywords, exclude_keywords):
            sent_cves[cve_id] = {
                "severity": cve_severity,
                "published": published
            }
            skipped_count += 1
            continue

        # Check if we've already notified about this CVE
        is_new = cve_id not in sent_cves
        old_severity = None
        
        if not is_new:
            old_cve_info = sent_cves[cve_id]
            # Handle legacy string format or dictionary format
            if isinstance(old_cve_info, dict):
                old_severity = old_cve_info.get("severity", "UNKNOWN").upper()
            else:
                old_severity = str(old_cve_info).upper()
            
            if old_severity == cve_severity:
                # Severity hasn't changed, skip this update (prevent duplicate spam)
                skipped_count += 1
                continue
            else:
                print(f"CVE {cve_id} modified: severity changed from {old_severity} to {cve_severity}.")

        # Check filters
        should_report = True
        
        if cve_severity in ["AWAITING_ANALYSIS", "UNKNOWN"]:
            if not report_unscored:
                should_report = False
        else:
            cve_level = SEVERITY_LEVELS.get(cve_severity, 0)
            min_level = SEVERITY_LEVELS.get(min_severity, 2)  # Default to MEDIUM (2)
            if cve_level < min_level:
                should_report = False

        # If it should be skipped, we still save its state (so we don't evaluate it again unless it changes again)
        if not should_report:
            sent_cves[cve_id] = {
                "severity": cve_severity,
                "published": published
            }
            skipped_count += 1
            continue

        # Find English description
        descriptions = cve.get("descriptions", [])
        description = "No description available."
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value")
                break

        references = cve.get("references", [])

        # Format and send message
        message = format_message(cve_id, score, severity, version, published, description, references, old_severity if not is_new else None)
        
        if args.dry_run:
            print("\n" + "="*40 + f" DRY RUN: MESSAGE FOR {cve_id} " + "="*40)
            print(message)
            print("="*100)
            sent_count += 1
            sent_cves[cve_id] = {
                "severity": cve_severity,
                "published": published
            }
        else:
            print(f"Sending notification for {cve_id}...")
            success = send_telegram_message(telegram_token, telegram_chat_id, message)
            if success:
                sent_count += 1
                sent_cves[cve_id] = {
                    "severity": cve_severity,
                    "published": published
                }
                # Respect Telegram rate limits
                time.sleep(1.0)
            else:
                print(f"Failed to send notification for {cve_id}. Skipping this notification to prevent blocking.")
                skipped_count += 1

    print(f"Execution finished. Sent: {sent_count}, Skipped: {skipped_count}.")

    # 4. Prune cache and save state if not dry-run
    if not args.dry_run:
        try:
            # Keep only CVEs published in the last 30 days to avoid infinite file growth
            thirty_days_ago = (now_utc - datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
            pruned_sent_cves = {}
            for cid, info in sent_cves.items():
                pub_date = ""
                if isinstance(info, dict):
                    pub_date = info.get("published", "")
                
                # If publication date is missing (legacy entry) or newer than 30 days, retain it
                if not pub_date or pub_date > thirty_days_ago:
                    pruned_sent_cves[cid] = info
            
            print(f"Pruned sent cache from {len(sent_cves)} to {len(pruned_sent_cves)} items (removed older than 30 days).")

            state_data = {
                "last_run_timestamp": pub_end_date,
                "sent_cves": pruned_sent_cves
            }
            with open(args.state_file, "w") as f:
                json.dump(state_data, f, indent=2)
            print(f"Updated state file {args.state_file} with timestamp {pub_end_date}.")
        except Exception as e:
            print(f"Error updating state file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
