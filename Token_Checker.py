"""
Token_Checker.py
Analyzes cryptocurrency tokens using Honeypot/QuickIntel APIs and stores results in Supabase.
Implements robust error handling, metrics, and retry logic.
Supports processing of tokens on various blockchains, checking for security vulnerabilities and compliance.
Includes checks for honeypots, tax rates, contract audits, and scam history (configurable for specific chains).
Extracts function names related to potential risks and categorizes contract-related links.
"""

import json
import os
import re
import time
import logging
import signal
import atexit
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone

# Environment variable handling
from dotenv import load_dotenv

import requests
from http.cookiejar import MozillaCookieJar
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import pybreaker
from prometheus_client import start_http_server, Counter, Histogram
from tenacity import retry, stop_after_attempt, wait_exponential
from requests.exceptions import HTTPError

# Supabase integration
from supabase import create_client, Client

# ------------------------------------------------------------------------------
# Load environment variables
# ------------------------------------------------------------------------------
load_dotenv()

SUPABASE_URL: str = os.getenv("SUPABASE_URL")
SUPABASE_KEY: str = os.getenv("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    logging.critical("Missing Supabase credentials in .env")
    exit(1)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

if supabase:
    logging.info("Supabase client initialized.")
else:
    logging.critical("Failed to initialize Supabase client.")
    exit(1)

# ------------------------------------------------------------------------------
# Prometheus Metrics Configuration
# ------------------------------------------------------------------------------
GET_REQUEST_COUNTER: Counter = Counter(
    "api_get_requests_total", "Total GET API requests", ["endpoint", "chain"]
)
POST_REQUEST_COUNTER: Counter = Counter(
    "api_post_requests_total", "Total POST API requests", ["endpoint", "chain"]
)
API_ERROR_COUNTER: Counter = Counter(
    "api_errors_total", "Total API errors", ["endpoint", "chain"]
)
GET_REQUEST_DURATION: Histogram = Histogram(
    "api_get_request_duration_seconds", "GET API request duration", ["endpoint", "chain"]
)
POST_REQUEST_DURATION: Histogram = Histogram(
    "api_post_request_duration_seconds", "POST API request duration", ["endpoint", "chain"]
)
SUPABASE_REQUEST_COUNTER: Counter = Counter(
    "supabase_requests_total", "Total Supabase requests", ["operation"]
)
SUPABASE_ERROR_COUNTER: Counter = Counter(
    "supabase_errors_total", "Total Supabase errors", ["operation"]
)

# ------------------------------------------------------------------------------
# Logging Configuration
# ------------------------------------------------------------------------------
LOG_FILENAME: str = "app.log"
logger: logging.Logger = logging.getLogger("TokenProcessor")
logger.setLevel(logging.DEBUG)

handler = RotatingFileHandler(LOG_FILENAME, maxBytes=10*1024*1024, backupCount=5)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# ------------------------------------------------------------------------------
# Configuration Constants
# ------------------------------------------------------------------------------
CONFIG_FILE: str = "quick_intel_config.json"
COOKIE_FILE: str = "cookies.txt"
QUICKINTEL_API_TIMEOUT_SECONDS: int = 60

# API Endpoints
HONEYPOT_CV_URL: str = "https://api.honeypot.is/v2/GetContractVerification"
HONEYPOT_IH_URL: str = "https://api.honeypot.is/v2/IsHoneypot"
QUICKINTEL_API_URL: str = "https://app.quickintel.io/api/quicki/getquickiauditfull"

# Chain Configuration
USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"
HONEYPOT_CHAINS: set = {"eth", "bsc", "base"}
QUICKINTEL_SUPPORTED_CHAINS: set = {
    "abstract", "ink", "berachain", "eth", "base", "bsc", "solana",
    "avalanche", "cronos", "injective", "pulse", "sonic", "sui",
    "tron", "unichain", "zora"
}
SCAM_CHECK_CHAINS: set = {"eth", "base"}

# Retry/Circuit Breaker Settings
RETRY_ATTEMPTS: int = 3
RETRY_DELAY: int = 3
breaker_get = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)
breaker_post = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)
last_breaker_reset = time.time()
BREAKER_RESET_INTERVAL = 300  # 5 minutes

# Special Cases
PUMPFUN_UPDATE_AUTHORITY: str = "TSLvdd1pWpHVjahSpsvCXUbgwsL3JAcvokwaKt1eokM"

# Supabase Configuration
TOKENS_TO_CHECK_TABLE: str = "tokens_to_check"
TOKEN_CHECKS_TABLE: str = "token_checks"
CHECK_INTERVAL_SECONDS: int = 5
RETRY_INTERVAL_1_SECONDS: int = 5 * 60
RETRY_INTERVAL_2_SECONDS: int = 15 * 60
MAX_RETRIES: int = 1

# Global State
shutdown_flag = False

# ------------------------------------------------------------------------------
# Core Functions
# ------------------------------------------------------------------------------
def validate_supabase_connection() -> None:
    """Validates Supabase connection."""
    try:
        response = supabase.table(TOKENS_TO_CHECK_TABLE).select("count", count="exact").execute()
        if response.count >= 0:
            logger.info("Supabase connection validated.")
        else:
            raise ConnectionError("Invalid Supabase response")
    except Exception as e:
        logger.critical(f"Supabase connection failed: {e}")
        exit(1)

def handle_signal(signum, frame):
    """Handles shutdown signals for graceful termination."""
    global shutdown_flag
    shutdown_flag = True
    logger.info("Shutdown signal received. Finishing current work...")

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

def cleanup():
    """Cleans up resources before exiting."""
    if supabase:
        supabase.auth.sign_out()
    logger.info("Cleanup completed.")

atexit.register(cleanup)

def load_config() -> Dict[str, Any]:
    """Loads QuickIntel API configuration from JSON file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config: Dict[str, Any] = json.load(f)
        if not all(k in config for k in ("user_address", "tier")):
            raise ValueError("Missing required fields in config.json")
        return config
    except FileNotFoundError as e:
        logger.critical(f"Config file {CONFIG_FILE} not found: {e}")
        raise
    except json.JSONDecodeError as e:
        logger.critical(f"Invalid JSON format in {CONFIG_FILE}: {e}")
        raise
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {e}")
        raise

def configure_session() -> Session:
    """Configures requests Session with retry logic and cookie handling."""
    session: Session = Session()
    retries = Retry(
        total=RETRY_ATTEMPTS,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))

    cookie_jar = MozillaCookieJar(COOKIE_FILE)
    if os.path.exists(COOKIE_FILE):
        cookie_jar.load(ignore_discard=True, ignore_expires=True)
    session.cookies = cookie_jar
    return session

def get_headers() -> Dict[str, str]:
    """Generates request headers for QuickIntel API calls."""
    return {
        "User-Agent": USER_AGENT,
        "Accept": "/",
        "Referer": "https://app.quickintel.io/scanner",
        "Content-Type": "text/plain;charset=UTF-8",
        "Origin": "https://app.quickintel.io",
        "DNT": "1",
        "Sec-GPC": "1",
        "Priority": "u=0",
    }

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def api_get_with_retries(url: str, params: Dict[str, Any], chain: str, timeout: int = 30) -> Optional[Any]:
    """Performs a GET request with retry and circuit breaker."""
    GET_REQUEST_COUNTER.labels(endpoint=url, chain=chain).inc()
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with GET_REQUEST_DURATION.labels(endpoint=url, chain=chain).time():
                response = breaker_get.call(
                    requests.get, url, params=params, timeout=timeout
                )
                response.raise_for_status()
                return response.json()
        except HTTPError as e:
            API_ERROR_COUNTER.labels(endpoint=url, chain=chain).inc()
            if e.response.status_code == 404:
                logger.warning(f"Honeypot API 404 for {url} (token: {params.get('address')}, chain: {chain})")
            else:
                logger.error(f"Error on GET {url} attempt {attempt+1}: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))
        except Exception as e:
            API_ERROR_COUNTER.labels(endpoint=url, chain=chain).inc()
            logger.error(f"Error on GET {url} attempt {attempt+1}: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def api_post_with_retries(
    url: str, headers: Dict[str, str], data: str, session: Session, chain: str, timeout: int = 30
) -> Optional[Any]:
    """Performs a POST request with retry and circuit breaker."""
    POST_REQUEST_COUNTER.labels(endpoint=url, chain=chain).inc()
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with POST_REQUEST_DURATION.labels(endpoint=url, chain=chain).time():
                response = breaker_post.call(
                    session.post, url, headers=headers, data=data, timeout=timeout
                )
                response.raise_for_status()
                session.cookies.save(ignore_discard=True, ignore_expires=True)
                return response.json()
        except Exception as e:
            API_ERROR_COUNTER.labels(endpoint=url, chain=chain).inc()
            logger.error(f"Error on POST {url} attempt {attempt+1}: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

def extract_function_names(func_list: Optional[List[Any]]) -> List[str]:
    """Extracts function names from a list of Solidity function strings."""
    names: List[str] = []
    if func_list and isinstance(func_list, list):
        for func in func_list:
            match = re.search(r"function\s+([^(]+)\(", func)
            if match:
                names.append(match.group(1).strip())
    return names

def apply_special_cases(
    quickintel_result: Dict[str, Any], chain: str, raw_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Applies chain-specific special case rules to QuickIntel results."""
    quickintel_result["specialCaseMessage"] = None # Initialize specialCaseMessage

    # Pump.Fun special case
    if chain == "solana":
        audit: Dict[str, Any] = raw_data.get("quickiAudit") or {}
        authorities: Dict[str, Any] = audit.get("authorities") or {}
        if authorities.get("update_Authority") == PUMPFUN_UPDATE_AUTHORITY:
            quickintel_result.update({
                "specialCase": "pumpFun",
                "status": "good",
                "message": "Passed Pump.Fun special case",
                "findings": []
            })
            quickintel_result["specialCaseMessage"] = "pumpFun token"

    # Base Bankr special case
    if chain == "base":
        audit: Dict[str, Any] = raw_data.get("quickiAudit") or {}
        contract_creator = audit.get("contract_Creator", "")
        contract_name = audit.get("contract_Name", "")
        if contract_creator == "0x002f07b0d63e8ac14f8ef6b73ccd8caf1fef074c" or contract_name == "ClankerToken":
            quickintel_result.update({
                "specialCase": "baseBankr",
                "status": "good",
                "message": "Passed Base Bankr special case",
                "findings": []
            })
            quickintel_result["specialCaseMessage"] = "baseBankr token"

    # Moonshot special case
    if chain in {"base", "abstract"}:
        audit: Dict[str, Any] = raw_data.get("quickiAudit") or {}
        contract_name = audit.get("contract_Name", "")
        token_details: Dict[str, Any] = raw_data.get("tokenDetails") or {}
        token_logo = str(token_details.get("tokenLogo", ""))
        if contract_name == "MoonshotToken" and token_logo.startswith("https://cdn.dexscreener.com/"):
            quickintel_result.update({
                "specialCase": "moonshot",
                "status": "good",
                "message": "Passed Moonshot special case",
                "findings": []
            })
            quickintel_result["specialCaseMessage"] = "moonshot token"

    return quickintel_result

# ------------------------------------------------------------------------------
# Supabase Operations
# ------------------------------------------------------------------------------
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def fetch_tokens_for_processing_from_supabase() -> List[Dict[str, Any]]:
    """Fetches tokens for processing from Supabase."""
    logger.info("Fetching tokens for processing from Supabase...")
    try:
        SUPABASE_REQUEST_COUNTER.labels(operation="select_tokens_for_processing").inc()
        response = supabase.table(TOKENS_TO_CHECK_TABLE).select("*").in_("status", ["unchecked", "undetermined"]).execute()
        if response.data is None:
            SUPABASE_ERROR_COUNTER.labels(operation="select_tokens_for_processing").inc()
            logger.error(f"Supabase query error: {response.error}")
            return []
        return response.data
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="select_tokens_for_processing").inc()
        logger.error(f"Error fetching tokens: {e}")
        return []

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def update_token_status_to_checked(token_address: str, chain: str) -> bool:
    """Updates token status to 'checked' in Supabase."""
    logger.info(f"Updating {token_address} on {chain} to checked")
    try:
        SUPABASE_REQUEST_COUNTER.labels(operation="update_token_status_checked").inc()
        response = supabase.table(TOKENS_TO_CHECK_TABLE).update(
            {"status": "checked", "last_checked": "now()"}
        ).eq("token_address", token_address).eq("chain", chain).execute()
        return response.data is not None
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="update_token_status_checked").inc()
        logger.error(f"Update failed: {e}")
        return False

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def update_token_status_to_undetermined(token_address: str, chain: str, retry_count: int) -> bool:
    """Updates token status to 'undetermined' and increments retry count."""
    logger.info(f"Marking {token_address} on {chain} as undetermined (retry {retry_count})")
    try:
        SUPABASE_REQUEST_COUNTER.labels(operation="update_token_status_undetermined").inc()
        response = supabase.table(TOKENS_TO_CHECK_TABLE).update({
            "status": "undetermined",
            "retry_count": retry_count,
            "last_retry_timestamp": "now()"
        }).eq("token_address", token_address).eq("chain", chain).execute()
        return response.data is not None
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="update_token_status_undetermined").inc()
        logger.error(f"Update failed: {e}")
        return False

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def update_token_status_to_bad(token_address: str, chain: str) -> bool:
    """Updates token status to 'bad'."""
    logger.info(f"Marking {token_address} on {chain} as bad")
    try:
        SUPABASE_REQUEST_COUNTER.labels(operation="update_token_status_bad").inc()
        response = supabase.table(TOKENS_TO_CHECK_TABLE).update({
            "status": "bad",
            "last_checked": "now()"
        }).eq("token_address", token_address).eq("chain", chain).execute()
        return response.data is not None
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="update_token_status_bad").inc()
        logger.error(f"Update failed: {e}")
        return False

# ------------------------------------------------------------------------------
# Token Processing
# ------------------------------------------------------------------------------
def process_honeypot(token_address: str, chain: str) -> Dict[str, Any]:
    """Analyzes token for honeypot characteristics using Honeypot APIs."""
    result: Dict[str, Any] = {}
    params = {"address": token_address}

    # Contract Verification check
    cv = api_get_with_retries(HONEYPOT_CV_URL, params, chain)
    cv_valid = (
        cv.get("isRootOpenSource") is True
        and cv.get("summary", {}).get("hasProxyCalls") is False
        and cv.get("summary", {}).get("isOpenSource") is True
    ) if cv else False
    result["ContractVerification"] = {
        "valid": cv_valid,
        "message": "Verified" if cv_valid else "Verification failed"
    }

    # Honeypot check
    ih = api_get_with_retries(HONEYPOT_IH_URL, params, chain)
    if ih:
        holder_analysis = ih.get("holderAnalysis", {})
        siphoned = int(holder_analysis.get("siphoned", "0") or 0)
        ih_valid = (
            ih.get("honeypotResult", {}).get("isHoneypot") is False
            and siphoned == 0
            and ih.get("simulationSuccess") is True
            and not ih.get("summary", {}).get("flags", [])
        )
        result["IsHoneypot"] = {
            "valid": ih_valid,
            "message": "Clean" if ih_valid else "Potential honeypot"
        }
    else:
        result["IsHoneypot"] = {"valid": False, "message": "No response"}

    result["status"] = "good" if all([
        result["ContractVerification"]["valid"],
        result["IsHoneypot"]["valid"]
    ]) else "bad"

    return result

def process_quickintel(
    token_address: str, chain: str, config: Dict[str, Any], session: Session
) -> Dict[str, Any]:
    """Processes token analysis using QuickIntel API."""
    payload = json.dumps({
        "chain": chain,
        "tokenAddress": token_address,
        "userAddress": config["user_address"],
        "tier": config["tier"]
    })

    data = api_post_with_retries(
        QUICKINTEL_API_URL,
        get_headers(),
        payload,
        session,
        chain,
        timeout=QUICKINTEL_API_TIMEOUT_SECONDS
    )

    if not data:
        return {
            "status": "failed",
            "message": "API request failed",
            "findings": []
        }

    # Initialize results
    result = {
        "tokenDetails": {},
        "taxes": {},
        "status": "good",
        "findings": [],
        "contractLinks": [],
        "extractedFunctions": {}
    }

    # Process token details
    token_details = data.get("tokenDetails", {})
    result["tokenDetails"] = {
        "name": token_details.get("tokenName"),
        "symbol": token_details.get("tokenSymbol"),
        "supply": token_details.get("tokenSupply"),
        "owner": token_details.get("tokenOwner")
    }

    # Check root-level critical fields
    root_critical_fields = {
        "isAirdropPhishingScam": (False, "Phishing scam detected"),
        "contractVerified": (True, "Unverified contract")
    }

    for field, (expected, msg) in root_critical_fields.items():
        value = data.get(field)
        if value is None:
            result["findings"].append(f"Missing {field} data")
            result["status"] = "undetermined"
        elif value != expected:
            result["findings"].append(msg)
            result["status"] = "bad"

    # Process dynamic details and tax checks
    dyn = data.get("tokenDynamicDetails", {})
    dyn_findings: List[str] = []
    tax_valid: bool = True

    try:
        buy_tax: float = float(dyn.get("buy_Tax") or 0)
        sell_tax: float = float(dyn.get("sell_Tax") or 0)
        transfer_tax: float = float(dyn.get("transfer_Tax") or 0)
    except (ValueError, TypeError):
        buy_tax = sell_tax = transfer_tax = 0

    if dyn.get("is_Honeypot") is not False:
        dyn_findings.append("Dynamic Details: is_Honeypot is not False")
        result["status"] = "bad"

    if buy_tax > 5:
        dyn_findings.append("Dynamic Details: buy_Tax exceeds 5%")
        tax_valid = False
    if sell_tax > 5:
        dyn_findings.append("Dynamic Details: sell_Tax exceeds 5%")
        tax_valid = False
    if transfer_tax > 5:
        dyn_findings.append("Dynamic Details: transfer_Tax exceeds 5%")
        tax_valid = False

    if not tax_valid:
        result["status"] = "bad"

    result["taxes"] = {
        "buy": buy_tax,
        "sell": sell_tax,
        "transfer": transfer_tax
    }
    result["findings"].extend(dyn_findings)

    # Process audit data and audit checks
    audit = data.get("quickiAudit", {})
    audit_checks = {
        "contract_Renounced": (True, "Contract not renounced"),
        "hidden_Owner": (False, "Hidden owner detected"),
        "is_Proxy": (False, "Proxy contract detected")
    }

    for field, (expected, msg) in audit_checks.items():
        value = audit.get(field)
        if value is None:
            result["findings"].append(f"Missing {field} data")
            result["status"] = "undetermined"
        elif value != expected:
            result["findings"].append(msg)
            result["status"] = "bad"

    # Scam history checks (for configurable chains)
    if chain in SCAM_CHECK_CHAINS:
        if "has_Scams" not in audit:
            result["findings"].append("Audit: Validation passed for has_Scams due to missing data from API.")
        elif audit.get("has_Scams") is not False:
            result["findings"].append("Audit: has_Scams is not False")

        if "has_Known_Scam_Wallet_Funding" not in audit:
            result["findings"].append("Audit: Validation passed for has_Known_Scam_Wallet_Funding due to missing data from API.")
        elif audit.get("has_Known_Scam_Wallet_Funding") is not False:
            result["findings"].append("Audit: has_Known_Scam_Wallet_Funding is not False")

    # Function name extraction for risk functions
    functions_to_extract: List[str] = [
        "modified_Transfer_Functions",
        "suspicious_Functions",
        "external_Functions",
        "fee_Update_Functions",
        "can_Potentially_Steal_Funds_Functions",
        "blacklistFunctionsRan",
    ]
    extracted_functions: Dict[str, List[str]] = {}
    for key in functions_to_extract:
        func_list = audit.get(key)
        extracted_functions[key] = extract_function_names(func_list)

    # Extract all contract functions from 'functions' field
    functions_list = audit.get("functions")
    if isinstance(functions_list, list):
        extracted_functions["contract_functions"] = functions_list
    else:
       # logger.warning(f"Unexpected data type for 'functions' field in QuickIntel API response. Expected list, got: {type(functions_list)}")
        extracted_functions["contract_functions"] = []

    result["extractedFunctions"] = extracted_functions

    # Contract link categorization
    links: List[Any] = audit.get("contract_Links") or []
    categorized_links: Dict[str, List[str]] = {
        "Telegram": [],
        "Twitter": [],
        "Website": [],
        "Other Links": [],
    }
    for url in links:
        if isinstance(url, str):
            if url.startswith("https://t.me/"):
                categorized_links["Telegram"].append(url)
            elif url.startswith("https://x.com/"):
                categorized_links["Twitter"].append(url)
            elif url.startswith("https://"):
                categorized_links["Website"].append(url)
            else:
                categorized_links["Other Links"].append(url)

    result["contractLinks"] = categorized_links

    # Apply special cases before final status determination
    result = apply_special_cases(result, chain, data)

    # Special case override
    if result.get("specialCase"):
        result["status"] = "good"
        result["findings"] = []

    return result

def process_token(token: Dict[str, Any], config: Dict[str, Any], session: Session) -> Dict[str, Any]:
    """Processes a single token by performing honeypot and QuickIntel analysis."""
    token_address = token.get("token_address", "")
    chain = token.get("chain", "").lower()
    retry_count = token.get("retry_count", 0)
    result = {
        "address": token_address,
        "chain": chain,
        "status": "unprocessed",
        "honeypot": {},
        "quickintel": {},
        "errors": []
    }

    try:
        # Honeypot Check Block
        if chain in HONEYPOT_CHAINS:
            honeypot_result = process_honeypot(token_address, chain)
        else:
            honeypot_result = {
                "status": "not_applicable",
                "message": f"Honeypot check not supported for {chain}"
            }
        result["honeypot"] = honeypot_result

        # QuickIntel Processing
        if chain in QUICKINTEL_SUPPORTED_CHAINS:
            quickintel_result = process_quickintel(token_address, chain, config, session)
        else:
            quickintel_result = {
                "status": "not_supported",
                "message": f"QuickIntel API does not support chain: {chain}",
                "findings": [],
                "extractedFunctions": {},
                "contractLinks": []
            }
        result["quickintel"] = quickintel_result

        # Determine final status with priority
        if quickintel_result["status"] == "failed":
            final_status = "bad"
        elif honeypot_result.get("status") == "bad":
            final_status = "bad"
        elif quickintel_result["status"] == "undetermined" and retry_count < MAX_RETRIES:
            final_status = "undetermined"
        else:
            final_status = quickintel_result["status"]

        # Special case override
        if quickintel_result.get("specialCase"):
            final_status = "good"

        # Update database based on final status
        if final_status == "undetermined":
            if retry_count >= MAX_RETRIES:
                update_token_status_to_bad(token_address, chain)
                final_status = "bad"
            else:
                update_token_status_to_undetermined(token_address, chain, retry_count + 1)
        else:
            update_token_status_to_checked(token_address, chain)

        # Store analysis data in Supabase
        analysis_data = {
            "honeypot": honeypot_result,
            "quickintel": {
                "status": quickintel_result["status"],
                "findings": quickintel_result["findings"],
                "taxes": quickintel_result["taxes"],
                "tokenDetails": quickintel_result["tokenDetails"],
                "contractLinks": quickintel_result["contractLinks"],
                "extractedFunctions": quickintel_result["extractedFunctions"],
                "specialCaseMessage": quickintel_result.get("specialCaseMessage")
            }
        }

        supabase.table(TOKEN_CHECKS_TABLE).insert({
            "token_address": token_address,
            "chain": chain,
            "status": final_status,
            "analysis_data": analysis_data
        }).execute()

        result["status"] = final_status
        SUPABASE_REQUEST_COUNTER.labels(operation="insert_token_checks").inc()

    except Exception as e:
        logger.error(f"Failed to process/store token {token_address}: {e}")
        result["status"] = "failed"
        result["errors"].append(str(e))
        update_token_status_to_bad(token_address, chain)
        SUPABASE_ERROR_COUNTER.labels(operation="insert_token_checks").inc()

    return result

# ------------------------------------------------------------------------------
# Main Execution
# ------------------------------------------------------------------------------
def main() -> None:
    """Main processing loop for token analysis."""
    global last_breaker_reset

    config = load_config()
    session = configure_session()
    validate_supabase_connection()
    start_http_server(8000)

    logger.info("Service started")
    while not shutdown_flag:
        # Circuit breaker automatic reset logging
        if time.time() - last_breaker_reset > BREAKER_RESET_INTERVAL:
            last_breaker_reset = time.time()
            logger.info("Circuit breakers reset timeout period reached, allowing automatic reset attempt.")

        tokens = fetch_tokens_for_processing_from_supabase()

        for token in tokens:
            token_address = token.get("token_address")
            chain = token.get("chain")
            status = token.get("status")
            last_retry = token.get("last_retry_timestamp")

            if not token_address or not chain:
                continue

            # Handle retry timing for 'undetermined' tokens
            if status == "undetermined" and last_retry:
                last_retry_time = datetime.fromisoformat(last_retry.replace('Z', '+00:00'))
                elapsed = (datetime.now(timezone.utc) - last_retry_time).total_seconds()
                required_delay = RETRY_INTERVAL_1_SECONDS if token["retry_count"] < 1 else RETRY_INTERVAL_2_SECONDS

                if elapsed < required_delay:
                    continue

            process_token(token, config, session)

        time.sleep(CHECK_INTERVAL_SECONDS)

    logger.info("Service stopped")

if __name__ == "__main__":
    main()