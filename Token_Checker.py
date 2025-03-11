"""
Token_Checker.py
The script analyzes crypto tokens by fetching data from Honeypot and QuickIntel APIs
to assess their security and legitimacy.
Author: 
Version: 
"""

import json
import os
import re
import time
import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional

import requests
from http.cookiejar import MozillaCookieJar
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import pybreaker
from prometheus_client import start_http_server, Counter, Histogram

# -------------------------------
# METRICS (Prometheus)
# -------------------------------
GET_REQUEST_COUNTER: Counter = Counter('api_get_requests_total', 'Total GET API requests', ['endpoint'])
POST_REQUEST_COUNTER: Counter = Counter('api_post_requests_total', 'Total POST API requests', ['endpoint'])
API_ERROR_COUNTER: Counter = Counter('api_errors_total', 'Total API errors', ['endpoint'])
GET_REQUEST_DURATION: Histogram = Histogram('api_get_request_duration_seconds', 'GET API request duration', ['endpoint'])
POST_REQUEST_DURATION: Histogram = Histogram('api_post_request_duration_seconds', 'POST API request duration', ['endpoint'])

# -------------------------------
# Logging Configuration
# -------------------------------
LOG_FILENAME: str = 'app.log'
logger: logging.Logger = logging.getLogger("TokenProcessor")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(LOG_FILENAME, maxBytes=10*1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# -------------------------------
# FILE & API CONFIGURATION
# -------------------------------
TEST_TOKENS_FILE: str = "test_tokens.json"
CHECKED_RESULTS_FILE: str = "test_checked.json"
CONFIG_FILE: str = "quick_intel_config.json"
COOKIE_FILE: str = "cookies.txt"

# Honeypot endpoints
HONEYPOT_CV_URL: str = "https://api.honeypot.is/v2/GetContractVerification"
HONEYPOT_IH_URL: str = "https://api.honeypot.is/v2/IsHoneypot"
# QuickIntel endpoint
QUICKINTEL_API_URL: str = "https://app.quickintel.io/api/quicki/getquickiauditfull"
USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"

# Supported chains for Honeypot
HONEYPOT_CHAINS: set = {"eth", "bsc", "base"}

# Retry settings
RETRY_ATTEMPTS: int = 3
RETRY_DELAY: int = 3  # base delay in seconds

# Special case constants for Solana Pump.Fun tokens
PUMPFUN_UPDATE_AUTHORITY: str = "TSLvdd1pWpHVjahSpsvCXUbgwsL3JAcvokwaKt1eokM"

# -------------------------------
# Circuit Breakers
# -------------------------------
breaker_get = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)
breaker_post = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)

# -------------------------------
# UTILITY FUNCTIONS
# -------------------------------
def load_config() -> Dict[str, Any]:
    """Load QuickIntel configuration from JSON file."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config: Dict[str, Any] = json.load(f)
        if not all(k in config for k in ('user_address', 'tier')):
            raise ValueError("Missing required fields in config.json")
        return config
    except FileNotFoundError as e:
        logger.critical(f"Config file {CONFIG_FILE} not found: {e}")
        raise
    except json.JSONDecodeError as e:
        logger.critical(f"Invalid JSON format in {CONFIG_FILE}: {e}")
        raise

def configure_session() -> Session:
    """Create a session with retries and cookie handling."""
    session: Session = Session()
    retries = Retry(total=RETRY_ATTEMPTS, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    cookie_jar = MozillaCookieJar(COOKIE_FILE)
    if os.path.exists(COOKIE_FILE):
        cookie_jar.load(ignore_discard=True, ignore_expires=True)
    session.cookies = cookie_jar
    return session

def get_headers() -> Dict[str, str]:
    """Generate request headers for QuickIntel API."""
    return {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Referer": "https://app.quickintel.io/scanner",
        "Content-Type": "text/plain;charset=UTF-8",
        "Origin": "https://app.quickintel.io",
        "DNT": "1",
        "Sec-GPC": "1",
        "Priority": "u=0"
    }

def api_get_with_retries(url: str, params: Dict[str, Any], timeout: int = 30) -> Optional[Any]:
    """GET request with retries, exponential backoff, and circuit breaker."""
    GET_REQUEST_COUNTER.labels(endpoint=url).inc()
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with GET_REQUEST_DURATION.labels(endpoint=url).time():
                response = breaker_get.call(requests.get, url, params=params, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            API_ERROR_COUNTER.labels(endpoint=url).inc()
            logger.error(f"Error on GET {url} attempt {attempt+1}: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

def api_post_with_retries(url: str, headers: Dict[str, str], data: str, session: Session, timeout: int = 30) -> Optional[Any]:
    """POST request with retries, exponential backoff, and circuit breaker."""
    POST_REQUEST_COUNTER.labels(endpoint=url).inc()
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with POST_REQUEST_DURATION.labels(endpoint=url).time():
                response = breaker_post.call(session.post, url, headers=headers, data=data, timeout=timeout)
            response.raise_for_status()
            session.cookies.save(ignore_discard=True, ignore_expires=True)
            return response.json()
        except Exception as e:
            API_ERROR_COUNTER.labels(endpoint=url).inc()
            logger.error(f"Error on POST {url} attempt {attempt+1}: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))
    return None

def extract_function_names(func_list: Optional[List[Any]]) -> List[str]:
    """
    Extract function names from a list of function strings.
    Captures text between 'function' and the first '('.
    """
    names: List[str] = []
    if func_list and isinstance(func_list, list):
        for func in func_list:
            match = re.search(r'function\s+([^(]+)\(', func)
            if match:
                names.append(match.group(1).strip())
    return names

def apply_special_cases(quickintel_result: Dict[str, Any], chain: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check for special cases.
    For Solana tokens:
      - If quickiAudit.authorities.update_Authority equals the special Pump.Fun address,
        override validation and mark as specialCase 'pumpFun'.
    """
    if chain == "solana":
        audit: Dict[str, Any] = raw_data.get("quickiAudit") or {}
        authorities: Dict[str, Any] = audit.get("authorities") or {}
        if authorities.get("update_Authority") == PUMPFUN_UPDATE_AUTHORITY:
            quickintel_result["specialCase"] = "pumpFun"
            quickintel_result["status"] = "good"
            quickintel_result["message"] = "Passed Pump.Fun special case"
            quickintel_result["findings"] = []
    # Placeholders for other special cases (e.g., for 'eth' or 'base')
    return quickintel_result

# -------------------------------
# PROCESSING API RESPONSES
# -------------------------------
def process_honeypot(token_address: str) -> Dict[str, Any]:
    """Call both Honeypot endpoints and return only the validation data."""
    result: Dict[str, Any] = {}
    params: Dict[str, str] = {'address': token_address}

    # ContractVerification endpoint
    cv = api_get_with_retries(HONEYPOT_CV_URL, params)
    if cv:
        cv_valid = (cv.get("isRootOpenSource") is True and
                    cv.get("summary", {}).get("hasProxyCalls") is False and
                    cv.get("summary", {}).get("isOpenSource") is True)
        result["ContractVerification"] = {
            "isRootOpenSource": cv.get("isRootOpenSource"),
            "hasProxyCalls": cv.get("summary", {}).get("hasProxyCalls"),
            "isOpenSource": cv.get("summary", {}).get("isOpenSource"),
            "valid": cv_valid,
            "message": "Valid" if cv_valid else "Failed validation for ContractVerification"
        }
    else:
        result["ContractVerification"] = {"valid": False, "message": "No response"}

    # IsHoneypot endpoint
    ih = api_get_with_retries(HONEYPOT_IH_URL, params)
    if ih:
        is_honeypot = ih.get("honeypotResult", {}).get("isHoneypot")
        siphoned = ih.get("holderAnalysis", {}).get("siphoned", "")
        simulation_success = ih.get("simulationSuccess")
        flags = ih.get("summary", {}).get("flags", [])
        ih_valid = (is_honeypot is False and siphoned == "0" and simulation_success is True and not flags)
        message = "Valid" if ih_valid else f"Failed validation: Token is honeypot: {ih.get('honeypotResult', {}).get('honeypotReason', '')}"
        result["IsHoneypot"] = {
            "isHoneypot": is_honeypot,
            "honeypotReason": ih.get("honeypotResult", {}).get("honeypotReason", ""),
            "siphoned": siphoned,
            "simulationSuccess": simulation_success,
            "flags": flags,
            "valid": ih_valid,
            "message": message
        }
    else:
        result["IsHoneypot"] = {"valid": False, "message": "No response"}

    overall_valid = (result["ContractVerification"].get("valid") and result["IsHoneypot"].get("valid"))
    result["status"] = "good" if overall_valid else "bad"
    return result

def process_quickintel(token_address: str, chain: str, config: Dict[str, Any], session: Session) -> Dict[str, Any]:
    """Call QuickIntel API and return only the relevant validation data, with detailed findings."""
    # Increase timeout for Pulsechain tokens
    timeout: int = 30 if chain == "pulsechain" else 30

    payload: str = json.dumps({
        "chain": chain,
        "tokenAddress": token_address,
        "userAddress": config['user_address'],
        "tier": config['tier']
    })
    data: Optional[Dict[str, Any]] = api_post_with_retries(QUICKINTEL_API_URL, get_headers(), payload, session, timeout=timeout)
    if not data:
        logger.error(f"No response from QuickIntel for token {token_address}")
        return {"valid": False, "message": "No response from QuickIntel", "findings": [], "fetchStatus": "failed"}

    # Extract tokenDetails
    token_details: Dict[str, Any] = data.get("tokenDetails") or {}
    details: Dict[str, Any] = {
        "tokenName": token_details.get("tokenName"),
        "tokenSymbol": token_details.get("tokenSymbol"),
        "tokenOwner": token_details.get("tokenOwner"),
        "tokenCreatedDate": token_details.get("tokenCreatedDate"),
        "tokenSupply": token_details.get("tokenSupply")
    }

    # Validate tokenDynamicDetails with detailed findings (using top-level for isAirdropPhishingScam and contractVerified)
    dyn: Dict[str, Any] = data.get("tokenDynamicDetails") or {}
    dyn_findings: List[str] = []
    try:
        buy_tax: float = float(dyn.get("buy_Tax") or 0)
        see_tax: float = float(dyn.get("see_Tax") or 0)
        transfer_tax: float = float(dyn.get("transfer_Tax") or 0)
    except (ValueError, TypeError):
        buy_tax = see_tax = transfer_tax = 0

    if dyn.get("is_Honeypot") is not False:
        dyn_findings.append("is_Honeypot is not False")
    if buy_tax > 5:
        dyn_findings.append("buy_Tax exceeds 5%")
    if see_tax > 5:
        dyn_findings.append("see_Tax exceeds 5%")
    if transfer_tax > 5:
        dyn_findings.append("transfer_Tax exceeds 5%")
    if data.get("isAirdropPhishingScam") is not False:
        dyn_findings.append("isAirdropPhishingScam is not False")
    if data.get("contractVerified") is not True:
        dyn_findings.append("contractVerified is not True")

    dyn_valid: bool = (len(dyn_findings) == 0)

    # Validate quickiAudit with detailed findings, only if keys exist
    audit: Dict[str, Any] = data.get("quickiAudit") or {}
    audit_findings: List[str] = []
    if "contract_Renounced" in audit and audit["contract_Renounced"] is not True:
        audit_findings.append("contract_Renounced is not True")
    if "hidden_Owner" in audit and audit["hidden_Owner"] is not False:
        audit_findings.append("hidden_Owner is not False")
    if "is_Proxy" in audit and audit["is_Proxy"] is not False:
        audit_findings.append("is_Proxy is not False")

    # --- Additional Validations ---
    if "has_Scams" not in audit:
        audit_findings.append("Validation passed for has_Scams due to missing data from API.")
    elif audit.get("has_Scams") is not False:
        audit_findings.append("has_Scams is not False (potential scam history detected)")

    if "has_Known_Scam_Wallet_Funding" not in audit:
        audit_findings.append("Validation passed for has_Known_Scam_Wallet_Funding due to missing data from API.")
    elif audit.get("has_Known_Scam_Wallet_Funding") is not False:
        audit_findings.append("has_Known_Scam_Wallet_Funding is not False (funded by known scam wallets)")
    # --- End Additional Validations ---

    audit_valid: bool = (len(audit_findings) == 0)

    # Extract function names from specific arrays in audit
    functions_to_extract: List[str] = [
        "modified_Transfer_Functions",
        "suspicious_Functions",
        "external_Functions",
        "fee_Update_Functions",
        "can_Potentially_Steal_Funds_Functions",
        "blacklistFunctionsRan"
    ]
    extracted_functions: Dict[str, List[str]] = {}
    for key in functions_to_extract:
        func_list = audit.get(key)
        extracted_functions[key] = extract_function_names(func_list)

    # Process contract links from quickiAudit.contract_Links
    links: List[Any] = audit.get("contract_Links") or []
    categorized_links: Dict[str, List[str]] = {"Telegram": [], "Twitter": [], "Website": [], "Other Links": []}
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

    overall_valid: bool = dyn_valid and audit_valid
    all_findings: List[str] = []
    if not dyn_valid:
        all_findings.extend(dyn_findings)
    if not audit_valid:
        all_findings.extend(audit_findings)

    result: Dict[str, Any] = {
        "tokenDetails": details,
        "tokenDynamicDetailsValid": dyn_valid,
        "quickiAuditValid": audit_valid,
        "extractedFunctions": extracted_functions,
        "contractLinks": categorized_links,
        "status": "good" if overall_valid else "bad",
        "message": "Valid" if overall_valid else "Failed validation in dynamic details or audit",
        "findings": all_findings
    }

    # Apply special cases for specific chains (e.g., Solana Pump.Fun tokens)
    result = apply_special_cases(result, chain, data)

    return result

def process_token(token: Dict[str, Any], config: Dict[str, Any], session: Session) -> Dict[str, Any]:
    """
    Process a single token.
    For supported chains (eth, bsc, base), call both Honeypot and QuickIntel.
    For other chains, only call QuickIntel.
    Returns a combined result with a status.
    """
    token_address: str = token.get("address")
    chain: str = token.get("chain", "").lower()
    result_entry: Dict[str, Any] = {
        "address": token_address,
        "chain": chain,
        "status": "good",  # default; will update below
        "honeypot": None,
        "quickintel": None,
        "errors": []
    }

    overall_valid: bool = True

    if chain in HONEYPOT_CHAINS:
        honeypot_result: Dict[str, Any] = process_honeypot(token_address)
        result_entry["honeypot"] = honeypot_result
        if honeypot_result.get("status") != "good":
            overall_valid = False
            logger.warning(f"Token {token_address} failed Honeypot validation: {honeypot_result.get('IsHoneypot', {}).get('message')}")
    else:
        result_entry["honeypot"] = f"Not applicable for chain {chain}"

    quickintel_result: Dict[str, Any] = process_quickintel(token_address, chain, config, session)
    result_entry["quickintel"] = quickintel_result
    if quickintel_result.get("fetchStatus") == "failed":
        overall_valid = False
        logger.error(f"Token {token_address} failed fetching QuickIntel data.")
        result_entry["status"] = "failed"
    elif quickintel_result.get("status") != "good":
        overall_valid = False
        logger.warning(f"Token {token_address} failed QuickIntel validation: {quickintel_result.get('findings')}")

    if result_entry["status"] != "failed":
        result_entry["status"] = "good" if overall_valid else "bad"
    return result_entry

def main() -> None:
    try:
        config: Dict[str, Any] = load_config()
        session: Session = configure_session()
        # Start Prometheus metrics HTTP server on port 8000
        start_http_server(8000)
        logger.info("Prometheus metrics server started on port 8000.")

        with open(TEST_TOKENS_FILE, 'r') as f:
            tokens: List[Dict[str, Any]] = json.load(f)
        results: List[Dict[str, Any]] = []
        for token in tokens:
            logger.info(f"Processing token: {token.get('address')} on chain {token.get('chain')}")
            token_result: Dict[str, Any] = process_token(token, config, session)
            results.append(token_result)
        with open(CHECKED_RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Token checks completed. Results saved in {CHECKED_RESULTS_FILE}")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
    finally:
        session.close()

if __name__ == "__main__":
    main()
