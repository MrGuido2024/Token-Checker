"""
Token_Checker.py
This script analyzes cryptocurrency tokens using Honeypot and QuickIntel APIs, then
stores the results in a Supabase database for further tracking (e.g., Telegram alerts).
It reads tokens to be checked from a Supabase table ('tokens_to_check'), updates their status after processing,
and includes robust error handling, logging, Prometheus metrics, and retry/circuit-breaker mechanisms.
"""

import json
import os
import re
import time
import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Union

# Environment variable handling for Supabase credentials
from dotenv import load_dotenv

import requests
from http.cookiejar import MozillaCookieJar
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import pybreaker
from prometheus_client import start_http_server, Counter, Histogram

# Supabase integration
from supabase import create_client, Client

# ------------------------------------------------------------------------------
# Load environment variables (e.g., SUPABASE_URL, SUPABASE_KEY)
# ------------------------------------------------------------------------------
load_dotenv()

SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Check if Supabase client is correctly initialized
if supabase:
    logging.info("Successfully initialized Supabase client.")
else:
    logging.critical("Failed to initialize Supabase client. Check SUPABASE_URL and SUPABASE_KEY.")
    exit(1)


# ------------------------------------------------------------------------------
# Prometheus Metrics Configuration
# ------------------------------------------------------------------------------
GET_REQUEST_COUNTER: Counter = Counter(
    "api_get_requests_total", "Total GET API requests", ["endpoint"]
)
POST_REQUEST_COUNTER: Counter = Counter(
    "api_post_requests_total", "Total POST API requests", ["endpoint"]
)
API_ERROR_COUNTER: Counter = Counter(
    "api_errors_total", "Total API errors", ["endpoint"]
)
GET_REQUEST_DURATION: Histogram = Histogram(
    "api_get_request_duration_seconds", "GET API request duration", ["endpoint"]
)
POST_REQUEST_DURATION: Histogram = Histogram(
    "api_post_request_duration_seconds", "POST API request duration", ["endpoint"]
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

handler = RotatingFileHandler(LOG_FILENAME, maxBytes=1010241024, backupCount=5)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# ------------------------------------------------------------------------------
# File & API Configuration
# ------------------------------------------------------------------------------
CONFIG_FILE: str = "quick_intel_config.json"
COOKIE_FILE: str = "cookies.txt"

# Honeypot and QuickIntel API endpoints
HONEYPOT_CV_URL: str = "https://api.honeypot.is/v2/GetContractVerification"
HONEYPOT_IH_URL: str = "https://api.honeypot.is/v2/IsHoneypot"
QUICKINTEL_API_URL: str = "https://app.quickintel.io/api/quicki/getquickiauditfull"

# User-Agent and supported chains
USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"
HONEYPOT_CHAINS: set = {"eth", "bsc", "base"}

# Retry and circuit-breaker settings
RETRY_ATTEMPTS: int = 3
RETRY_DELAY: int = 3  # base delay in seconds
breaker_get = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)
breaker_post = pybreaker.CircuitBreaker(fail_max=5, reset_timeout=60)

# Special case constants for Solana Pump.Fun tokens
PUMPFUN_UPDATE_AUTHORITY: str = "TSLvdd1pWpHVjahSpsvCXUbgwsL3JAcvokwaKt1eokM"

# Supabase table configuration
TOKENS_TO_CHECK_TABLE: str = "tokens_to_check"
TOKEN_CHECKS_TABLE: str = "token_checks"
CHECK_INTERVAL_SECONDS: int = 5


# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------
def load_config() -> Dict[str, Any]:
    """
    Load QuickIntel configuration from a JSON file.

    Returns:
        Dict[str, Any]: Configuration dictionary containing 'user_address' and 'tier'.
    """
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


def configure_session() -> Session:
    """
    Create a requests Session with retry logic and cookie handling.

    Returns:
        Session: A configured requests session with retry/backoff behavior.
    """
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
    """
    Generate request headers for the QuickIntel API.

    Returns:
        Dict[str, str]: A dictionary containing standard headers.
    """
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


def api_get_with_retries(url: str, params: Dict[str, Any], timeout: int = 30) -> Optional[Any]:
    """
    Perform a GET request with retries, exponential backoff, and a circuit breaker.

    Args:
        url (str): The API endpoint URL.
        params (Dict[str, Any]): Query parameters for the GET request.
        timeout (int): Timeout for the request in seconds.

    Returns:
        Optional[Any]: JSON response or None if all retries fail.
    """
    GET_REQUEST_COUNTER.labels(endpoint=url).inc()
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with GET_REQUEST_DURATION.labels(endpoint=url).time():
                response = breaker_get.call(
                    requests.get, url, params=params, timeout=timeout
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            API_ERROR_COUNTER.labels(endpoint=url).inc()
            logger.error(f"Error on GET {url} attempt {attempt+1}: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY * (2 ** attempt))
    return None


def api_post_with_retries(
    url: str, headers: Dict[str, str], data: str, session: Session, timeout: int = 30
) -> Optional[Any]:
    """
    Perform a POST request with retries, exponential backoff, and a circuit breaker.

    Args:
        url (str): The API endpoint URL.
        headers (Dict[str, str]): Request headers.
        data (str): JSON string data to send in the request body.
        session (Session): The configured requests session.
        timeout (int): Timeout for the request in seconds.

    Returns:
        Optional[Any]: JSON response or None if all retries fail.
    """
    POST_REQUEST_COUNTER.labels(endpoint=url).inc()
    for attempt in range(RETRY_ATTEMPTS):
        try:
            with POST_REQUEST_DURATION.labels(endpoint=url).time():
                response = breaker_post.call(
                    session.post, url, headers=headers, data=data, timeout=timeout
                )
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
    Extract function names from a list of Solidity function strings.

    Args:
        func_list (Optional[List[Any]]): A list of function definitions as strings.

    Returns:
        List[str]: A list of extracted function names.
    """
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
    """
    Apply special-case rules to QuickIntel results, e.g. for Solana Pump.Fun tokens.

    Args:
        quickintel_result (Dict[str, Any]): The QuickIntel result object to modify.
        chain (str): The blockchain chain identifier (e.g., 'solana').
        raw_data (Dict[str, Any]): The raw QuickIntel API response.

    Returns:
        Dict[str, Any]: The possibly modified QuickIntel result.
    """
    # Existing Solana Pump.Fun special case
    if chain == "solana":
        audit: Dict[str, Any] = raw_data.get("quickiAudit") or {}
        authorities: Dict[str, Any] = audit.get("authorities") or {}
        if authorities.get("update_Authority") == PUMPFUN_UPDATE_AUTHORITY:
            quickintel_result["specialCase"] = "pumpFun"
            quickintel_result["status"] = "good"
            quickintel_result["message"] = "Passed Pump.Fun special case"
            quickintel_result["findings"] = []

    # New Base Bankr special case
    if chain == "base":
        audit: Dict[str, Any] = raw_data.get("quickiAudit") or {}
        contract_creator: str = audit.get("contract_Creator", "")
        contract_name: str = audit.get("contract_Name", "")
        if (
            contract_creator == "0x002f07b0d63e8ac14f8ef6b73ccd8caf1fef074c"
            or contract_name == "ClankerToken"
        ):
            quickintel_result["specialCase"] = "baseBankr"
            quickintel_result["status"] = "good"
            quickintel_result["message"] = "Passed Base Bankr special case"
            quickintel_result["findings"] = []

    # New Moonshot special case
    if chain in {"base", "abstract"}:
        audit: Dict[str, Any] = raw_data.get("quickiAudit") or {}
        contract_name: str = audit.get("contract_Name", "")
        token_details: Dict[str, Any] = raw_data.get("tokenDetails") or {}
        token_logo: str = token_details.get("tokenLogo", "")
        if contract_name == "MoonshotToken" and token_logo.startswith(
            "https://cdn.dexscreener.com/"
        ):
            quickintel_result["specialCase"] = "moonshot"
            quickintel_result["status"] = "good"
            quickintel_result["message"] = "Passed Moonshot special case"
            quickintel_result["findings"] = []

    return quickintel_result


# ------------------------------------------------------------------------------
# Supabase Data Interaction Functions
# ------------------------------------------------------------------------------
def fetch_unchecked_tokens_from_supabase() -> List[Dict[str, Any]]:
    """
    Fetch tokens with 'unchecked' status from the Supabase 'tokens_to_check' table.

    Returns:
        List[Dict[str, Any]]: A list of token dictionaries, or an empty list if no tokens are found or an error occurs.
    """
    logger.info("Fetching 'unchecked' tokens from Supabase...")
    try:
        SUPABASE_REQUEST_COUNTER.labels(operation="select_unchecked_tokens").inc()
        response = supabase.table(TOKENS_TO_CHECK_TABLE).select("*").eq("status", "unchecked").execute()
        if response.data is None:  # Correctly check for errors using response.data
            SUPABASE_ERROR_COUNTER.labels(operation="select_unchecked_tokens").inc()
            logger.error(f"Supabase query error fetching 'unchecked' tokens: {response.error}")
            return []
        tokens: List[Dict[str, Any]] = response.data
        logger.info(f"Successfully fetched {len(tokens)} 'unchecked' tokens from Supabase.")
        return tokens
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="select_unchecked_tokens").inc()
        logger.error(f"Error fetching 'unchecked' tokens from Supabase: {e}")
        return []


def update_token_status_to_checked(token_address: str, chain: str) -> bool:
    """
    Update the status of a token in the Supabase 'tokens_to_check' table to 'checked'.

    Args:
        token_address (str): The address of the token.
        chain (str): The blockchain chain of the token.

    Returns:
        bool: True if the status was successfully updated, False otherwise.
    """
    logger.info(f"Updating status to 'checked' for token: {token_address} on chain: {chain} in Supabase...")
    try:
        SUPABASE_REQUEST_COUNTER.labels(operation="update_token_status").inc()
        response = supabase.table(TOKENS_TO_CHECK_TABLE).update({"status": "checked"}).eq("token_address", token_address).eq("chain", chain).execute()
        if response.data is None:  # Correctly check for errors using response.data
            SUPABASE_ERROR_COUNTER.labels(operation="update_token_status").inc()
            logger.error(f"Supabase update error for token {token_address} on {chain}: {response.error}")
            return False
        logger.info(f"Successfully updated status to 'checked' for token: {token_address} on chain: {chain} in Supabase.")
        return True
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="update_token_status").inc()
        logger.error(f"Error updating status for token {token_address} on {chain} in Supabase: {e}")
        return False


# ------------------------------------------------------------------------------
# Honeypot & QuickIntel Processing
# ------------------------------------------------------------------------------
def process_honeypot(token_address: str) -> Dict[str, Any]:
    """
    Call both Honeypot endpoints and return validation data about the token.

    Args:
        token_address (str): The contract address of the token to check.

    Returns:
        Dict[str, Any]: A dictionary containing contract verification and honeypot status.
    """
    result: Dict[str, Any] = {}
    params: Dict[str, str] = {"address": token_address}

    # ContractVerification endpoint
    cv = api_get_with_retries(HONEYPOT_CV_URL, params)
    if cv:
        cv_valid = (
            cv.get("isRootOpenSource") is True
            and cv.get("summary", {}).get("hasProxyCalls") is False
            and cv.get("summary", {}).get("isOpenSource") is True
        )
        result["ContractVerification"] = {
            "isRootOpenSource": cv.get("isRootOpenSource"),
            "hasProxyCalls": cv.get("summary", {}).get("hasProxyCalls"),
            "isOpenSource": cv.get("summary", {}).get("isOpenSource"),
            "valid": cv_valid,
            "message": "Valid"
            if cv_valid
            else "Failed validation for ContractVerification",
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
        ih_valid = (
            is_honeypot is False
            and siphoned == "0"
            and simulation_success is True
            and not flags
        )
        message = (
            "Valid"
            if ih_valid
            else f"Failed validation: Token is honeypot: {ih.get('honeypotResult', {}).get('honeypotReason', '')}"
        )
        result["IsHoneypot"] = {
            "isHoneypot": is_honeypot,
            "honeypotReason": ih.get("honeypotResult", {}).get("honeypotReason", ""),
            "siphoned": siphoned,
            "simulationSuccess": simulation_success,
            "flags": flags,
            "valid": ih_valid,
            "message": message,
        }
    else:
        result["IsHoneypot"] = {"valid": False, "message": "No response"}

    overall_valid = (
        result["ContractVerification"].get("valid")
        and result["IsHoneypot"].get("valid")
    )
    result["status"] = "good" if overall_valid else "bad"
    return result


def process_quickintel(
    token_address: str, chain: str, config: Dict[str, Any], session: Session
) -> Dict[str, Any]:
    """
    Call QuickIntel API and return relevant validation data, with detailed findings.

    Args:
        token_address (str): The contract address of the token to check.
        chain (str): The blockchain chain identifier (e.g., 'eth', 'bsc').
        config (Dict[str, Any]): Configuration dict containing user address and tier.
        session (Session): A requests Session object for making POST calls.

    Returns:
        Dict[str, Any]: A dictionary containing QuickIntel validation results.
    """
    # Increase timeout for certain chains if needed
    timeout: int = 30 if chain == "pulsechain" else 30

    payload: str = json.dumps(
        {
            "chain": chain,
            "tokenAddress": token_address,
            "userAddress": config["user_address"],
            "tier": config["tier"],
        }
    )
    data: Optional[Dict[str, Any]] = api_post_with_retries(
        QUICKINTEL_API_URL, get_headers(), payload, session, timeout=timeout
    )
    if not data:
        logger.error(f"No response from QuickIntel for token {token_address}")
        return {
            "valid": False,
            "message": "No response from QuickIntel",
            "findings": [],
            "fetchStatus": "failed",
        }

    # Extract basic token details
    token_details: Dict[str, Any] = data.get("tokenDetails") or {}
    details: Dict[str, Any] = {
        "tokenName": token_details.get("tokenName"),
        "tokenSymbol": token_details.get("tokenSymbol"),
        "tokenOwner": token_details.get("tokenOwner"),
        "tokenCreatedDate": token_details.get("tokenCreatedDate"),
        "tokenSupply": token_details.get("tokenSupply"),
    }

    # Validate tokenDynamicDetails
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

    dyn_valid: bool = len(dyn_findings) == 0

    # Validate quickiAudit
    audit: Dict[str, Any] = data.get("quickiAudit") or {}
    audit_findings: List[str] = []
    if "contract_Renounced" in audit and audit["contract_Renounced"] is not True:
        audit_findings.append("contract_Renounced is not True")
    if "hidden_Owner" in audit and audit["hidden_Owner"] is not False:
        audit_findings.append("hidden_Owner is not False")
    if "is_Proxy" in audit and audit["is_Proxy"] is not False:
        audit_findings.append("is_Proxy is not False")

    # Additional validations
    if "has_Scams" not in audit:
        audit_findings.append(
            "Validation passed for has_Scams due to missing data from API."
        )
    elif audit.get("has_Scams") is not False:
        audit_findings.append("has_Scams is not False (potential scam history detected)")

    if "has_Known_Scam_Wallet_Funding" not in audit:
        audit_findings.append(
            "Validation passed for has_Known_Scam_Wallet_Funding due to missing data from API."
        )
    elif audit.get("has_Known_Scam_Wallet_Funding") is not False:
        audit_findings.append(
            "has_Known_Scam_Wallet_Funding is not False (funded by known scam wallets)"
        )

    audit_valid: bool = len(audit_findings) == 0

    # Extract function names
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

    # Categorize contract links
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

    # Determine overall validation status
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
        "findings": all_findings,
    }

    # Apply any chain-specific special cases (e.g., Pump.Fun)
    result = apply_special_cases(result, chain, data)
    return result


# ------------------------------------------------------------------------------
# Token Processing (Fetching from Supabase and Storing results in Supabase)
# ------------------------------------------------------------------------------
def process_token(token: Dict[str, Any], config: Dict[str, Any], session: Session) -> Dict[str, Any]:
    """
    Process a single token by calling Honeypot/QuickIntel APIs and then storing
    the results in Supabase. Fetches token data from Supabase 'tokens_to_check' table.

    Args:
        token (Dict[str, Any]): A dictionary containing 'token_address' and 'chain' keys from Supabase.
        config (Dict[str, Any]): QuickIntel configuration dict (contains user_address, tier).
        session (Session): Configured requests session for API calls.

    Returns:
        Dict[str, Any]: A result entry summarizing the token analysis and status.
    """
    token_address: str = token.get("token_address", "")  # Use 'token_address' from Supabase record
    chain: str = token.get("chain", "").lower()  # Use 'chain' from Supabase record

    # Initialize a result entry for local usage/logging
    result_entry: Dict[str, Union[str, Dict[str, Any], List[str]]] = {
        "address": token_address,
        "chain": chain,
        "status": "good",
        "honeypot": None,
        "quickintel": None,
        "errors": [],
    }

    overall_valid: bool = True

    try:
        # Honeypot check (if chain is supported by the Honeypot API)
        if chain in HONEYPOT_CHAINS:
            honeypot_result: Dict[str, Any] = process_honeypot(token_address)
            result_entry["honeypot"] = honeypot_result
            if honeypot_result.get("status") != "good":
                overall_valid = False
        else:
            result_entry["honeypot"] = f"Not applicable for chain {chain}"

        # QuickIntel check
        quickintel_result: Dict[str, Any] = process_quickintel(
            token_address, chain, config, session
        )
        result_entry["quickintel"] = quickintel_result

        # Determine final status
        if quickintel_result.get("fetchStatus") == "failed":
            overall_valid = False
            result_entry["status"] = "failed"
        elif quickintel_result.get("status") != "good":
            overall_valid = False

        # Update final status
        if result_entry["status"] != "failed":
            result_entry["status"] = "good" if overall_valid else "bad"

        # Insert the analysis into Supabase
        supabase.table(TOKEN_CHECKS_TABLE).insert(
            {
                "token_address": token_address,
                "chain": chain,
                "analysis_data": {
                    "honeypot": result_entry["honeypot"],
                    "quickintel": result_entry["quickintel"],
                    "status": result_entry["status"],
                },
                "status": result_entry["status"],
            }
        ).execute()

    except Exception as e:
        logger.error(f"Failed to process/store token {token_address}: {e}")
        result_entry["status"] = "failed"
        # Append the error message for local reference
        errors_list = result_entry["errors"] if isinstance(result_entry["errors"], list) else []
        errors_list.append(str(e))
        result_entry["errors"] = errors_list

    return result_entry


# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
def main() -> None:
    """
    Main function to:
      1. Load config and initialize a requests Session.
      2. Start Prometheus metrics server.
      3. Periodically fetch 'unchecked' tokens from Supabase.
      4. Process each token and store results in Supabase, updating token status to 'checked'.
      5. Sleep for a defined interval before checking for new tokens again.
    """
    config: Optional[Dict[str, Any]] = None  # Initialize config outside the loop
    session: Optional[Session] = None  # Initialize session outside the loop

    try:
        config = load_config()
        session = configure_session()

        # Start Prometheus metrics server
        start_http_server(8000)
        logger.info("Prometheus metrics server started on port 8000.")

        while True:
            logger.info("Checking for new tokens to process...")
            tokens_to_process: List[Dict[str, Any]] = fetch_unchecked_tokens_from_supabase()

            if not tokens_to_process:
                logger.info("No 'unchecked' tokens found in Supabase. Sleeping...")
            else:
                logger.info(f"Found {len(tokens_to_process)} 'unchecked' tokens. Processing...")
                for token in tokens_to_process:
                    token_address = token.get("token_address")
                    chain = token.get("chain")
                    if token_address and chain:
                        logger.info(f"Processing token: {token_address} on chain {chain}")
                        process_token(token, config, session)  # Pass the token dictionary directly
                        if update_token_status_to_checked(token_address, chain):
                            logger.info(f"Successfully updated status to 'checked' for token: {token_address} on chain: {chain}.")
                        else:
                            logger.error(f"Failed to update status to 'checked' for token: {token_address} on chain: {chain}.")
                    else:
                        logger.error(f"Invalid token data received from Supabase: {token}. Skipping.")

            logger.info(f"Sleeping for {CHECK_INTERVAL_SECONDS} seconds...")
            time.sleep(CHECK_INTERVAL_SECONDS)
            logger.info("Waking up and checking for new tokens again.")

    except KeyboardInterrupt:
        logger.info("Token checker interrupted by user (KeyboardInterrupt). Shutting down gracefully...")

    except Exception as e:
        logger.critical(f"Fatal error in main loop: {e}", exc_info=True)

    finally:
        if session:
            session.close()
            logger.info("Session closed.")
        logger.info("Token checker loop finished.")


# Standard Python entry point
if __name__ == "__main__":
    main()