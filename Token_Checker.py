import json
import os
import re
import time
import requests
from http.cookiejar import MozillaCookieJar
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -------------------------------
# FILE & API CONFIGURATION
# -------------------------------
TEST_TOKENS_FILE = "test_tokens.json"
CHECKED_RESULTS_FILE = "test_checked2.json"
CONFIG_FILE = "quick_intel_config.json"
COOKIE_FILE = "cookies.txt"

# Honeypot endpoints
HONEYPOT_CV_URL = "https://api.honeypot.is/v2/GetContractVerification"
HONEYPOT_IH_URL = "https://api.honeypot.is/v2/IsHoneypot"
# QuickIntel endpoint
QUICKINTEL_API_URL = "https://app.quickintel.io/api/quicki/getquickiauditfull"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"

# Supported chains for Honeypot
HONEYPOT_CHAINS = {"eth", "bsc", "base"}

# Retry settings
RETRY_ATTEMPTS = 3
RETRY_DELAY = 3  # seconds

# -------------------------------
# UTILITY FUNCTIONS
# -------------------------------
def load_config():
    """Load QuickIntel configuration from JSON file."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        if not all(k in config for k in ('user_address', 'tier')):
            raise ValueError("Missing required fields in config.json")
        return config
    except FileNotFoundError:
        raise FileNotFoundError(f"Config file {CONFIG_FILE} not found")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in {CONFIG_FILE}")

def configure_session():
    """Create a session with retries and cookie handling."""
    session = Session()
    retries = Retry(total=RETRY_ATTEMPTS, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    cookie_jar = MozillaCookieJar(COOKIE_FILE)
    if os.path.exists(COOKIE_FILE):
        cookie_jar.load(ignore_discard=True, ignore_expires=True)
    session.cookies = cookie_jar
    return session

def get_headers():
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

def api_get_with_retries(url, params, timeout=10):
    """GET request with retries."""
    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error on GET {url} attempt {attempt+1}: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY)
    return None

def api_post_with_retries(url, headers, data, session, timeout=10):
    """POST request with retries using the provided session."""
    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = session.post(url, headers=headers, data=data, timeout=timeout)
            response.raise_for_status()
            session.cookies.save(ignore_discard=True, ignore_expires=True)
            return response.json()
        except requests.RequestException as e:
            print(f"Error on POST {url} attempt {attempt+1}: {e}")
            if attempt < RETRY_ATTEMPTS - 1:
                time.sleep(RETRY_DELAY)
    return None

def extract_function_names(func_list):
    """
    Extract function names from a list of function strings.
    Captures text between 'function' and the first '('.
    """
    names = []
    if func_list and isinstance(func_list, list):
        for func in func_list:
            match = re.search(r'function\s+([^(]+)\(', func)
            if match:
                names.append(match.group(1).strip())
    return names

# -------------------------------
# PROCESSING API RESPONSES
# -------------------------------
def process_honeypot(token_address):
    """Call both Honeypot endpoints and return only the validation data."""
    result = {}
    params = {'address': token_address}
    
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

def process_quickintel(token_address, chain, config, session):
    """Call QuickIntel API and return only the relevant validation data, with detailed findings."""
    payload = json.dumps({
        "chain": chain,
        "tokenAddress": token_address,
        "userAddress": config['user_address'],
        "tier": config['tier']
    })
    data = api_post_with_retries(QUICKINTEL_API_URL, get_headers(), payload, session)
    if not data:
        return {"valid": False, "message": "No response from QuickIntel", "findings": []}
    
    # Extract tokenDetails
    token_details = data.get("tokenDetails") or {}
    details = {
        "tokenName": token_details.get("tokenName"),
        "tokenSymbol": token_details.get("tokenSymbol"),
        "tokenOwner": token_details.get("tokenOwner"),
        "tokenCreatedDate": token_details.get("tokenCreatedDate"),
        "tokenSupply": token_details.get("tokenSupply")
    }
    
    # Validate tokenDynamicDetails with detailed findings
    dyn = data.get("tokenDynamicDetails") or {}
    dyn_findings = []
    try:
        buy_tax = float(dyn.get("buy_Tax") or 0)
        sell_tax = float(dyn.get("sell_Tax") or 0)
        transfer_tax = float(dyn.get("transfer_Tax") or 0)
    except (ValueError, TypeError):
        buy_tax = sell_tax = transfer_tax = 0
    
    if dyn.get("is_Honeypot") is not False:
        dyn_findings.append("is_Honeypot is not False")
    if buy_tax > 5:
        dyn_findings.append("buy_Tax exceeds 5%")
    if sell_tax > 5:
        dyn_findings.append("sell_Tax exceeds 5%")
    if transfer_tax > 5:
        dyn_findings.append("transfer_Tax exceeds 5%")
    
    # Check top-level keys for isAirdropPhishingScam and contractVerified
    top_isAirdropPhishingScam = data.get("isAirdropPhishingScam")
    top_contractVerified = data.get("contractVerified")
    if top_isAirdropPhishingScam is not False:
        dyn_findings.append("isAirdropPhishingScam is not False")
    if top_contractVerified is not True:
        dyn_findings.append("contractVerified is not True")
    
    dyn_valid = (len(dyn_findings) == 0)
    
    # Validate quickiAudit with detailed findings
    audit = data.get("quickiAudit") or {}
    audit_findings = []
    if audit.get("contract_Renounced") is not True:
        audit_findings.append("contract_Renounced is not True")
    if audit.get("hidden_Owner") is not False:
        audit_findings.append("hidden_Owner is not False")
    if audit.get("is_Proxy") is not False:
        audit_findings.append("is_Proxy is not False")
    
    audit_valid = (len(audit_findings) == 0)
    
    # Extract function names from specific arrays in audit
    functions_to_extract = [
        "modified_Transfer_Functions",
        "suspicious_Functions",
        "external_Functions",
        "fee_Update_Functions",
        "can_Potentially_Steal_Funds_Functions",
        "blacklistFunctionsRan"
    ]
    extracted_functions = {}
    for key in functions_to_extract:
        func_list = audit.get(key)
        extracted_functions[key] = extract_function_names(func_list)
    
    # Process contract links from quickiAudit.contract_Links
    links = audit.get("contract_Links") or []
    categorized_links = {"Telegram": [], "Twitter": [], "Website": [], "Other Links": []}
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
    
    overall_valid = dyn_valid and audit_valid
    all_findings = []
    if not dyn_valid:
        all_findings.extend(dyn_findings)
    if not audit_valid:
        all_findings.extend(audit_findings)
    
    result = {
        "tokenDetails": details,
        "tokenDynamicDetailsValid": dyn_valid,
        "quickiAuditValid": audit_valid,
        "extractedFunctions": extracted_functions,
        "contractLinks": categorized_links,
        "status": "good" if overall_valid else "bad",
        "message": "Valid" if overall_valid else "Failed validation in dynamic details or audit",
        "findings": all_findings
    }
    return result

# -------------------------------
# MAIN PROCESSING FUNCTION
# -------------------------------
def process_token(token, config, session):
    """
    Process a single token.
    For supported chains (eth, bsc, base), call both Honeypot and QuickIntel.
    For other chains, only call QuickIntel.
    Returns a combined result with a status.
    """
    token_address = token.get("address")
    chain = token.get("chain", "").lower()
    result_entry = {
        "address": token_address,
        "chain": chain,
        "status": "good",  # default to good; will update below
        "honeypot": None,
        "quickintel": None,
        "errors": []
    }
    
    overall_valid = True
    
    if chain in HONEYPOT_CHAINS:
        honeypot_result = process_honeypot(token_address)
        result_entry["honeypot"] = honeypot_result
        if honeypot_result.get("status") != "good":
            overall_valid = False
            print(f"Token {token_address} failed Honeypot validation: {honeypot_result.get('IsHoneypot', {}).get('message')}")
    else:
        result_entry["honeypot"] = "Not applicable for chain " + chain
    
    quickintel_result = process_quickintel(token_address, chain, config, session)
    result_entry["quickintel"] = quickintel_result
    if quickintel_result.get("status") != "good":
        overall_valid = False
        print(f"Token {token_address} failed QuickIntel validation: {quickintel_result.get('findings')}")
    
    result_entry["status"] = "good" if overall_valid else "bad"
    return result_entry

def main():
    try:
        config = load_config()
        session = configure_session()
        with open(TEST_TOKENS_FILE, 'r') as f:
            tokens = json.load(f)
        results = []
        for token in tokens:
            print(f"Processing token: {token.get('address')} on chain {token.get('chain')}")
            token_result = process_token(token, config, session)
            results.append(token_result)
        with open(CHECKED_RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Token checks completed. Results saved in {CHECKED_RESULTS_FILE}")
    except Exception as e:
        print(f"Fatal error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    main()
