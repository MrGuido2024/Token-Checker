"""
twitter_data_fetcher.py
Fetches tweet data from SocialData API, processes it, and stores it in Supabase.
Implements robust error handling, rate limiting, Prometheus metrics, and graceful shutdown.
Utilizes dynamic spam account and content exclusion filters, persistent HTTP sessions, and concurrent processing.
"""

import os
import time
import requests
import json
import logging
import signal
import atexit
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Environment variable handling
from dotenv import load_dotenv
from urllib.parse import quote_plus  # For URL encoding

# Retry and Circuit Breaker Libraries
from tenacity import retry, stop_after_attempt, wait_exponential
import pybreaker

# Prometheus Metrics Libraries
from prometheus_client import start_http_server, Counter, Histogram
from requests.exceptions import HTTPError

# Supabase integration
from supabase import create_client, Client

# ------------------------------------------------------------------------------
# Configuration Constants
# ------------------------------------------------------------------------------
load_dotenv()

# Environment credentials
SUPABASE_URL: str = os.getenv("SUPABASE_URL")
SUPABASE_KEY: str = os.getenv("SUPABASE_KEY")
SOCIALDATA_API_KEY: str = os.getenv("SOCIALDATA_API_KEY")
if not SUPABASE_URL or not SUPABASE_KEY or not SOCIALDATA_API_KEY:
    logging.critical("Missing Supabase or SocialData API credentials in .env")
    exit(1)

# Prometheus Metrics Port
PROMETHEUS_PORT: int = 8000

# Twitter Data Filtering
MIN_FAVES_THRESHOLD: int = 0
MIN_RETWEETS_THRESHOLD: int = 0
MIN_REPLIES_THRESHOLD: int = 0
CONTENT_EXCLUSION_KEYWORDS: List[str] = [
    "scam", "rug", "rugpull", "scammer", "scammers", "insider", "insiders",
    "fake", "bundled", "warning", "alert", "avoid"
]

# Rate Limiting and Retry Settings
RATE_LIMIT_BACKOFF_SECONDS: int = 5
MAX_RATE_LIMIT_RETRIES: int = 3
RETRY_INTERVAL_UNDETERMINED_MINUTES: int = 5
RETRY_ATTEMPTS: int = 3
RETRY_DELAY: int = 3

# Circuit Breaker Settings (merged into one)
CIRCUIT_BREAKER_FAIL_MAX: int = 5
CIRCUIT_BREAKER_RESET_TIMEOUT: int = 60

# Thread Pool for concurrent token processing
THREAD_POOL_WORKERS: int = 10

# Check interval and breaker reset interval (in seconds)
CHECK_INTERVAL_SECONDS: int = 1
BREAKER_RESET_INTERVAL: int = 300

# ------------------------------------------------------------------------------
# Prometheus Metrics Configuration
# ------------------------------------------------------------------------------
API_REQUESTS_TOTAL: Counter = Counter(
    "socialdata_api_requests_total", "Total SocialData API requests"
)
DB_OPERATIONS_TOTAL: Counter = Counter(
    "supabase_db_operations_total", "Total Supabase database operations", ["operation"]
)
SUPABASE_ERROR_COUNTER: Counter = Counter(
    "supabase_errors_total", "Total Supabase errors", ["operation"]
)
TOKENS_PROCESSED_TOTAL: Counter = Counter(
    "tokens_processed_total", "Total tokens processed"
)
TWEETS_SAVED_TOTAL: Counter = Counter(
    "tweets_saved_total", "Total tweets saved to database"
)
ERRORS_TOTAL: Counter = Counter(
    "errors_total", "Total errors encountered", ["type"]
)
API_REQUEST_DURATION: Histogram = Histogram(
    "socialdata_api_request_duration_seconds", "SocialData API request duration"
)

# ------------------------------------------------------------------------------
# Logging Configuration
# ------------------------------------------------------------------------------
LOG_FILENAME: str = "twitter_checker.log"
logger: logging.Logger = logging.getLogger("TwitterChecker")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(LOG_FILENAME, maxBytes=1 * 1024 * 1024, backupCount=1)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
handler.setFormatter(formatter)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Global Variables and Initialization
# ------------------------------------------------------------------------------
# Global shutdown flag for graceful exit
is_shutting_down: bool = False

# Initialize Supabase client variable (to be set in initialize_supabase_client)
supabase_client: Optional[Client] = None

# Initialize a persistent HTTP session
http_session = requests.Session()

# Initialize a single circuit breaker for all API calls
breaker = pybreaker.CircuitBreaker(fail_max=CIRCUIT_BREAKER_FAIL_MAX, reset_timeout=CIRCUIT_BREAKER_RESET_TIMEOUT)

# Variable to track the last circuit breaker reset time
last_breaker_reset = time.time()

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------

def validate_supabase_connection() -> None:
    """Validates the connection to Supabase by performing a test query on the tweets_data table."""
    try:
        supabase_client.table("tweets_data").select("*", count="exact").limit(1).execute()
        logger.info("Supabase connection validated.")
    except Exception as e:
        logger.critical(f"Supabase connection failed: {e}")
        raise ConnectionError("Supabase connection validation failed")

def initialize_supabase_client() -> None:
    """Initializes the Supabase client and validates the connection."""
    global supabase_client
    supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    if supabase_client:
        logger.info("Supabase client initialized and connection validated.")
        validate_supabase_connection()
    else:
        logger.critical("Failed to initialize Supabase client.")
        exit(1)

def construct_socialdata_query(token_address: str, spam_accounts: List[str]) -> str:
    """
    Constructs the SocialData API query string.
    """
    query = f'"{token_address}" -filter:retweets'
    encoded_query = quote_plus(query)
    logger.debug(f"Constructed SocialData API query: {encoded_query}")
    return encoded_query

@API_REQUEST_DURATION.time()
@retry(stop=stop_after_attempt(RETRY_ATTEMPTS), wait=wait_exponential(multiplier=1, max=10))
@breaker
def fetch_twitter_data(query: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Fetches data from the SocialData API using a persistent HTTP session, with retries and circuit breaker."""
    API_REQUESTS_TOTAL.inc()
    url = "https://api.socialdata.tools/twitter/search"
    headers = {'Authorization': f'Bearer {api_key}', 'Accept': 'application/json'}
    params = {'query': query, 'type': 'Latest'}
    logger.debug(f"SocialData API Request URL: {sanitize_url(url, params)}")
    try:
        response = http_session.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        ERRORS_TOTAL.labels(type="socialdata_api_http_error").inc()
        if e.response.status_code == 429:
            logger.warning(f"SocialData API rate limit hit, retrying after backoff. Error: {e}")
        elif e.response.status_code == 402:
            logger.critical("SocialData API Payment Required (402). Check API balance.")
            ERRORS_TOTAL.labels(type="socialdata_api_payment_required").inc()
        else:
            logger.error(f"SocialData API HTTP error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        ERRORS_TOTAL.labels(type="socialdata_api_request_exception").inc()
        logger.error(f"SocialData API request exception: {e}")
        return None
    except json.JSONDecodeError as e:
        ERRORS_TOTAL.labels(type="socialdata_api_json_decode_error").inc()
        logger.error(f"SocialData API JSON decode error: {e}")
        return None

def sanitize_url(url: str, params: Dict[str, str]) -> str:
    """Sanitizes the URL by redacting sensitive parameter values from logs."""
    query_string = '&'.join([f"{k}=[REDACTED]" for k in params.keys()])
    return f"{url}?{query_string}"

def calculate_time_elapsed_minutes(tweet_created_at_str: Optional[str]) -> int:
    """Calculates the number of minutes elapsed since the tweet was created."""
    if not tweet_created_at_str:
        return 0
    try:
        tweet_created_at = datetime.strptime(tweet_created_at_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        time_difference = datetime.now(timezone.utc) - tweet_created_at
        return int(time_difference.total_seconds() / 60)
    except ValueError as e:
        logger.error(f"Error parsing tweet_created_at timestamp: {e}")
        return 0

def calculate_engagement_score(tweet: Dict[str, Any]) -> int:
    """Calculates the engagement score for a tweet by summing favorites, replies, retweets, and bookmarks."""
    favorite_count = tweet.get('favorite_count', 0)
    reply_count = tweet.get('reply_count', 0)
    retweet_count = tweet.get('retweet_count', 0)
    bookmark_count = tweet.get('bookmark_count', 0)
    return favorite_count + reply_count + retweet_count + bookmark_count

def tweet_link_constructor(screen_name: str, tweet_id_str: str) -> str:
    """Constructs a direct link to the tweet."""
    return f"https://x.com/{screen_name}/status/{tweet_id_str}"

def process_tweet_data(api_response_data: Dict[str, Any], tweet_link_constructor, spam_accounts: List[str]) -> Tuple[Optional[Dict[str, Any]], Optional[List[str]], Optional[Dict[str, Any]]]:
    """
    Processes API response data by filtering out tweets from spam accounts or containing excluded keywords,
    then selects the tweet with the highest engagement as the primary tweet.
    """
    primary_tweet_data = None
    other_tweet_links = []
    primary_tweet_object = None
    max_engagement_score = -1
    primary_tweep_screen_name = None

    if not api_response_data or not api_response_data.get('tweets'):
        return None, None, None

    filtered_tweets = []
    tweets = api_response_data.get('tweets', [])
    # Filter tweets based on spam account and content exclusion
    for tweet in tweets:
        user_data = tweet.get('user', {})
        user_screen_name = user_data.get('screen_name', '')
        if user_screen_name in spam_accounts:
            continue
        tweet_text = tweet.get('full_text', '').lower()
        if any(keyword in tweet_text for keyword in CONTENT_EXCLUSION_KEYWORDS):
            continue
        if calculate_engagement_score(tweet) < (MIN_FAVES_THRESHOLD + MIN_RETWEETS_THRESHOLD + MIN_REPLIES_THRESHOLD):
            continue
        filtered_tweets.append(tweet)

    if not filtered_tweets:
        return None, None, None

    # Select the primary tweet with the highest engagement score
    for tweet in filtered_tweets:
        tweet_id_str = tweet.get('id_str')
        tweet_created_at_str = tweet.get('tweet_created_at')
        user_data = tweet.get('user', {})
        tweet_link = tweet_link_constructor(user_data.get('screen_name'), tweet_id_str)
        time_elapsed_minutes = calculate_time_elapsed_minutes(tweet_created_at_str)
        engagement_score = calculate_engagement_score(tweet)
        is_reply_status = tweet.get('in_reply_to_status_id_str') is not None
        is_quote_status = tweet.get('quoted_status_id_str') is not None
        is_original_tweet = not is_reply_status and not is_quote_status

        if engagement_score > max_engagement_score:
            max_engagement_score = engagement_score
            primary_tweet_object = tweet
            primary_tweet_data = {
                "primary_tweet_link": tweet_link,
                "time_elapsed_minutes": time_elapsed_minutes,
                "tweet_type_flags": {
                    "is_reply_status": is_reply_status,
                    "is_quote_status": is_quote_status,
                    "is_original_tweet": is_original_tweet
                },
                "user_info": {
                    "user_id_str": user_data.get('id_str'),
                    "screen_name": user_data.get('screen_name'),
                    "statuses_count": user_data.get('statuses_count'),
                    "followers_count": user_data.get('followers_count')
                }
            }
            primary_tweep_screen_name = user_data.get('screen_name')

        other_tweet_links.append(tweet_link)

    if primary_tweet_object and primary_tweep_screen_name:
        other_tweet_links = [link for link in other_tweet_links if not link.startswith(f"https://x.com/{primary_tweep_screen_name}/status/")]

    return primary_tweet_data, other_tweet_links, primary_tweet_object

# ------------------------------------------------------------------------------
# Supabase Operations Functions
# ------------------------------------------------------------------------------

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def fetch_tokens_for_processing_from_supabase() -> List[Dict[str, Any]]:
    """Fetches tokens eligible for Twitter checks from Supabase."""
    logger.info("Fetching tokens for Twitter check from Supabase (with retries)...")
    try:
        DB_OPERATIONS_TOTAL.labels(operation="select_tokens_for_twitter_check").inc()
        now = datetime.now(timezone.utc)
        five_minutes_ago = now - timedelta(minutes=RETRY_INTERVAL_UNDETERMINED_MINUTES)
        response = supabase_client.table("token_checks").select("token_address, chain").or_(
            f"twitter_check.eq.unchecked,and(twitter_check.eq.undetermined,last_checked.lt.{five_minutes_ago.isoformat()})"
        ).eq("status", "good").execute()
        if not response.data:
            SUPABASE_ERROR_COUNTER.labels(operation="select_tokens_for_twitter_check").inc()
            logger.warning(f"Supabase query returned empty data for tokens to process: {response}")
            return []
        return response.data
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="select_tokens_for_twitter_check").inc()
        logger.error(f"Error fetching tokens from Supabase: {e}")
        return []

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def fetch_spam_accounts_from_supabase(chain: str) -> List[str]:
    """Fetches spam account usernames for a given chain from Supabase using the array contains operator."""
    logger.debug(f"Fetching spam accounts for chain: {chain} from Supabase...")
    try:
        DB_OPERATIONS_TOTAL.labels(operation="select_spam_accounts").inc()
        response = supabase_client.table("twitter_blacklists").select("username").filter("chain", "cs", f'{{"{chain}"}}').execute()
        if not response.data:
            SUPABASE_ERROR_COUNTER.labels(operation="select_spam_accounts").inc()
            logger.warning(f"Supabase query returned empty data for spam accounts for chain {chain}: {response}")
            return []
        return [item['username'] for item in response.data if 'username' in item]
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="select_spam_accounts").inc()
        logger.error(f"Error fetching spam accounts from Supabase: {e}")
        return []

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def save_tweet_data_to_supabase(token_address: str, name: str, primary_tweet_data: Dict[str, Any], other_tweets_data: List[str]) -> bool:
    """Saves processed tweet data to the Supabase tweets_data table."""
    logger.debug(f"Saving tweet data for token: {token_address} to Supabase...")
    try:
        DB_OPERATIONS_TOTAL.labels(operation="insert_tweet_data").inc()
        data_to_insert = {
            "token_address": token_address,
            "name": name,
            "primary_tweet_data": primary_tweet_data,
            "other_tweets_data": other_tweets_data
        }
        response = supabase_client.table("tweets_data").insert(data_to_insert).execute()
        if not response.data:
            SUPABASE_ERROR_COUNTER.labels(operation="insert_tweet_data").inc()
            logger.error(f"Supabase insert error: {response}")
            return False
        TWEETS_SAVED_TOTAL.inc()
        logger.info(f"Tweet data saved to Supabase for token: {token_address}")
        return True
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="insert_tweet_data").inc()
        logger.error(f"Error saving tweet data to Supabase: {e}")
        return False

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
def update_token_check_status_supabase(token_address: str, twitter_check_status: str) -> bool:
    """Updates the Twitter check status and last_checked timestamp in the token_checks table."""
    logger.debug(f"Updating token_checks status for token: {token_address} to {twitter_check_status}...")
    try:
        DB_OPERATIONS_TOTAL.labels(operation="update_token_check_status").inc()
        now_iso = datetime.now(timezone.utc).isoformat()
        updates = {"twitter_check": twitter_check_status, "last_checked": now_iso}
        response = supabase_client.table("token_checks").update(updates).eq("token_address", token_address).execute()
        if not response.data:
            SUPABASE_ERROR_COUNTER.labels(operation="update_token_check_status").inc()
            logger.error(f"Supabase update error: {response}")
            return False
        logger.info(f"Token_checks status updated for token: {token_address} to {twitter_check_status}")
        return True
    except Exception as e:
        SUPABASE_ERROR_COUNTER.labels(operation="update_token_check_status").inc()
        logger.error(f"Error updating token_checks status in Supabase: {e}")
        return False

# ------------------------------------------------------------------------------
# Token Processing Function
# ------------------------------------------------------------------------------
def process_token_for_twitter_data(token_data: Dict[str, Any]) -> None:
    """Processes a single token by fetching its Twitter data, filtering and saving the results to Supabase."""
    token_address = token_data['token_address']
    chain = token_data['chain']
    logger.info(f"Processing Twitter data for token: {token_address} on {chain}...")
    
    spam_accounts = fetch_spam_accounts_from_supabase(chain)
    query = construct_socialdata_query(token_address, spam_accounts)
    api_response_data = fetch_twitter_data(query, SOCIALDATA_API_KEY)
    
    # If API call fails or returns empty tweets, mark token as undetermined.
    if api_response_data is None:
        logger.warning(f"Failed to fetch SocialData API data for token: {token_address} on {chain}. Marking as undetermined.")
        update_token_check_status_supabase(token_address, 'undetermined')
        return
    if not api_response_data.get('tweets'):
        logger.warning(f"SocialData API returned empty tweets for token: {token_address} on {chain}. Marking as undetermined. Response: {api_response_data}")
        update_token_check_status_supabase(token_address, 'undetermined')
        return

    primary_tweet_data, other_tweet_links, primary_tweet_object = process_tweet_data(api_response_data, tweet_link_constructor, spam_accounts)
    
    # Save tweet data if available; if no primary tweet passes the filter, still mark as checked.
    if primary_tweet_data:
        save_tweet_data_to_supabase(
            token_address=token_address,
            name=primary_tweet_object['user']['name'],
            primary_tweet_data=primary_tweet_data,
            other_tweets_data=other_tweet_links,
        )
    else:
        logger.info(f"No primary tweet data extracted for token: {token_address} on {chain}.")
    update_token_check_status_supabase(token_address, 'checked')

# ------------------------------------------------------------------------------
# Main Function (Execution Workflow)
# ------------------------------------------------------------------------------
def main() -> None:
    """Main function to concurrently fetch tokens from Supabase and process them for Twitter data."""
    global last_breaker_reset
    logger.info("Starting Twitter data fetch and save script.")
    
    initialize_supabase_client()
    start_http_server(PROMETHEUS_PORT)
    logger.info(f"Prometheus metrics server started on port {PROMETHEUS_PORT}")

    while not is_shutting_down:
        if time.time() - last_breaker_reset > BREAKER_RESET_INTERVAL:
            last_breaker_reset = time.time()
            logger.info("Circuit breakers reset timeout reached, allowing automatic reset attempt.")
        
        tokens_to_process = fetch_tokens_for_processing_from_supabase()
        if tokens_to_process:
            TOKENS_PROCESSED_TOTAL.inc(len(tokens_to_process))
            logger.info(f"Processing {len(tokens_to_process)} tokens concurrently for Twitter data.")
            with ThreadPoolExecutor(max_workers=THREAD_POOL_WORKERS) as executor:
                futures = {executor.submit(process_token_for_twitter_data, token): token for token in tokens_to_process}
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error processing token: {futures[future]}: {e}")
            # Clean up tokens from memory after processing the batch.
            del tokens_to_process
        else:
            logger.info("No new tokens to check. Waiting for next interval.")
        
        time.sleep(CHECK_INTERVAL_SECONDS)
        logger.info("Waiting for next interval before fetching new tokens.")
    
    logger.info("Twitter data fetch and save script stopped.")

# ------------------------------------------------------------------------------
# Signal Handling and Cleanup
# ------------------------------------------------------------------------------
def signal_handler(signum: int, frame: Any) -> None:
    """Handles shutdown signals to initiate graceful shutdown."""
    global is_shutting_down
    is_shutting_down = True
    logger.info("Shutdown signal received, initiating graceful shutdown...")

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

def cleanup() -> None:
    """Performs final cleanup tasks before exit."""
    logger.info("Cleanup completed.")

atexit.register(cleanup)

if __name__ == "__main__":
    main()
