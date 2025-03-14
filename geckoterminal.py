#!/usr/bin/env python3
"""
Filename: geckoterminal.py
Description: This script fetches and processes token data from the GeckoTerminal API.
             It validates tokens against network-specific filters and stores new tokens in a Supabase database.
             The configuration can be overridden via an external config file.
Dependencies: asyncio, aiohttp, json, logging, aiolimiter, prometheus_client, supabase, dotenv
"""

import os
import json
import asyncio
import aiohttp
import logging
from datetime import datetime, timezone
from aiolimiter import AsyncLimiter

# Supabase integration
from dotenv import load_dotenv
from supabase import create_client, Client

# ---------------------------
# Prometheus Metrics Setup
# ---------------------------
from prometheus_client import start_http_server, Counter, Histogram

# Start HTTP server for Prometheus metrics on port 8000
start_http_server(8000)

# Define metrics for geckoterminal
GECKO_API_REQUESTS = Counter('gecko_api_requests_total', 'Total API requests made', ['network'])
GECKO_TOKENS_PROCESSED = Counter('gecko_tokens_processed_total', 'Total tokens processed', ['network'])
GECKO_NETWORK_PROCESSING_DURATION = Histogram('gecko_network_processing_duration_seconds', 'Time taken for processing a network', ['network'])
SUPABASE_REQUEST_COUNTER = Counter(
    "supabase_requests_total", "Total Supabase requests", ["operation"]
)
SUPABASE_ERROR_COUNTER = Counter(
    "supabase_errors_total", "Total Supabase errors", ["operation"]
)


# ---------------------------
# Logging Configuration
# ---------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------------------
# Default Configuration
# ---------------------------
BASE_API_URL = "https://api.geckoterminal.com/api/v2/networks/{network}/new_pools"
API_VERSION = "20230302"

# NETWORKS configuration with full objects rearranged to start with major chains.
NETWORKS = {
    "solana": {
        "filters": {
            "token_age": 5,
            "liquidity": 10000,
            "marketcap": {"min": 50000, "max": 1000000},
            "m15_buys": 15,
            "m15_sells": 1,
            "price_change": 100,
            "volume": 10000,
        },
        "max_valid_checks": 8
    },
    "eth": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 5000, "max": 500000},
            "m15_buys": 15,
            "m15_sells": 1,
            "price_change": 50,
            "volume": 1000,
        },
        "max_valid_checks": 5
    },
    "base": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 5000, "max": 500000},
            "m15_buys": 15,
            "m15_sells": 1,
            "price_change": 50,
            "volume": 1000,
        },
        "max_valid_checks": 8
    },
    "bsc": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 5000, "max": 500000},
            "m15_buys": 15,
            "m15_sells": 1,
            "price_change": 50,
            "volume": 1000,
        },
        "max_valid_checks": 5
    },
    "pulsechain": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 5000, "max": 20000},
            "m15_buys": 10,
            "m15_sells": 1,
            "price_change": 10,
            "volume": 1000,
        },
        "max_valid_checks": 2
    },
    "sonic": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 1000, "max": 200000},
            "m15_buys": 10,
            "m15_sells": 1,
            "price_change": 5,
            "volume": 1000,
        },
        "max_valid_checks": 7
    },
    "berachain": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 1000, "max": 200000},
            "m15_buys": 10,
            "m15_sells": 1,
            "price_change": 5,
            "volume": 1000,
        },
        "max_valid_checks": 5
    },
    "ink": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 1000, "max": 200000},
            "m15_buys": 10,
            "m15_sells": 1,
            "price_change": 50,
            "volume": 1000,
        },
        "max_valid_checks": 3
    },
    "xrpl": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 1000, "max": 200000},
            "m15_buys": 10,
            "m15_sells": 1,
            "price_change": 5,
            "volume": 1000,
        },
        "max_valid_checks": 4
    },
    "abstract": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 1000, "max": 200000},
            "m15_buys": 10,
            "m15_sells": 1,
            "price_change": 5,
            "volume": 1000,
        },
        "max_valid_checks": 2
    },
    "story": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 1000, "max": 200000},
            "m15_buys": 10,
            "m15_sells": 1,
            "price_change": 5,
            "volume": 1000,
        },
        "max_valid_checks": 3
    },
    "ton": {
        "filters": {
            "token_age": 5,
            "liquidity": 1000,
            "marketcap": {"min": 1000, "max": None},
            "m15_buys": 10,
            "m15_sells": 1,
            "price_change": 10,
            "volume": 1000,
        },
        "max_valid_checks": 3
    }
}

RATE_LIMIT = 30
SLEEP_BETWEEN_NETWORKS = 5
MAX_RETRIES = 3
RETRY_DELAY = 2
SUPABASE_TABLE_NAME = "tokens_to_check"

# ---------------------------
# Load External Configuration
# ---------------------------
CONFIG_FILE = "config_gecko.json"
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
            BASE_API_URL = config.get("BASE_API_URL", BASE_API_URL)
            API_VERSION = config.get("API_VERSION", API_VERSION)
            NETWORKS = config.get("NETWORKS", NETWORKS)
            RATE_LIMIT = config.get("RATE_LIMIT", RATE_LIMIT)
            SLEEP_BETWEEN_NETWORKS = config.get("SLEEP_BETWEEN_NETWORKS", SLEEP_BETWEEN_NETWORKS)
            MAX_RETRIES = config.get("MAX_RETRIES", MAX_RETRIES)
            RETRY_DELAY = config.get("RETRY_DELAY", RETRY_DELAY)
        logging.info("Loaded configuration from config_gecko.json")
    except Exception as e:
        logging.error(f"Error loading configuration from {CONFIG_FILE}: {e}")

limiter = AsyncLimiter(RATE_LIMIT, 60)

# ----------------------------------
# Supabase Client Initialization
# ----------------------------------
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    logging.critical("Supabase URL and Key must be set in environment variables.")
    exit(1)

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    logging.info("Successfully initialized Supabase client.")
except Exception as e:
    logging.critical(f"Failed to initialize Supabase client: {e}")
    exit(1)


def validate_token(attributes, filters):
    try:
        now = datetime.now(timezone.utc)
        token_age = datetime.fromisoformat(attributes["pool_created_at"].replace("Z", "+00:00"))
        token_age_diff = (now - token_age).total_seconds() / 60
        liquidity = float(attributes["reserve_in_usd"])
        marketcap = float(attributes["fdv_usd"]) if attributes.get("fdv_usd") else 0
        marketcap_min = filters["marketcap"]["min"]
        marketcap_max = filters["marketcap"].get("max")
        m15_buys = attributes["transactions"]["m15"]["buys"]
        m15_sells = attributes["transactions"]["m15"]["sells"]
        price_change = float(attributes["price_change_percentage"]["h24"])
        volume = float(attributes["volume_usd"]["h1"])
        return (
            token_age_diff <= filters["token_age"] and
            liquidity >= filters["liquidity"] and
            (marketcap >= marketcap_min and (marketcap <= marketcap_max if marketcap_max is not None else True)) and
            m15_buys >= filters["m15_buys"] and
            m15_sells >= filters["m15_sells"] and
            price_change >= filters["price_change"] and
            volume >= filters["volume"]
        )
    except Exception as e:
        logging.error(f"Validation error: {e}")
        return False

def build_url_with_page(network, page):
    return f"{BASE_API_URL.format(network=network)}?page={page}"

async def fetch_tokens(session, url, network):
    for attempt in range(1, MAX_RETRIES + 1):
        async with limiter:
            try:
                async with session.get(url, headers={"Accept": f"application/json;version={API_VERSION}"}) as response:
                    response.raise_for_status()
                    GECKO_API_REQUESTS.labels(network=network).inc()
                    data = await response.json()
                    return data.get("data", [])
            except aiohttp.ClientError as e:
                logging.warning(f"Attempt {attempt} - Client error while fetching data from {url}: {e}. Retrying...")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_DELAY * attempt)
                else:
                    logging.error(f"Max retries reached for {url}. Skipping.")
                    return []
            except Exception as e:
                logging.error(f"Unexpected error fetching data from {url}: {e}")
                return []

async def process_network(network, session):
    new_tokens_count = 0 # Track number of tokens inserted to DB
    filters = NETWORKS[network]["filters"]
    max_valid_checks = NETWORKS[network]["max_valid_checks"]

    # Time the processing of this network
    with GECKO_NETWORK_PROCESSING_DURATION.labels(network=network).time():
        valid_check_count = 0
        for page in range(1, 11):
            url = build_url_with_page(network, page)
            tokens = await fetch_tokens(session, url, network)
            if not tokens:
                logging.info(f"No data found on page {page} for network {network}. Stopping further requests.")
                break
            page_has_valid_tokens = False
            for token in tokens:
                attributes = token.get("attributes", {})
                if validate_token(attributes, filters):
                    page_has_valid_tokens = True
                    relationships = token.get("relationships", {})
                    base_token_data = relationships.get("base_token", {}).get("data", {})
                    base_token_id = base_token_data.get("id", "")
                    if base_token_id:
                        if network == "xrpl":
                            address = base_token_id.rsplit('.', 1)[-1]
                        else:
                            address = base_token_id.split('_', 1)[-1]
                    else:
                        address = "Unknown"
                    token_data = {
                        "token_address": address,
                        "chain": network,
                        "status": "unchecked",
                    }

                    try:
                        # Check if token already exists in Supabase
                        SUPABASE_REQUEST_COUNTER.labels(operation="select_token_exists").inc()
                        response = supabase.table(SUPABASE_TABLE_NAME).select("*").eq("token_address", token_data["token_address"]).eq("chain", network).execute()
                        if response.data is None: # Correct error check: if response.data is None
                            SUPABASE_ERROR_COUNTER.labels(operation="select_token_exists").inc()
                            logging.error(f"Supabase select error for token {token_data['token_address']} on {network}: {response.error}") # Keep logging response.error for detail
                        elif not response.data: # If no data is returned (but no error), token doesn't exist
                            # Insert token data into Supabase
                            SUPABASE_REQUEST_COUNTER.labels(operation="insert_token").inc()
                            insert_response = supabase.table(SUPABASE_TABLE_NAME).insert(token_data).execute()
                            if insert_response.data is None: # Correct error check for insert_response
                                SUPABASE_ERROR_COUNTER.labels(operation="insert_token").inc()
                                logging.error(f"Supabase insert error for token {token_data['token_address']} on {network}: {insert_response.error}") # Keep logging insert_response.error
                            else:
                                new_tokens_count += 1
                                logging.info(f"Inserted token {token_data['token_address']} on {network} into Supabase.")
                        else:
                            logging.debug(f"Token {token_data['token_address']} on {network} already exists in Supabase. Skipping insertion.")

                    except Exception as db_error:
                        SUPABASE_ERROR_COUNTER.labels(operation="db_operation_error").inc()
                        logging.error(f"Database operation failed for token {token_data['token_address']} on {network}: {db_error}")


            if page_has_valid_tokens:
                valid_check_count = 0
            else:
                valid_check_count += 1
                logging.info(f"No valid tokens on page {page} for {network}")
                if valid_check_count >= max_valid_checks:
                    logging.info(f"Maximum valid checks reached for {network}. Stopping further requests.")
                    break


    GECKO_TOKENS_PROCESSED.labels(network=network).inc(new_tokens_count) # Update count with inserted tokens
    logging.info(f"Processed and inserted {new_tokens_count} new token(s) into Supabase for {network}") # Reflect DB insert in log message

async def main():
    async with aiohttp.ClientSession() as session:
        try:
            while True:
                for network in NETWORKS.keys():
                    logging.info(f"Processing network: {network}")
                    await process_network(network, session)
                    logging.info(f"Completed network: {network}. Sleeping for {SLEEP_BETWEEN_NETWORKS} seconds...")
                    await asyncio.sleep(SLEEP_BETWEEN_NETWORKS)
        except asyncio.CancelledError:
            logging.info("Program shutting down gracefully.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except RuntimeError as e:
        if "asyncio.run() cannot be called" in str(e):
            loop = asyncio.get_event_loop()
            loop.run_until_complete(main())