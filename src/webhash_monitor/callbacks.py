"""
callbacks.py

WebHash Monitor Callback Handlers

This module provides notification callbacks that can be triggered when a
monitored webpage change is detected by the WebHash Monitor.

Callbacks are optional and can be dynamically selected via configuration.
Each callback is expected to follow a simple interface: it receives relevant
event data (e.g., a URL) and performs a side effect such as sending a
notification.

Currently implemented callbacks:
    - Pushbullet:
        Sends a notification using the Pushbullet REST API when a webpage
        change is detected. Requires a valid API key provided via environment
        variable `PUSHBULLET_API_KEY`.

Environment:
    PUSHBULLET_API_KEY:
        API token used to authenticate with the Pushbullet service.
        Typically loaded from a `.env` file.

Design Notes:
    - Callbacks are designed to be lightweight and non-blocking.
    - They should not raise unhandled exceptions that disrupt monitoring.
    - Additional callbacks (e.g., email, Slack, webhook) can be added by
      following the same function signature.

Author: NenshaM
License: GPL v3
"""

import os

import requests
from dotenv import load_dotenv

# Load environment variables from a .env file into the process environment
load_dotenv()


def send_pushbullet_note(url: str) -> dict:
    """
    Send a Pushbullet notification indicating that a monitored URL has changed.

    Args:
        url (str): The URL that triggered the notification (e.g., a changed webpage).

    Returns:
        dict: The JSON response returned by the Pushbullet API.

    Raises:
        ValueError: If the API key is not found in the environment.
        requests.HTTPError: If the HTTP request to Pushbullet fails.

    Example:
        >>> send_pushbullet_note("https://example.com")
    """
    title = "Webhash-Monitor"
    body = f"URL changed: {url}"

    # Read API key from environment
    api_key = os.getenv("PUSHBULLET_API_KEY")
    if not api_key:
        raise ValueError("Missing PUSHBULLET_API_KEY in .env")

    api_url = "https://api.pushbullet.com/v2/pushes"
    headers = {
        "Access-Token": api_key,
        "Content-Type": "application/json",
    }

    # Payload for a simple note push
    data = {
        "type": "note",
        "title": title,
        "body": body,
    }
    response = requests.post(api_url, json=data, headers=headers)

    # Raise an exception for HTTP errors (4xx, 5xx)
    response.raise_for_status()

    return response.json()


def send_telegram_msg(url: str):
    """
    Send a Telegram message indicating that a monitored URL has changed.

    Args:
        url (str): The URL that triggered the notification (e.g., a changed webpage).

    Returns:
        dict: The JSON response returned by the Telegram API.

    Raises:
        ValueError: If the API key is not found in the environment.
        requests.HTTPError: If the HTTP request to Telegram fails.

    Example:
        >>> send_telegram_msg("https://example.com")
    """
    msg = f"URL changed: {url}"

    # Read API key from environment
    api_key = os.getenv("TELEGRAM_API_KEY")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not api_key or not chat_id:
        raise ValueError("Missing TELEGRAM_API_KEY or TELEGRAM_CHAT_ID in .env")

    api_url = f"https://api.telegram.org/bot{api_key}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": msg,
        "parse_mode": "HTML",  # Optional: allows bold/italic tags
    }
    response = requests.post(api_url, data=payload)
    return response.json()


if __name__ == "__main__":
    send_pushbullet_note("test.url")
    send_telegram_msg("test.url")
