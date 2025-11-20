#!/usr/bin/env python3
"""One-Shot Notification via Delta Chat

Sends encrypted message to first available chat.
Uses existing account from accounts directory.

Usage:
    ./send.py "Message as argument"
    echo "Message via stdin" | ./send.py

    # With custom accounts directory:
    ACCOUNTS_DIR=/path/to/accounts ./send.py "Message"

Requirements:
    - deltachat-rpc-server running or installed
    - deltachat-rpc-client installed
    - Existing configured account in accounts directory
    - At least one chat created (via Delta Chat app)

Example:
    # From cronjob:
    echo "Backup completed" | ./send.py

    # From monitoring:
    ./send.py "CPU usage > 90%"
"""

import os
import sys
import time
from pathlib import Path

from deltachat_rpc_client import DeltaChat, Rpc

# Default accounts directory (can be overridden via environment)
ACCOUNTS_DIR = os.environ.get("ACCOUNTS_DIR", "/opt/dechat/accounts")


def send_notification(message: str, accounts_dir: str = ACCOUNTS_DIR) -> None:
    """
    Send notification message via Delta Chat.

    This function:
    1. Connects to RPC server
    2. Loads first available account
    3. Gets chatlist
    4. Sends message to first chat

    Args:
        message: Text message to send
        accounts_dir: Path to Delta Chat accounts directory

    Raises:
        SystemExit: On errors (no accounts, no chats, etc.)
    """
    # Validate accounts directory exists
    if not Path(accounts_dir).exists():
        print(f"❌ Accounts directory not found: {accounts_dir}")
        print("   Set ACCOUNTS_DIR environment variable or create directory")
        sys.exit(1)

    # Start RPC connection
    rpc = Rpc(accounts_dir=accounts_dir)
    rpc.start()

    try:
        dc = DeltaChat(rpc)

        # Load account (REAL API: get_all_accounts)
        # Source: deltachat.py:get_all_accounts() -> list[Account]
        accounts = dc.get_all_accounts()

        if not accounts:
            print(f"❌ No accounts found in {accounts_dir}")
            print("   Configure an account first using Delta Chat app or Bot.configure()")
            rpc.close()
            sys.exit(1)

        account = accounts[0]  # Use first account

        # Get account email for better error messages
        try:
            account_email = account.get_config("addr")
            print(f"✓ Using account: {account_email}")
        except Exception:
            account_email = "unknown"

        # Start IO (required for sending messages)
        # Source: echobot_no_hooks.py shows start_io() is needed
        account.start_io()

        # Give IO a moment to initialize
        time.sleep(0.5)

        # Get chatlist (REAL API: get_chatlist)
        # Source: account.py:get_chatlist() -> list[Chat]
        chats = account.get_chatlist()

        if not chats:
            print(f"❌ No chats found for {account_email}")
            print("   Create a chat first using Delta Chat app")
            print("   Tip: Send a message to someone to create a chat")
            account.stop_io()
            rpc.close()
            sys.exit(1)

        # Send to first chat (REAL API: send_text)
        # Source: chat.py:send_text(text: str) -> Message
        chat = chats[0]

        # Get chat name for better feedback
        try:
            snapshot = chat.get_basic_snapshot()
            chat_name = snapshot.name
            print(f"✓ Sending to chat: {chat_name}")
        except Exception:
            chat_name = "unknown"
            print("✓ Sending to first chat")

        # Send message
        msg = chat.send_text(message)
        print(f"✓ Message sent successfully (msg_id: {msg.id})")

        # Give some time for message to be sent
        time.sleep(1)

        # Cleanup
        account.stop_io()

    finally:
        rpc.close()


def main():
    """Main entry point for CLI usage."""
    # Parse message from CLI argument or stdin
    if len(sys.argv) >= 2:
        # Use arguments (join multiple args with spaces)
        message = " ".join(sys.argv[1:])
    else:
        # Try to read from stdin (for piping)
        message = sys.stdin.read().strip() if not sys.stdin.isatty() else ""

    # Validate message
    if not message:
        print("Delta Chat One-Shot Notification Sender")
        print()
        print("Usage:")
        print("  ./send.py 'Your message here'")
        print("  echo 'Your message' | ./send.py")
        print()
        print("Environment:")
        print(f"  ACCOUNTS_DIR={ACCOUNTS_DIR}")
        print()
        print("Example:")
        print("  ./send.py 'Server backup completed'")
        print("  echo 'CPU usage critical' | ./send.py")
        sys.exit(1)

    # Send notification
    send_notification(message)


if __name__ == "__main__":
    main()
