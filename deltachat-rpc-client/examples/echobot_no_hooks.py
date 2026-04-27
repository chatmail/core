#!/usr/bin/env python3
"""
Example echo bot without using hooks
"""

import logging
import sys

from deltachat_rpc_client import DeltaChat, EventType, Rpc, SpecialContactId


def main():
    with Rpc() as rpc:
        deltachat = DeltaChat(rpc)
        system_info = deltachat.get_system_info()
        logging.info(f"Running deltachat core {system_info['deltachat_core_version']}")

        accounts = deltachat.get_all_accounts()
        account = accounts[0] if accounts else deltachat.add_account()

        account.set_config("bot", "1")
        if not account.is_configured():
            logging.info("Account is not configured, configuring")
            account.add_or_update_transport({"addr": sys.argv[1], "password": sys.argv[2]})
            logging.info("Configured")
        else:
            logging.info("Account is already configured")
            deltachat.start_io()

        qr = account.get_qr_code()
        logging.info(f"Invite link: {qr}")
        while True:
            event = account.wait_for_event()
            if event.kind == EventType.INFO:
                logging.info(event["msg"])
            elif event.kind == EventType.WARNING:
                logging.warning(event["msg"])
            elif event.kind == EventType.ERROR:
                logging.error(event["msg"])
            elif event.kind == EventType.INCOMING_MSG:
                logging.info("Got an incoming message")
                message = account.get_message_by_id(event.msg_id)
                snapshot = message.get_snapshot()
                if snapshot.from_id != SpecialContactId.SELF and not snapshot.is_bot and not snapshot.is_info:
                    snapshot.chat.send_text(snapshot.text)
                snapshot.message.mark_seen()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
