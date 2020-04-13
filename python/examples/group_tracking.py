
# content of group_tracking.py

from deltachat import account_hookimpl, run_cmdline


class GroupTrackingPlugin:
    @account_hookimpl
    def ac_incoming_message(self, message):
        print("process_incoming message", message)
        if message.text.strip() == "/quit":
            message.account.shutdown()
        else:
            # unconditionally accept the chat
            message.accept_sender_contact()
            addr = message.get_sender_contact().addr
            text = message.text
            message.chat.send_text("echoing from {}:\n{}".format(addr, text))

    @account_hookimpl
    def ac_configure_completed(self, success):
        print("*** ac_configure_completed:", success)

    @account_hookimpl
    def ac_member_added(self, chat, contact):
        print("*** ac_member_added", contact.addr, "from", chat)
        for member in chat.get_contacts():
            print("chat member: {}".format(member.addr))

    @account_hookimpl
    def ac_member_removed(self, chat, contact):
        print("*** ac_member_removed", contact.addr, "from", chat)


def main(argv=None):
    run_cmdline(argv=argv, account_plugins=[GroupTrackingPlugin()])


if __name__ == "__main__":
    main()
