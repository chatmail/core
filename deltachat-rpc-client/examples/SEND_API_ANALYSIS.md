# API-Analyse deltachat-rpc-client

Dieses Dokument beschreibt die **echte API** von `deltachat-rpc-client` basierend auf Source Code Analyse der GitHub-Repositories.

## Übersicht

Analysierte Quellen:
- `deltachat-core-rust/deltachat-rpc-client/src/deltachat_rpc_client/deltachat.py`
- `deltachat-core-rust/deltachat-rpc-client/src/deltachat_rpc_client/account.py`
- `deltachat-core-rust/deltachat-rpc-client/src/deltachat_rpc_client/chat.py`
- `deltachat-core-rust/deltachat-rpc-client/examples/echobot_no_hooks.py`
- `deltachat-core-rust/deltachat-rpc-client/tests/test_something.py`

---

## DeltaChat Klasse

**Datei:** `deltachat.py`

Die `DeltaChat` Klasse ist "the root of the object oriented API" für Delta Chat Account Management.

### Wichtige Methoden

#### `__init__(rpc: Rpc) -> None`
Initialisiert den Account Manager mit einer RPC-Verbindung.

**Beispiel:**
```python
from deltachat_rpc_client import Rpc, DeltaChat

rpc = Rpc(accounts_dir="/path/to/accounts")
rpc.start()
dc = DeltaChat(rpc)
```

#### `get_all_accounts() -> list[Account]`
**Die Methode zum Account-Laden!**

Gibt eine Liste aller verfügbaren Accounts zurück.

**Beispiel:**
```python
accounts = dc.get_all_accounts()

if not accounts:
    print("Keine Accounts gefunden!")
    sys.exit(1)

# Ersten Account verwenden
account = accounts[0]
```

**Wichtig:** Es gibt KEINE `get_account(id)` Methode! Nur `get_all_accounts()`.

#### `add_account() -> Account`
Erstellt einen neuen Account und gibt ihn zurück.

#### `start_io() -> None`
Startet I/O für alle Accounts.

#### `stop_io() -> None`
Stoppt I/O für alle Accounts.

---

## Account Klasse

**Datei:** `account.py`

Die `Account` Klasse repräsentiert einen konfigurierten Delta Chat Account.

### Chat-Management

#### `get_chatlist(...) -> list[Chat]`
**Die Methode zum Chats-Holen!**

Gibt eine Liste von Chats zurück.

**Signatur:**
```python
def get_chatlist(
    query: Optional[str] = None,
    contact: Optional[Contact] = None,
    archived_only: bool = False,
    for_forwarding: bool = False,
    no_specials: bool = False,
    alldone_hint: bool = False,
    snapshot: bool = False
) -> Union[list[Chat], list[AttrDict]]
```

**Parameter:**
- `query`: Textsuche für Chat-Namen
- `contact`: Filter nach spezifischem Kontakt
- `archived_only`: Nur archivierte Chats
- `for_forwarding`: Chats zum Forwarding
- `no_specials`: Spezial-Chats ausschließen
- `alldone_hint`: Alle-gelesen Hinweis
- `snapshot`: Gibt AttrDict mit Details zurück statt Chat-Objekte

**Beispiele:**
```python
# Alle Chats
chats = account.get_chatlist()

# Nach Name filtern
chats = account.get_chatlist(query="Broadcast channel!")

# Mit Snapshots für Details
chats = account.get_chatlist(snapshot=True)

# Ersten Chat nehmen
if chats:
    chat = chats[0]
```

**Quelle:** `test_something.py:get_broadcast()`

#### `get_chat_by_id(chat_id: int) -> Chat`
Holt einen spezifischen Chat per ID.

#### `get_chat_by_contact(contact: Union[int, Contact]) -> Optional[Chat]`
Holt Chat mit spezifischem Kontakt.

### I/O Management

#### `start_io() -> None`
**Wichtig für One-Shot Sending!**

Startet Netzwerk-I/O für den Account. Muss aufgerufen werden bevor Nachrichten gesendet werden.

**Beispiel:**
```python
account.start_io()
# ... Nachrichten senden ...
account.stop_io()  # Cleanup
```

**Quelle:** `echobot_no_hooks.py` zeigt `start_io()` Nutzung

#### `stop_io() -> None`
Stoppt Netzwerk-I/O.

### Nachrichten

#### `get_next_messages() -> list[Message]`
Holt nächste Batch von Nachrichten (für Bots).

**Quelle:** `echobot_no_hooks.py:process_messages()`

#### `get_fresh_messages() -> list[Message]`
Holt neue ungelesene Nachrichten.

### Konfiguration

#### `get_config(key: str) -> str`
Holt Config-Wert (z.B. E-Mail-Adresse).

**Beispiel:**
```python
email = account.get_config("addr")
password = account.get_config("mail_pw")
```

#### `configure() -> None`
Konfiguriert Account mit gesetzten Config-Werten.

---

## Chat Klasse

**Datei:** `chat.py`

Die `Chat` Klasse repräsentiert eine Konversation.

### Nachrichten Senden

#### `send_text(text: str) -> Message`
**Die einfachste Methode zum Senden!**

Sendet eine Text-Nachricht.

**Beispiel:**
```python
msg = chat.send_text("Hello World!")
print(f"Message sent with ID: {msg.id}")
```

**Quelle:** `chat.py`, `echobot_no_hooks.py:process_messages()`

#### `send_message(...) -> Message`
Flexiblere Methode mit mehr Optionen.

**Signatur:**
```python
def send_message(
    text=None,
    html=None,
    viewtype=None,
    file=None,
    filename=None,
    location=None,
    override_sender_name=None,
    quoted_msg=None
) -> Message
```

**Parameter:**
- `text`: Text-Inhalt
- `html`: HTML-Inhalt
- `viewtype`: Message-Typ
- `file`: Datei-Pfad
- `filename`: Dateiname-Override
- `location`: Standort
- `override_sender_name`: Sender-Name überschreiben
- `quoted_msg`: Zitierte Nachricht

#### `send_file(path) -> Message`
Sendet eine Datei.

#### `send_sticker(path: str) -> Message`
Sendet einen Sticker.

### Chat-Informationen

#### `get_basic_snapshot() -> AttrDict`
Holt Basis-Informationen über Chat.

**Beispiel:**
```python
snapshot = chat.get_basic_snapshot()
print(f"Chat name: {snapshot.name}")
```

**Quelle:** `test_something.py:test_leave_broadcast()`

#### `get_full_snapshot() -> AttrDict`
Holt vollständige Chat-Informationen.

### Andere Methoden

- `get_messages()`: Holt Nachrichten aus Chat
- `get_fresh_message_count()`: Anzahl neuer Nachrichten
- `mark_noticed()`: Chat als gesehen markieren
- `delete()`, `block()`, `accept()`, `leave()`: Chat-Lifecycle
- `archive()`, `unarchive()`, `pin()`, `unpin()`: Organisation
- `mute()`, `unmute()`: Benachrichtigungen

---

## Vollständiger Workflow: One-Shot Message Senden

Basierend auf der echten API:

```python
#!/usr/bin/env python3
from deltachat_rpc_client import Rpc, DeltaChat
import sys

# 1. RPC starten
rpc = Rpc(accounts_dir="/opt/dechat/accounts")
rpc.start()

try:
    dc = DeltaChat(rpc)

    # 2. Account laden (ECHTE API!)
    accounts = dc.get_all_accounts()
    if not accounts:
        print("❌ Keine Accounts!")
        sys.exit(1)

    account = accounts[0]

    # 3. I/O starten (WICHTIG!)
    account.start_io()

    # 4. Chatliste holen (ECHTE API!)
    chats = account.get_chatlist()
    if not chats:
        print("❌ Keine Chats!")
        sys.exit(1)

    # 5. Nachricht senden (ECHTE API!)
    chat = chats[0]
    msg = chat.send_text("Meine Nachricht")

    print(f"✓ Nachricht gesendet (ID: {msg.id})")

    # 6. Cleanup
    account.stop_io()

finally:
    rpc.close()
```

---

## Häufige Fehler (zu vermeiden)

### ❌ `get_account(id)` existiert nicht!
```python
# FALSCH:
account = dc.get_account(1)  # AttributeError!

# RICHTIG:
accounts = dc.get_all_accounts()
account = accounts[0]
```

### ❌ `set_config()` auf DeltaChat existiert nicht!
```python
# FALSCH:
dc.set_config(account_id, "addr", email)  # AttributeError!

# RICHTIG:
account = dc.get_all_accounts()[0]
# Config ist bereits im Account gesetzt
```

### ❌ IO nicht starten
```python
# FALSCH (Nachricht wird nicht gesendet):
account = accounts[0]
chat.send_text("Test")  # Wird nicht versendet!

# RICHTIG:
account = accounts[0]
account.start_io()  # I/O starten!
chat.send_text("Test")
```

### ❌ Falsche Chatlist-Methode
```python
# FALSCH:
chats = account.get_chats()  # Existiert nicht!

# RICHTIG:
chats = account.get_chatlist()
```

---

## Quellen-Referenzen

### Python-Dateien (Source of Truth)
- `deltachat.py:DeltaChat.get_all_accounts()` - Account-Loading
- `account.py:Account.get_chatlist()` - Chat-Liste
- `chat.py:Chat.send_text()` - Nachricht senden
- `account.py:Account.start_io()` - I/O starten

### Funktionierende Beispiele
- `examples/echobot_no_hooks.py` - Zeigt Account-Loading und Message-Handling
- `tests/test_something.py` - Zeigt get_chatlist() Nutzung
- `tests/conftest.py` - Zeigt Account-Setup

### Dokumentation
- [py.delta.chat/jsonrpc](https://py.delta.chat/jsonrpc/reference.html) - Kann veraltet sein!
- **Immer Source Code checken!** - Code ist die Wahrheit

---

## Zusammenfassung

| Aufgabe | Methode | Quelle |
|---------|---------|--------|
| RPC starten | `Rpc(accounts_dir=path).start()` | rpc.py |
| Account laden | `DeltaChat.get_all_accounts()[0]` | deltachat.py |
| I/O starten | `Account.start_io()` | account.py |
| Chats holen | `Account.get_chatlist()` | account.py |
| Nachricht senden | `Chat.send_text(text)` | chat.py |
| Cleanup | `Account.stop_io()`, `Rpc.close()` | account.py, rpc.py |

**Alle Methoden sind verifiziert gegen den echten Source Code!** ✓
