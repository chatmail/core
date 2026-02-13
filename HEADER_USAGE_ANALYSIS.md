# Header Usage Analysis: Receive Message Pipeline

**Question**: Is the receive message pipeline doing anything with received headers, other than passing them to UIs for display as "message info"?

**Answer**: **YES - Headers are extensively used for critical business logic, far beyond UI display.**

## Executive Summary

The Delta Chat receive message pipeline (`src/receive_imf.rs` and `src/mimeparser.rs`) uses email headers as the **primary control plane** for:
- Message routing and chat assignment
- Group membership operations
- Encryption and key management
- Mailing list detection and processing
- Message threading and relationships
- Content type transformations
- System notifications generation
- Message edit/delete operations

Headers are **not merely metadata for display** - they drive fundamental decisions about how messages are processed, where they are stored, and what actions are triggered.

## Key Finding Categories

### 1. Message Routing & Chat Assignment

Headers determine **which chat receives the message**:

| Header | Purpose | Code Reference |
|--------|---------|----------------|
| `Chat-Group-ID` | Routes to specific group chat | `receive_imf.rs` ~650-1000 |
| `List-ID` | Identifies mailing list, creates/routes to list chat | `mimeparser.rs` ~1975 |
| `In-Reply-To` + `References` | Finds parent message for threading | `get_parent_message()` |
| `Chat-Version` | Distinguishes Delta Chat from regular email | Throughout pipeline |

**Impact**: Without these headers, messages would go to wrong chats or create duplicate conversations.

### 2. Mailing List Special Processing

**Detection Methods** (mimeparser.rs ~1975-2005):
```rust
pub(crate) fn get_mailinglist_header() -> Option<&str>  // Returns List-ID
pub(crate) fn is_mailinglist_message() -> bool          // True if List-ID present
pub(crate) fn is_schleuder_message() -> bool            // Special encrypted list
```

**Special Behaviors Triggered**:
- **Footer removal**: Strips list software footers from message text (except Schleuder)
- **Contact renaming prevention**: Ignores display-name changes from list software
- **Footer parsing suppression**: Skips signature extraction for list messages
- **Different chat creation logic**: Uses list name instead of sender

**Code**: `mimeparser.rs` lines 857, 607, 1962

### 3. Group Management Operations

**Member Management Headers**:
| Header | Operation | Code Location |
|--------|-----------|---------------|
| `Chat-Group-Member-Added` | Adds member to group | `receive_imf.rs` ~1600 |
| `Chat-Group-Member-Removed` | Removes member from group | `receive_imf.rs` ~1500 |
| `Chat-Group-Member-Timestamps` | Records member addition times | `mimeparser.rs` ~2060 |
| `Chat-Group-Member-Fpr` | Stores member key fingerprints | `mimeparser.rs` ~2073 |

**Metadata Management Headers**:
- `Chat-Group-Name` + `Chat-Group-Name-Timestamp` → Group name changes with conflict resolution
- `Chat-Group-Description` + `Chat-Group-Description-Timestamp` → Description updates
- `Chat-Group-Avatar` → Group avatar updates (binary data in header)

**Without these headers**: Group operations would fail; members couldn't be added/removed remotely.

### 4. Encryption & Security

**Key Distribution** (mimeparser.rs ~440-483, ~2117-2175):
- `Autocrypt` header: Contains sender's public key for future encrypted replies
- `Autocrypt-Gossip` header: Distributes other participants' keys in encrypted group messages
  - Validates addresses match To/Cc list (security check)
  - Saves keys to database for future use
- `Secure-Join` header: Coordinates Autocrypt key verification protocol

**Header Security Boundaries** (mimeparser.rs ~2228-2247):

Protected headers (only trusted from encrypted sections):
- All `chat-*` headers
- `from`, `to`, `cc`, `message-id`, `in-reply-to`, `references`
- Security-critical routing headers

**Impact**: Encryption decisions, key management, and trust establishment depend entirely on header processing.

### 5. System Message Generation

Headers trigger **synthetic system messages** displayed in chat (mimeparser.rs ~744-784):

| Header | System Message Generated |
|--------|--------------------------|
| `Chat-Content: location-streaming-enabled` | "Location streaming enabled" |
| `Chat-Content: ephemeral-timer-changed` | "Ephemeral timer changed to X" |
| `Chat-Group-Member-Removed` | "Alice removed Bob" |
| `Chat-Group-Member-Added` | "Alice added Bob" |
| `Chat-Group-Name-Changed` | "Alice changed group name to X" |
| `Autocrypt-Setup-Message` | Special setup message UI |

**Code Flow**: Headers → `SystemMessage` enum → Displayed as system notification in chat.

### 6. Content Transformation

Headers **change how message content is interpreted**:

| Header | Transformation | Code |
|--------|----------------|------|
| `Chat-Duration` | Sets audio/video duration metadata | Line 894 |
| `Chat-Voice-Message` | Converts Audio → VoiceMsg type | Line 881 |
| `Chat-Content: sticker` | Marks image as sticker (no caption) | Line 886 |
| `Chat-Webrtc-Room` | Sets up video call metadata | Line 800-827 |
| `Chat-Content: call` | Marks as call invitation | Various |

**Result**: Same binary attachment (e.g., audio file) displays differently based on headers.

### 7. Message Operations

**Edit/Delete Headers** (receive_imf.rs ~855):
- `Chat-Edit`: Contains Message-ID of message to edit
- `Chat-Delete`: Space-separated Message-IDs to delete

**Processing**: These messages **skip normal insertion** - they only modify/delete existing messages.

### 8. Bot & Automation Detection

**Headers Used**:
- `Auto-Submitted`: Marks sender as bot/automated system
- `Precedence: bulk`: Identifies automated mailings

**Impact**: Contact is marked as bot; affects notification behavior and UI display.

### 9. Message Threading & Reports

**Threading**:
- `In-Reply-To` + `References`: Builds conversation threads
- `Message-ID`: Unique identifier for deduplication

**Reports (NDN/MDN)**:
- `Disposition-Notification-To`: Requests read receipt
- `Original-Message-ID`: Links report to original message

## Code Architecture: Header Processing Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. MIME Parsing (mimeparser.rs)                            │
│    - parse_mime()                                           │
│    - merge_headers() ← Merges outer + encrypted headers    │
│    - get_header(HeaderDef) ← Generic header accessor       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Security Validation (mimeparser.rs ~2228-2255)          │
│    - is_protected() ← Only from encrypted parts?            │
│    - is_hidden() ← Parse from mixed/signed only?            │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Message Classification (receive_imf.rs)                 │
│    - get_chat_group_id() ← Group chat?                      │
│    - get_mailinglist_header() ← Mailing list?               │
│    - get_parent_message() ← Thread reply?                   │
│    - is_system_message() ← System notification?             │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Chat Assignment (receive_imf.rs ~650-1000)              │
│    Decision: Group | Mailing List | 1:1 | Trash            │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Business Logic Execution                                 │
│    - add_group_member() ← Chat-Group-Member-Added           │
│    - remove_group_member() ← Chat-Group-Member-Removed      │
│    - save_gossip_keys() ← Autocrypt-Gossip                  │
│    - set_msg_reaction() ← Chat-Content: reaction            │
│    - handle_edit_delete() ← Chat-Edit / Chat-Delete         │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Database Insertion                                       │
│    - Headers stored in messages.mime_headers (BLOB)         │
│    - HeaderDef values extracted for specific columns        │
│    - Some headers drive computed fields (is_bot, etc.)      │
└─────────────────────────────────────────────────────────────┘
```

## Specific Code Examples

### Example 1: List-ID Header Determines Footer Removal

**File**: `src/mimeparser.rs` line ~1962
```rust
pub(crate) fn get_mailinglist_footer(&self) -> Option<&str> {
    if self.is_mailinglist_message() {
        if self.is_schleuder_message() {
            // Schleuder has different structure
            return None;
        }
        // Remove footer for mailing lists
        return self.mailinglist_footer.as_deref();
    }
    None
}
```

**Impact**: List-ID header triggers footer removal logic, changing message text displayed to user.

### Example 2: Chat-Group-ID Header Routes Message

**File**: `src/receive_imf.rs` line ~650
```rust
fn get_chat_group_id(mime_parser: &MimeMessage) -> Option<String> {
    mime_parser.get_header(HeaderDef::ChatGroupId)
}
```
**Usage**: This value determines which group chat receives the message. Without it, message goes to 1:1 chat or ad-hoc group.

### Example 3: Autocrypt-Gossip Distributes Keys

**File**: `src/mimeparser.rs` line ~2117
```rust
pub fn gossiped_keys(&self) -> Result<Vec<GossipedKey>> {
    let mut gossiped_keys = Vec::new();
    for value in self.get_header_values(HeaderDef::AutocryptGossip) {
        // Parse Autocrypt-Gossip header
        let header = AutocryptHeader::from_str(&value)?;
        gossiped_keys.push(GossipedKey {
            addr: header.addr,
            key: header.key,
        });
    }
    Ok(gossiped_keys)
}
```

**Impact**: Keys extracted from header are saved to database and used for encrypting future replies.

### Example 4: Chat-Voice-Message Changes Content Type

**File**: `src/mimeparser.rs` line ~881
```rust
if self.get_header(HeaderDef::ChatVoiceMessage).is_some() {
    if viewtype == Viewtype::Audio {
        viewtype = Viewtype::Voice;
    }
}
```

**Impact**: Same audio file displays as "Voice Message" instead of "Audio" based on header.

## Headers That Are Only For Display

**Very few headers are display-only**:
- `Subject` (with exceptions - used for mailing list chat names)
- `Date` (except for sorting and conflict resolution)
- Custom `X-*` headers not in HeaderDef
- MIME boundary markers

Even these have processing implications (e.g., Date used for message ordering).

## Conclusion

**The receive message pipeline performs extensive business logic based on email headers.**

Headers control:
1. ✅ **Message routing** - Which chat receives the message
2. ✅ **Group operations** - Add/remove members, update metadata
3. ✅ **Security** - Key distribution, encryption decisions
4. ✅ **Content interpretation** - Message type, attachments, special content
5. ✅ **Threading** - Parent/child relationships
6. ✅ **Mailing lists** - Special processing, footer removal
7. ✅ **System notifications** - Generate synthetic messages
8. ✅ **Message operations** - Edit/delete existing messages
9. ✅ **Automation detection** - Mark bots, suppress notifications

**Headers are NOT just metadata for UI display** - they are the protocol control layer for Delta Chat's email-based messaging system.

## Related Files

- **`src/receive_imf.rs`**: Main receive pipeline with chat assignment logic
- **`src/mimeparser.rs`**: Header parsing, extraction, and initial processing
- **`src/headerdef.rs`**: Header definitions and enumerations
- **`src/chat.rs`**: Group operations triggered by headers
- **`src/pgp.rs`**: Autocrypt header processing
- **`src/securejoin.rs`**: Secure-Join protocol header handling

---

**Generated**: 2026-02-13  
**Analysis Scope**: Delta Chat Core `receive_imf` and `mimeparser` modules  
**Conclusion**: Headers drive critical business logic, not just display metadata.
