# SecureChat User Guide

This document walks through every feature of the SecureChat client. You will need three terminal windows: one for the server and two for clients.

## Prerequisites

Make sure you have completed the deployment steps in [README.md](README.md). The server should be running before you start any client.

---

## 1. Starting Up

### Start the server (Terminal 1)

```
cd code
python -m server.server
```

Wait until you see:

```
[INFO] Server starting on 0.0.0.0:5050
 * Serving Flask app 'server'
```

### Start clients (Terminal 2 and 3)

```
cd code
python -m client.client
```

You will see:

```
============================================================
  SecureChat - Secure E2EE Instant Messaging Client
============================================================

Commands: register, login, quit
>
```

---

## 2. Registration

Before you can use SecureChat, you need to create an account.

```
> register
Username (3-32 alphanumeric chars): alice
Password (min 8 chars):
Confirm password:

[OK] Registration successful for 'alice'!

*** IMPORTANT: Save your TOTP secret for 2FA login ***
  OTP Secret: JBSWY3DPEHPK3PXP
  OTP URI: otpauth://totp/SecureChat:alice?secret=JBSWY3DPEHPK3PXP&issuer=SecureChat

Add this to your authenticator app (Google Authenticator, etc.)
```

**Important**: write down the `OTP Secret`. You will need it every time you log in.

There are two ways to use the OTP secret:

1. Add it to an authenticator app (Google Authenticator, Authy, etc.) which generates a 6-digit code every 30 seconds.
2. For quick testing, generate the code from the command line in a separate terminal:
   ```
   python3 -c "import pyotp; print(pyotp.TOTP('YOUR_OTP_SECRET_HERE').now())"
   ```

Notes:
- The password is hidden when you type it (this is normal).
- Usernames must be 3-32 characters, letters and numbers only.
- Passwords must be at least 8 characters.

---

## 3. Login

```
> login
Username: alice
Password:
OTP Code: 482916

[OK] Logged in as 'alice'
[INFO] Generating identity keypairs...
[OK] Keys generated.
```

The OTP Code is the 6-digit number from your authenticator app (or the python command above). It changes every 30 seconds, so enter it promptly.

On first login, the client generates your cryptographic keypairs (Ed25519 for identity, X25519 for key exchange) and uploads the public portions to the server. On subsequent logins, your keys are restored from encrypted local storage.

After logging in, you see the full command list:

```
[alice] Commands: chat, send, conversations, friends, add, pending,
                  remove, block, unblock, verify, refresh, logout, quit
>
```

---

## 4. Adding Friends

You must be friends with someone before you can exchange messages. This is a deliberate anti-spam measure.

### Sending a friend request

On Alice's client:
```
[alice] > add
Username to add: bob
[OK] Friend request sent to bob
```

### Accepting a friend request

On Bob's client:
```
[bob] > pending

=== Incoming Requests ===
  [1] From: alice (2026-04-04 10:05)

Enter request ID to respond (or press Enter to skip): 1
Accept or decline? (a/d): a
[OK] Request accepted.
```

You can also decline with `d`, or press Enter to skip and deal with it later.

### Checking your friends list

```
[alice] > friends

=== Friends ===
  bob
```

---

## 5. Chatting

### Interactive chat mode

This is the main way to have a conversation.

```
[alice] > chat
Chat with (username): bob

Chatting with bob. Type messages and press Enter.
Commands: /quit, /ttl N, /refresh, /history N

  [alice]: Hello Bob!
  [v] (sent)
  [alice]: How are you?
  [vv] (delivered)
```

Delivery indicators:
- `[v]` = message reached the server (sent)
- `[vv]` = message reached the recipient (delivered)

### Receiving messages

Due to CLI limitations, incoming messages are not displayed the instant they arrive. They are fetched in three situations:

1. When you enter `chat` mode (automatic).
2. After you send a message (automatic).
3. When you type `/refresh` (manual).

So if you're waiting for a reply:

```
  [alice]: /refresh
  [10:12:30] bob: I'm good, thanks!
```

### Chat mode commands

| Command | What it does |
|---------|-------------|
| `/quit` | Leave chat mode and return to the main menu. |
| `/ttl 30` | Enable self-destruct. Messages sent after this will auto-delete from both sides after 30 seconds. |
| `/ttl` | Disable self-destruct. |
| `/refresh` | Fetch new messages from the server. |
| `/history 50` | Show the last 50 messages in this conversation. |

Everything else you type is sent as a message.

### Quick send (without entering chat mode)

```
[alice] > send
To (username): bob
Message: See you at 3pm
Self-destruct timer (seconds, or press Enter for none):
[v] Message sent to bob (sent)
```

---

## 6. Self-Destruct Messages

In chat mode, set a timer before sending:

```
  [alice]: /ttl 60
  [Self-destruct set to 60s]
  [alice]: This message will disappear in 60 seconds
  [v] (sent)
```

After 60 seconds:
- The message is removed from both clients' local storage on the next refresh or chat entry.
- The server deletes the ciphertext from the offline queue (best-effort).

To turn it off:
```
  [alice]: /ttl
  [Self-destruct disabled]
```

Note: self-destruct cannot prevent screenshots or a modified client from saving the message. This is a known limitation.

---

## 7. Conversations List

See all your conversations sorted by most recent activity, with unread counts:

```
[alice] > conversations

=== Conversations ===
  bob (2026-04-04 10:15) [2 unread]
  charlie (2026-04-04 09:30)
```

---

## 8. Safety Number Verification

To verify that your encrypted session with a contact has not been intercepted (MITM), compare safety numbers:

```
[alice] > verify
Username to verify: bob

=== Safety Number for alice <-> bob ===
54145 10363 00854 21568 64077 59718 39584 08865 01413 23423 13812 64330
61156 39020 12536 22075 61282 34046 22333 12686 39859 54455 55089 06168

Compare this with your contact through a trusted channel.
Mark as verified? (yes/no): yes
[OK] bob marked as verified.
```

Both Alice and Bob should see the same safety number. Compare them in person, over a phone call, or any other trusted channel. If they differ, someone may be intercepting the connection.

After verification, the friends list shows:
```
[alice] > friends

=== Friends ===
  bob [verified]
```

If Bob reinstalls the app (generating new keys), Alice will see a warning:
```
[WARNING] Identity key changed for 'bob'!
  This could indicate:
  - The user reinstalled their app
  - A potential security issue (MITM attack)
  Continue anyway? (yes/no):
```

---

## 9. Blocking and Removing

### Block a user

Blocked users cannot send you messages or friend requests.

```
[alice] > block
Username to block: spammer
[OK] Blocked spammer
```

### Unblock

```
[alice] > unblock
Username to unblock: spammer
[OK] Unblocked spammer
```

### Remove a friend

This removes the friendship (both directions) but does not block them.

```
[alice] > remove
Username to remove: bob
[OK] Removed bob from friends
```

---

## 10. Refreshing Messages

Outside of chat mode, use `refresh` to pull any pending messages:

```
[alice] > refresh

[INFO] 3 pending message(s) received.
  [10:20:15] bob: Hey, are you there?
  [10:21:02] bob: I have a question
  [10:22:30] charlie: Meeting at 4pm

[OK] Messages refreshed.
```

---

## 11. Logging Out

```
[alice] > logout
[OK] Logged out.
```

This saves your encrypted state to disk, disconnects the WebSocket, and invalidates your session token on the server. You will need your password and a fresh OTP code to log in again.

To exit the application entirely:
```
> quit
Goodbye!
```

---

## 12. Typical Workflow

Here is a complete example with two users.

**Terminal 2 (Alice):**
```
> register           (create account, save OTP secret)
> login              (enter password + OTP code)
> add                (send friend request to bob)
```

**Terminal 3 (Bob):**
```
> register           (create account, save OTP secret)
> login
> pending            (see Alice's request, accept it)
> chat               (enter: alice)
  [bob]: Hi Alice!
```

**Terminal 2 (Alice):**
```
> chat               (enter: bob — sees "Hi Alice!" automatically)
  [alice]: Hi Bob!
  [vv] (delivered)
  [alice]: /ttl 30
  [alice]: This is a secret message
  [v] (sent)
  [alice]: /quit
> conversations      (see conversation list)
> verify             (verify bob's identity)
> logout
```

---

## 13. Troubleshooting

| Problem | Solution |
|---------|----------|
| "Cannot connect to server" | Make sure the server is running in Terminal 1 (`python -m server.server`). |
| "Must be friends to send messages" | You need to add the user as a friend (`add`) and they need to accept (`pending`). |
| "Invalid OTP code" | The code expires every 30 seconds. Generate a fresh one and enter it quickly. |
| "Decryption failed" | Delete `client_data/` and `server/securechat.db`, restart the server, and re-register both users. This resets all encryption state. |
| Cannot see incoming messages | Type `/refresh` in chat mode, or `refresh` in the main menu. |
| Port 5000 in use (macOS) | The server uses port 5050 by default to avoid conflict with AirPlay. |
| Password seems blank when typing | `getpass` hides your input for security. Just type and press Enter. |
