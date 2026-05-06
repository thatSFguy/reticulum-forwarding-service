# reticulum-forwarding-service (`fwdsvc`)

A Reticulum/LXMF group-chat relay written in pure Go, with no third-party
Reticulum library — implements the protocol layers we need directly from
[the spec](https://github.com/thatSFguy/reticulum-specifications) and
verifies wire-format correctness against the upstream Python `rns` + `LXMF`
reference implementation. Live-tested round-trip with a mobile LXMF client
over a public testnet entry node.

Users send LXMF messages to this service and it forwards each message to
every other roster member, creating a many-to-many group chat. Designed to
run unattended on small Linux hardware: Debian, Raspberry Pi (arm64/armv7),
x86_64.

## Wire-format features implemented

These are the parts of the Reticulum / LXMF protocol stack the service
currently speaks. Everything here has at least one of: a static test
vector against canonical Python output, a passing live subprocess
interop test, or a confirmed live round-trip with a third-party LXMF
client.

- **Identity** — X25519 + Ed25519 keypair, on-disk format, `identity_hash`
  and `destination_hash` derivation (SPEC §1).
- **Token cipher** — AES-256-CBC + HMAC-SHA256 + HKDF with `identity_hash`
  salt (SPEC §3).
- **Packet header** — HEADER_1 and HEADER_2 codec, including the
  hashable-part rule that makes proofs survive HEADER_1↔HEADER_2 in flight
  (SPEC §2).
- **HDLC framing** for `tcp_client` interfaces (SPEC §8.2).
- **Announce** — build, parse, verify, with and without ratchet
  (SPEC §4). `app_data` msgpack `[display_name_bytes, stamp_cost]`
  including the §9.3 `bin`-vs-`str` gotcha.
- **Opportunistic LXMF** — full sign/encrypt/decrypt/verify both
  directions, including the SPEC §5.6 dual-msgpack-variant tolerance
  for stamp-bearing inbound messages (SPEC §5).
- **PROOF emission** — every received `CTX_NONE` DATA packet at a
  SINGLE destination is acknowledged with a 64-byte implicit-form
  PROOF (SPEC §6.5), so senders' `PacketReceipt`s resolve and they
  stop retransmitting.
- **Path requests** — when a message arrives from a sender we can't
  verify, we issue a `path?` broadcast (SPEC §7.1) and a path-aware
  relay's path-response announce gives us their public key. Per-target
  60 s dedup so noisy retransmitters don't make us flood.
- **HEADER_2 originator conversion** — outbound DATA addressed to a
  recipient that announced via a relay uses HEADER_2 with the cached
  next-hop transport_id (SPEC §2.3), so multi-hop recipients actually
  receive our messages.

## Behaviour

- **Explicit `/join`.** The first non-command message from a new
  Reticulum identity gets a private invitation reply explaining the
  service. The sender's message is not forwarded and they are not added
  to the roster — they have to send `/join` to opt in. This avoids the
  awkward "I sent one message and now strangers are getting it" UX.
- **Replay on join.** New (and returning) members receive the most recent
  messages so they can pick up the conversation. Defaults: last 100 messages,
  nothing older than 7 days.
- **Pause without leaving.** A member can `/pause` to stop receiving
  forwarded messages (and stop having their own messages forwarded to
  others). `/resume` reverses it. Roster entry stays put.
- **Per-message char cap** (`service.max_inbound_chars`, default 500) —
  oversized non-command messages get rejected with a polite reply,
  separate from the lower wire-format size limit.
- **Auto-prune.** Members whose Reticulum identity hasn't announced in
  4 weeks are removed.
- **Slash commands** (the `/?` reply is **role-aware** — non-members
  only see commands that work for them, mods see the moderation set):

  | Command                   | Who          | Effect                                                            |
  |---------------------------|--------------|-------------------------------------------------------------------|
  | `/?` or `/help`           | anyone       | List commands available to you                                    |
  | `/users`                  | anyone       | List roster (paused members marked `[paused]`)                    |
  | `/mods`                   | anyone       | List mods                                                         |
  | `/admin`                  | anyone       | List admins                                                       |
  | `/join`                   | non-members  | Opt in: receive forwarded messages, your messages get forwarded   |
  | `/leave`                  | members      | Leave the chat (you can `/join` again later)                      |
  | `/pause`                  | members      | Stop receiving forwarded messages (and stop forwarding yours)     |
  | `/resume`                 | members      | Reverse `/pause`                                                  |
  | `/nick <newname>`         | members      | Change own nickname                                               |
  | `/nick <user> <newname>`  | mods, admins | Change another user's nickname                                    |
  | `/kick <user>`            | mods, admins | Remove from roster (user can `/join` again)                       |
  | `/ban <user>`             | mods, admins | Add to banlist; future `/join`s and messages refused              |
  | `/unban <user>`           | mods, admins | Remove from banlist                                               |
  | `/announce`               | mods, admins | Broadcast a fresh announce immediately                            |

  `<user>` accepts a nickname (case-insensitive) or a destination-hash
  prefix (>=4 hex chars).

## Limitations

The implementation is intentionally minimal — just enough Reticulum + LXMF
to run a leaf-node group-chat hub. If any of these matter for your
deployment, the service won't fit as-is.

### Message size

The hard limit comes from upstream `LXMF.LXMessage.ENCRYPTED_PACKET_MAX_CONTENT
= 295 bytes` (the maximum msgpack payload that fits in a single Reticulum
DATA packet after Token encryption). Subtracting the LXMF msgpack envelope
(array tag, float64 timestamp, empty title, content prefix, empty fields
map) leaves **about 280 bytes for the raw message content** before
forwarding's `[nickname] ` prefix is added.

After accounting for the prefix, the user-visible budget per message is:

| Sender state                         | Prefix overhead              | Max content (ASCII) |
|--------------------------------------|------------------------------|---------------------|
| 8-char hash fallback (no `/nick`)    | `[deadbeef] ` = 11 bytes     | **~269 bytes**      |
| Short nick, e.g. `bob`               | `[bob] ` = 6 bytes           | **~274 bytes**      |
| 24-character nick (the maximum)      | `[<24-char-nick>] ` = 27 B   | **~253 bytes**      |

In **characters** (since not all bytes carry one character):

| Content                              | Per char       | Max chars            |
|--------------------------------------|----------------|----------------------|
| Pure ASCII / Latin-1 single-byte     | 1 byte         | ~250–275             |
| Latin diacritics (é, ñ, …)           | 2 bytes        | ~125–135             |
| CJK / most non-Latin scripts         | 3 bytes        | ~85–90               |
| Emoji and other 4-byte UTF-8         | 4 bytes        | ~60–70               |

**Behavior on too-long messages:** the service refuses to forward them
and replies privately to the original sender with a message like
`Message not delivered: 423 bytes is too long for single-packet relay.
Your max is roughly 269 bytes (link-based delivery is not implemented
yet).` The message is **not** appended to history, so other roster
members never see it.

**Forwarded messages add a `[nickname] ` prefix**, which is what makes
the practical limit lower than the raw 280-byte cap and why long
nicknames cost everyone budget.

**No fragmentation / Reticulum Resource transfer.** SPEC §10 resource
fragmentation isn't implemented; multi-packet messages would require
link-based delivery, which isn't implemented either.

### Transport

- **Only one interface type: `tcp_client`.** We dial out to a TCP
  Reticulum peer and exchange HDLC-framed packets. **No LoRa / RNode
  serial, no UDP, no AutoInterface (LAN multicast), no I2P.** A Pi with
  a real LoRa modem will need to run upstream `rnsd` alongside `fwdsvc`
  and let `fwdsvc` connect to `rnsd` over TCP.
- **No transit relay.** We don't forward third-party packets. Other
  Reticulum nodes can't route through us.
- **No automatic reconnect.** If the TCP interface drops, the service
  logs and continues; you have to restart it. (Use systemd `Restart=on-failure`.)
- **Path table doesn't persist across restart.** `transport.known` is
  in-memory only. After a restart, the next message from a previously-known
  sender triggers a path? request (SPEC §7.1) and the first message from
  them gets dropped while we wait for the path response. The roster
  itself, history, and banlist do persist on disk.

### LXMF features deferred

- **No link-based delivery.** Messages requiring an established Reticulum
  Link (anything over the size limit, or any peer on a high-latency path
  where opportunistic timeouts) won't work.
- **No propagation node / store-and-forward.** If a recipient is offline
  when a message is forwarded to them, the message is **lost from their
  perspective**. Replay-on-join only kicks in for users joining or
  rejoining after a kick/prune — it does not cover daily reachability
  gaps. Long-offline-then-online is not handled.
- **No ratchets / forward secrecy.** Every Token-encrypted message uses
  the recipient's long-term X25519 key. If the long-term key is later
  compromised, all past messages are decryptable. We accept and ignore
  the `ratchet_pub` field on inbound announces; we never rotate our own.
- **No stamps / proof-of-work anti-spam.** SPEC §5.7 stamps are not
  enforced (we accept everything) and not generated (peers requiring
  stamp-cost > 0 will silently reject our outbound LXMF). Our own
  announces declare `stamp_cost = 0`.
- **No tickets** (the pre-shared shortcut around stamp PoW).
- **No msgpack `fields` content.** Outbound messages always carry an
  empty fields dict. Inbound parsing accepts and discards any fields
  present. So no attachments, stickers, embedded LXMs, or telemetry
  on either direction.

### Identity / trust

- **Trust on first announce (TOFU).** The first signed announce we hear
  from any destination is taken at face value. SPEC §4.5 step 4 then
  rejects subsequent attempts to override the public key for that
  destination — so you can't be silently MitM'd after the first contact,
  but the first contact has no out-of-band verification.
- **Lost identities cannot recover the same destination.** Per SPEC, a
  user who loses their identity material gets a different identity_hash
  on regeneration → different destination_hash → effectively a new
  user from our perspective. Their old roster entry will eventually
  prune; their new one is a fresh join.
- **Senders MUST announce before messaging.** We can't decrypt to a
  recipient whose public key we haven't heard, and we can't verify a
  signature from a sender whose Ed25519 pub we haven't cached. A peer
  whose first packet is an LXMF (no prior announce) will be rejected.

### Service design

- **Single chat room.** No multi-room support. One process, one roster.
- **No runtime promotion.** `[admins]` and `[mods]` are config-file only.
  No `/promote` command. Edit the file and restart to change.
- **No DM support.** Every non-command message is forwarded to the entire
  roster. No private message paths.
- **No edit / delete.** Forwarded messages are immutable; a sender cannot
  retract or amend.
- **No reply pagination.** Command replies are sent as a single LXMF
  packet (~280-byte budget). `/?` and `/help` fit by design (a regression
  test guards the budget). `/users`, `/mods`, `/admin` produce dynamic
  output that can in principle exceed the limit if the roster grows large;
  the send-side `ErrPayloadTooLarge` guard refuses the reply and logs the
  failure rather than corrupting the wire. Pagination (`/users 1`,
  `/users 2`, etc.) is a future enhancement.

## Build

Requires Go 1.26 or newer.

If you don't have Go installed yet:

- **Windows:** download the `.msi` from https://go.dev/dl/ and run it.
  After install, open a fresh PowerShell and confirm `go version` works.
- **Debian / Ubuntu:** `sudo apt install golang-go` (check version is >= 1.26;
  if not, install from https://go.dev/dl/).
- **Raspberry Pi:** prefer cross-compiling from a development machine.

First-time build:

```sh
go mod tidy
go build -o fwdsvc ./cmd/fwdsvc
go test ./...
```

Cross-compile for Raspberry Pi:

```sh
GOOS=linux GOARCH=arm64 go build -o fwdsvc-arm64 ./cmd/fwdsvc        # Pi 4/5
GOOS=linux GOARCH=arm GOARM=7 go build -o fwdsvc-armv7 ./cmd/fwdsvc  # Pi 2/3/Zero 2
```

Or use `scripts/build-rpi.sh`.

## Run

1. Copy `configs/fwdsvc.example.toml` to `~/.fwdsvc/config.toml` and edit:
   - Set `display_name` to whatever you want users to see in announces.
   - Set at least one `[[interfaces]]` entry with `type = "tcp_client"`
     pointing at a reachable Reticulum peer (e.g. `rns.michmesh.net:7822`
     is one community-run testnet entry node, or use a local `rnsd` if
     you're running one).
   - Add the identity hash of at least one admin to `admins = [...]`.
     (You can run the service once first, copy the printed identity hash,
     then add it.)
2. Run it:

   ```sh
   ./fwdsvc -config ~/.fwdsvc/config.toml
   ```

   On first run the service generates its identity at `identity_path` and
   prints its destination hash on stdout. Share that hash with the people
   who should be able to message the service.

This service does **not** read `~/.reticulum/config` — it implements the
Reticulum protocol itself, so the `[[interfaces]]` block in
`config.toml` is the entire interface config.

## Storage layout

Default state directory is `~/.fwdsvc/`:

| File           | Purpose                                                   |
|----------------|-----------------------------------------------------------|
| `config.toml`  | The config file (you create this).                        |
| `identity`     | The service's 64-byte Reticulum identity (do not share).  |
| `state.json`   | Roster + banlist.                                         |
| `history.json` | Recent-message ring buffer for replay-on-join.            |

## Verification

The implementation is checked at three increasingly strong levels:

- **Static byte-level test vectors** — `go test ./...` includes tests
  that load the canonical Python `rns` 1.2.0 / `LXMF` 0.9.6 wire-byte
  vectors from `../reticulum-specifications/test-vectors/{identities,
  announces,lxmf}.json` and assert byte-exact equality on identity
  derivation, announce build (with and without ratchet), Token
  decrypt, and LXMF body build. Tests skip cleanly if the spec
  sibling repo isn't present.

- **Live subprocess interop** — `go test -tags=interop ./tests/interop/...`
  spawns a Python helper that drives upstream `rns` + `LXMF` directly
  and exchanges fresh announce + opportunistic-LXMF bytes with the Go
  code in **both directions**. Requires `pip install rns lxmf` (rns
  >= 1.2.0, LXMF >= 0.9.6) and `python` on PATH. Skips otherwise.

- **Live mesh interop with a third-party LXMF client.** During
  development the service was run against `rns.michmesh.net:7822` and
  exercised end-to-end with a mobile LXMF client: announce propagation
  in both directions, opportunistic LXMF send, PROOF emission stopping
  the mobile's retransmit loop, path-request resolving an unannounced
  sender, and `/?` round-tripping back to the mobile UI. This is the
  qualitative check that nothing in our wire format silently breaks
  when the path involves real relays and asymmetric mesh topology.

## License

MIT.
