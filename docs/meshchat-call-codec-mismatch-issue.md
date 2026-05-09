# Draft issue for liamcottle/reticulum-meshchat

Submit at: https://github.com/liamcottle/reticulum-meshchat/issues/new

---

**Title:** Voice call to a peer with no `call.audio` destination shows misleading "codec mismatch" instead of "not supported"

---

## Summary

When MeshChat tries to call a peer whose RNS identity exists and announces normally on `lxmf.delivery` but does **not** register a `call.audio` destination, the call attempt times out at the link-establishment stage and the UI surfaces a "codec mismatch" / failed-call message. The actual failure isn't codec-related at all — it's "no destination listening" — so the displayed reason is misleading and points users at the wrong problem.

## What the user sees

A text-only LXMF peer (in our case [`reticulum-forwarding-service`](https://github.com/thatSFguy/reticulum-forwarding-service), a group-chat relay that registers only `lxmf.delivery`) appears in the address book / online list as expected. Tapping the call button — or any frontend code path that triggers a voice call to that destination — shows a brief "incoming/outgoing call" UI that immediately ends with a codec-mismatch-flavored message. The service's log shows nothing on the call attempt because the LINKREQUEST hits a destination hash with no local listener and is silently dropped.

## Why it happens (per code)

`src/backend/audio_call_manager.py`:

- The call protocol opens an `RNS.Link` to a destination on the peer's identity with aspects `"call"` and `"audio"`:
  ```python
  server_destination = RNS.Destination(
      server_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
      "call", "audio")
  link = RNS.Link(server_destination)
  ```
- A peer that doesn't register `call.audio` has no responder for that hash. The LINKREQUEST goes unanswered; the `RNS.Link` constructor's establishment timer fires and the wrapper raises:
  ```python
  raise CallFailedException("Could not establish link to destination.")
  ```
- The frontend translates this generic "could not establish link" into the codec-mismatch UI, which is misleading — codec negotiation never started.

## Proposed fix

Distinguish the *no-listener-at-all* failure mode from genuine codec/establishment failures, and surface a different message:

- If the link establishment times out **without** any LRPROOF arriving at all (i.e. the destination hash has no responder on the network), treat that as "peer doesn't support voice calls" and display a UI to that effect — e.g. *"This peer doesn't support voice calls"* or *"No call destination on this peer"*.
- If an LRPROOF arrives but subsequent codec/audio negotiation fails, keep the current "codec mismatch" message — that's accurate then.

The two cases are distinguishable inside `RNS.Link` (initiator either gets an LRPROOF or doesn't). A small wrapper around the link callback could classify the failure before the frontend reaches the codec-mismatch path.

Even simpler short-term: add a hint to the failed-call UI suggesting that "this peer may not support voice calls" so users don't chase phantom codec issues.

## Why this matters

Text-only LXMF peers (group-chat relays, command bots, automation endpoints) are a growing class of useful destinations. They announce normally and respond to LXMF, but have no voice surface and never will. Today's UX makes them look broken to MeshChat users when they're working as intended.

Happy to put together a PR if you'd like to suggest the shape of the change.

cc @ynosgr — reporting this from the affected-user side (running into it via fwdsvc).
