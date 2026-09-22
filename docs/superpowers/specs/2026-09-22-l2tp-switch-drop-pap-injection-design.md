# L2TP switch: remove live-PAP injection

## Motivation

The l2tp-switch feature's live-PAP-injection watcher (`struct
l2tp_switch_pap_watcher_t` and its surrounding machinery in
`accel-pppd/ctrl/l2tp/l2tp.c`) was built to let a switched call authenticate
against a downstream LNS that doesn't consume the ICCN's `Proxy-Authen-*`
AVPs. In production it has two independent, confirmed failure modes:

1. **Watcher-creation race.** The watcher is only created inside
   `l2tp_switch_finish_downstream()`, two `triton_context_call()` hops plus a
   blocking `connect()` syscall after ICRP handling. The ICCN itself, and the
   upstream→downstream splice link the watcher is supposed to observe, both
   go live earlier and faster (ICCN is sent synchronously, zero-hop, from
   `l2tp_recv_ICRP()`). Any downstream target that replies fast enough gets
   its Configure-Ack round-tripped through the already-armed splice link
   before the watcher exists to see it. `l2tp_switch_link_peek()` silently
   drops frames when there's no watcher yet (`if (!w) return;`) — no log, no
   error. The watcher's state never gets set, no PAP is ever injected, and
   the call hangs until the target's own native auth timeout kills it.
   Confirmed against the tcpdump of a partner running accel-ppp as their LNS: ICCN
   carries the correct proxied credentials, the target's Configure-Request
   asks for PAP, both Configure-Acks are exchanged correctly, and then
   nothing — 5 seconds of silence — until the target's own Term-Request and
   CDN.

2. **Redundant injection against a call that already authenticated live.**
   When the watcher isn't blinded by (1), it still decides to inject based
   only on having seen both Configure-Acks — it has no way to know that the
   real upstream and downstream peers already completed a live,
   non-proxied PAP exchange with each other directly through the transparent
   splice pipe. When that happens, the target (correctly) ignores our late,
   unsolicited duplicate PAP request, having already moved past the
   Authentication phase, and our own 3-second `pap-timeout` then kills an
   otherwise fully-working, already-passing-traffic call. Confirmed against
   a second partner running a Juniper LNS: LCP, authentication, IPCP,
   and bidirectional data all complete successfully, then the switch itself
   sends a CDN (`Result Code 2 / Error Code 6`, RFC 2661 Appendix B —
   "generic vendor-specific error") at very close to exactly 3.00-3.03
   seconds into the call, every time, including with CHAP disabled and PAP
   the only offered protocol. Per the partner: **this setup worked before
   the live-PAP-injection feature was added** — the feature is a regression
   for this case, not a missing capability.

Both bugs live in the same passive, cross-context, tee/peek-based
architecture. Rather than patch two independent race/ordering bugs into a
subsystem that has to reconstruct call state by guessing from a side copy of
traffic, this removes the injection mechanism entirely. The two partners
onboarded so far are the concrete motivating cases:

- The partner running a Juniper LNS: dropping the feature **restores**
  previously-working behavior (live auth already worked end-to-end before
  the feature existed).
- The partner running accel-ppp as their own downstream LNS: dropping the
  feature means their setup goes back to not authenticating switched
  calls, exactly as before the feature was built. This is accepted: they
  will need to adapt their LNS configuration (or software) to consume the
  proxied `Proxy-Authen-Name`/`Proxy-Authen-Response` AVPs itself, which is
  the RFC 2661-compliant way to handle a proxied call in the first place,
  rather than relying on us to fake a live PPP exchange it can already
  avoid.

## Scope

### Remove entirely

In `accel-pppd/ctrl/l2tp/l2tp.c`:

- `struct l2tp_switch_pap_watcher_t` and every function built around it:
  `l2tp_switch_pap_watcher_create/hold/put/free/detach/get`,
  `l2tp_switch_pap_observe`, `l2tp_switch_pap_decide_locked`,
  `l2tp_switch_pap_log_skip`, `l2tp_switch_pap_start_send`,
  `l2tp_switch_pap_upstream_ack_delivered`, `l2tp_switch_pap_send_request`,
  `l2tp_switch_pap_timeout`, `l2tp_switch_pap_disconnect` /
  `l2tp_switch_pap_disconnect_cb`, the PAP header struct/constants used only
  by injection (`struct l2tp_switch_pap_hdr`, `L2TP_SWITCH_PAP_REQ/ACK/NAK`,
  `L2TP_SWITCH_PROXY_AUTHEN_*`, `Proxy_Authen_*` lookups used only to build
  the injected request — `Proxy_Authen_Response`/`Proxy_Authen_Challenge`
  stay if still needed for anything else the AVP-capture path uses; confirm
  during implementation).
- The tee/peek plumbing that exists only to feed the watcher's *decision*
  logic: `ack_pending` on `struct l2tp_switch_link_t`, `peek_pipe_rd`/
  `peek_pipe_wr` if nothing else uses them, `l2tp_switch_link_ack_forwarded()`.
- Watcher attachment in `l2tp_switch_finish_downstream()` (the
  `downstream->switch_pap_watcher = l2tp_switch_pap_watcher_create(...)`
  block and its error path) and the `switch_pap_watcher` field on
  `struct l2tp_sess_t`.
- `pap-timeout` config option: parsing in `l2tp_switch_conf.c`,
  `l2tp_switch_conf_pap_timeout_ms()`, its declaration in
  `l2tp_switch_conf.h`, and its documentation in `accel-ppp.conf` /
  `accel-ppp.conf.5`.
- The two PAP-injection-specific test files:
  `tests/accel-pppd/l2tp_switch/test_switch_downstream_pap.py` and
  `test_switch_downstream_pap_race.py`.

### Keep, made stateless

The LCP-auth-protocol visibility logging (today's
`l2tp_switch_pap_log_lcp()`, called for the target's first Configure-Request,
any Protocol-Reject, and any Terminate-Request) stays, but loses every
dependency on the watcher struct: no `resolved` flag, no lock, no timer, no
injection decision, no cross-context call. It becomes a small, direct,
per-link peek purely for operator visibility — so a hung call still shows up
in the log as "downstream LCP Configure-Request asks for PAP" /
"...asks for CHAP (algorithm 0x..)" / "...has no authentication-protocol
option", telling an operator immediately why a given target's calls aren't
authenticating, without any of the removed machinery. This still needs a
`tee()`-based peek (same mechanism, no state machine behind it) since the
real splice pipe must stay untouched.

Everything else in the switch — `target=`/`match=` config, on-demand/
persistent modes and their timers, the transparent splice/data path itself,
`l2tp switch show`, CLI match management, metrics — is unaffected.

## Config compatibility

An existing config with a `pap-timeout=` line under `[l2tp]` must not
silently do something different than before with no explanation. During
implementation, confirm how the switch config parser (`l2tp_switch_conf.c`)
handles a now-unrecognized key and make it either: (a) a clear, fatal "no
longer supported, remove this line" error consistent with this codebase's
existing "malformed config is a fatal error" convention for switch options,
or (b) if the general option parser already warns-and-ignores unknown keys
elsewhere, let that existing behavior apply and just make sure the removal
doesn't regress startup on an old config. Prefer (a) if it doesn't require
new special-casing — a loud failure beats a silently-ignored knob.

## Documentation

`docs/l2tp_switching.md`'s "Authentication" section is rewritten (not just
deleted) to state the requirement plainly:

- A switched call's two legs are a transparent pipe; PAP/CHAP negotiate
  directly between the real upstream and downstream peers.
- If the upstream side proxies authentication via ICCN AVPs instead of ever
  sending a live PPP auth frame, the downstream target must consume those
  AVPs itself (RFC 2661 §4.4.2) to treat the call as authenticated. accel-ppp
  does not do anything on the target's behalf.
- If the target doesn't do that, and the upstream doesn't relay live auth
  either, the call will hang until the target's own native auth timeout
  tears it down — this is expected behavior, not a bug, and is visible in
  the log via the retained LCP-auth-protocol logging.
- This is a requirement to communicate to any new downstream partner during
  onboarding, not something this software works around.

`CHANGELOG.md` gets an entry noting the mechanism's removal and why (race +
redundant-injection failure modes; partner impact for existing users of the
feature).

## Testing

- Delete the two PAP-injection-specific test files outright (they test
  removed behavior).
- Audit `l2tp_switch_peer_lcp.c` / `l2tp_switch_peer_test.c` /
  `tests/accel-pppd/l2tp_switch/helpers.py` for PAP-injection-only helpers
  (e.g. anything that simulates or asserts on an injected PAP
  request/reply) and trim just those; the rest of this harness is shared by
  the general LCP/switch test suite and must keep working.
- Add (or adapt an existing test into) one test asserting the documented
  "no help offered" behavior: a switched call to a target whose Confreq
  asks for PAP just sits on the transparent pipe with no injected traffic,
  and the existing LCP-auth-protocol log line still appears.
- Run the full `l2tp_switch` suite (`tests/run_l2tp_switch_sharded.sh`) to
  confirm nothing outside the removed scope regressed.

## Out of scope

- Any change to how accel-ppp's normal LNS mode (not the switch) handles
  `Proxy-Authen-*` AVPs on its own incoming calls. Whether accel-ppp could
  usefully gain that as a first-class LNS feature (which would directly
  help partners running accel-ppp as their own downstream LNS) is
  a separate, independent piece of work, not part of this change.
- Any change to partner-facing onboarding process/docs beyond the
  in-repo `docs/l2tp_switching.md` update above.
