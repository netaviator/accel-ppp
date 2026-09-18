# L2TP Switch Downstream Live-PAP Implementation Plan (KISS revision)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Revision note:** This replaces an earlier version of this plan that ran a full local `ppp_t`/LCP/auth layer chain for the downstream leg (via `ppp_lcp.c`/`ppp_auth.c`, with a new `switch_no_local_auth` flag threaded through shared PPP code). The user explicitly asked for a simpler design: no local authentication decision (we don't have the downstream target's RADIUS/subscriber data and must never pretend to validate it), no changes to shared `ppp/*.c` code at all, and minimal new surface area. This revision does that: **it never opens a real PPP session at all**. See "What changed and why" below.

**Goal:** Make the L2TP switch's downstream leg present genuine, live PAP authentication to the target LNS, using the credentials already captured from the upstream leg's ICCN, so that any unmodified/standard LNS (accel-ppp or otherwise) accepts a switched call exactly as it would a normal client — no patch needed on the receiving end, and no local auth decision made on our end.

## What changed and why

The prior revision's premise was wrong in one detail that mattered: to send live PAP we do **not** need a working local PPP client (LCP negotiation, layer chain, etc.) — the real peers (the actual calling client, relayed via the upstream LAC, and the downstream target LNS) are *already* negotiating real LCP with each other today, transparently, through accel-ppp's existing raw `splice(2)` byte pipe (confirmed by the prior investigation: `l2tp_switch_link_create()`, `accel-pppd/ctrl/l2tp/l2tp.c:4499-4557`, wires each leg's kernel `pppol2tp` socket to the other via an intermediate kernel pipe using `splice(2)`, zero PPP parsing, `ppp_start()` never called). That splicing is *why* LCP already works. It only breaks at PAP because the upstream LAC (DTAG) never puts a live PAP frame on the wire — it proxies auth via ICCN AVPs instead, and nothing on the downstream end ever asked for or needs a live PAP frame in principle — the two real peers would negotiate it themselves if the upstream side just sent one.

So instead of accel-ppp *becoming* a PPP client, this design has it stay exactly what it already is — a transparent byte pipe — and just **passively watch the pipe for the moment LCP has settled, then inject one synthesized PAP `Authenticate-Request` frame directly into the downstream-bound stream**, built from bytes already captured from the upstream ICCN. The splice keeps running unmodified, before, during, and after — this frame is just one more frame in an already-flowing stream, exactly as if the real client had sent it. The one reply frame we care about (`Authenticate-Ack`/`Nak`) is picked off the same way, without interrupting anything.

This means:
- **Zero changes to `accel-pppd/ppp/*.c`.** No new flags on `struct ppp_t`, no touching `ppp_auth.c`/`ppp_lcp.c`/`ppp_ipcp.c`/`ppp.c`'s layer-chain driver. Every change lives in `accel-pppd/ctrl/l2tp/` (a new file plus edits to `l2tp.c`), which trivially satisfies "must not change behavior for non-switch sessions" — there is no shared code touched to gate.
- **No local auth decision.** We never accept or reject anything about the *content* of the credentials — we relay the exact bytes DTAG already captured, unmodified, and relay whatever Ack/Nak comes back. The downstream target does 100% of the actual authentication decision, same as it always has for any real client.
- **The two "blocking unknowns" from the prior revision are gone.** We never send our own `Configure-Request`, never demand or reject a `CI_AUTH` option, never participate in LCP's option negotiation at all — so whether Luiz's LNS demands `CI_AUTH` from us is moot; it's negotiating that with the real client, same as before, same as if we weren't switching at all.

**Architecture:** `l2tp_switch_link_create()` currently creates two `struct l2tp_switch_link_t` objects per pairing (one per direction), each splicing `src->ppp.fd` through an intermediate pipe (`link->pipe_rd`/`pipe_wr`) to `dst->ppp.fd` (`l2tp_switch_link_read()`, `l2tp.c:4274-4382`). This plan adds a small **watcher** attached to the pairing that:

1. After each direction's input-side `splice()` fills `link->pipe_rd`/`pipe_wr` but *before* the existing output-side `splice()` drains it, uses `tee(2)` to duplicate (not consume) that data into a small side "peek" pipe, then `read()`s the peek pipe (a completely separate, tiny copy — the original data in `link->pipe_rd` is untouched and flows out exactly as it does today).
2. Inspects only the first 3 bytes of each PPP frame in that copy (`proto` + `code`, mirroring `struct lcp_hdr_t`, `accel-pppd/ppp/ppp_lcp.h:37-43`) for an LCP (`0xC021`) `CONFACK` (`accel-pppd/ppp/ppp_lcp.c:261`; already `#define`d there, not redefined here — see Task 2).
3. Once **both** directions have shown a `CONFACK` (each real peer has accepted the other's LCP options — a reasonable, deliberately simple proxy for "LCP is open" that doesn't require running RFC 1661's full state machine), builds and `write()`s one raw PAP `Authenticate-Request` frame (`0xC023`, mirroring `struct pap_hdr`, `accel-pppd/auth/auth_pap.c:49-54`) directly onto `downstream->ppp.fd`, using the already-captured `Proxy-Authen-Name`/`Proxy-Authen-Response` AVP bytes (`sess->switch_avps`, `l2tp.c:210`/`235-239`) as Peer-ID/Password verbatim.
4. Keeps watching the same way for the one PAP reply frame (`0xC023`) from the downstream leg: `PAP_ACK` → watcher retires itself, nothing else changes, splicing (which was never interrupted) continues exactly as today; `PAP_NAK` or a timeout → tear down both legs via this codebase's existing switch-teardown conventions.
5. Once resolved either way, the watcher stops doing any work at all — `l2tp_switch_link_read()` goes back to being exactly today's function, with zero ongoing overhead for the rest of the call.

**Tech Stack:** C, `tee(2)`/`splice(2)` (Linux syscalls, already `#include`d and in use in this file), `triton` timers for the timeout, existing L2TP switch code (`accel-pppd/ctrl/l2tp/l2tp.c`). No `ppp_t`/`ppp_layer_t` involvement at all.

**Spec:** No existing spec doc covers this — originates from a live production incident (see `docs/l2tp_switching.md` update in Task 7). This plan doubles as the spec.

## Global Constraints

- PAP only. Production traffic (DTAG wholesale L2TP hand-off) never sends `Proxy-Authen-Challenge` — no challenge means PAP (RFC 2661 §4.4.2's `Proxy-Authen-Type` enum: `3` = PPP PAP), and CHAP client support is explicitly **out of scope**.
- We are a relay, not an authenticator. Never validate, transform, or make pass/fail decisions about the credential bytes themselves — only relay them and relay back whatever the real downstream authenticator decides. This is a hard constraint from the user (no RADIUS/credential access for downstream targets), not just a design preference.
- Must work against an **unmodified** downstream LNS — no assumption the target implements RFC 2661 Proxy Authentication consumption, and no assumption it's even accel-ppp.
- **Must not touch `accel-pppd/ppp/*.c` at all.** Every line of this feature lives in `accel-pppd/ctrl/l2tp/`. If implementation reveals this isn't achievable, that's a stop-and-ask-the-user moment, not a silent scope change back to the prior design.
- Must not disturb the existing, already-working splice for any non-watched traffic, and must not add meaningful steady-state overhead: the watcher must fully retire itself (stop calling `tee()`/doing any parsing) once PAP is resolved, for the lifetime of the call.
- Follow this codebase's cross-context-call discipline (see "Concurrency" below — this is the single highest-risk correctness detail in this whole plan, more so than in the prior revision, because the watcher is now explicitly touched from **two different triton contexts**).
- Reuse existing wire structures where they exist: `struct pap_hdr`/`struct pap_ack` (`accel-pppd/auth/auth_pap.c:49-60`), `struct lcp_hdr_t` (`accel-pppd/ppp/ppp_lcp.h:37-43`). Same note as before: `auth_pap.c` is a self-contained static translation unit (its structs aren't exported), so this is a deliberate field-for-field mirror, not a `#include`. `ppp_lcp.h` **is** a shared header already included elsewhere outside `ppp_lcp.c` — check whether it's safe/conventional to `#include "ppp_lcp.h"` directly from `l2tp.c`/the new file for `struct lcp_hdr_t` and `PPP_LCP`/`CONFACK` before deciding to mirror those too; prefer including the real header over copying if it doesn't drag in unwanted dependencies (it looks header-only/pure-data, but confirm in Task 2 Step 1).

## Concurrency: the one thing that will bite if rushed

`l2tp_switch_link_create()` registers each direction's `l2tp_switch_link_t.hnd` on **`src`'s own tunnel context**, not a shared one: the upstream→downstream link (`from_upstream=1`, `src=upstream`) runs in `upstream->paren_conn->ctx`; the downstream→upstream link (`from_upstream=0`, `src=downstream`) runs in `downstream->paren_conn->ctx`. These are two different tunnels, almost always two different triton contexts/threads.

That means: the frame carrying the **real client's** `CONFACK` (upstream telling downstream "your LCP options are fine") is observed by the link running in the **upstream** tunnel's context, while the frame carrying **Luiz's** `CONFACK` is observed by the link running in the **downstream** tunnel's context. Any shared watcher state (the two `seen_confack` flags, the injected request's timer, the resolved/pending state) is therefore written from both contexts. This is exactly the class of bug this codebase's existing comments describe having been bitten by before (see `l2tp_switch_place_call_on`'s extensive cross-context notes, `l2tp.c:5266-5396`) — do not add a second, ad hoc synchronization convention. Options, in preference order, to nail down in Task 2:
1. Give the watcher its own small `pthread_mutex_t` (mirroring `l2tp_switch_target_t.lock`'s usage pattern) guarding just its own flags/state, with the timer and the actual frame injection/teardown always performed via `triton_context_call()` into the **downstream** leg's own context (matching where its `switch_pap_ctx`-equivalent state should live, and matching how `l2tp_switch_drain_pending_calls()`/`l2tp_switch_place_call_on()` already treat the downstream tunnel context as the authoritative one for a pairing's lifecycle state).
2. Confirm this against how `target->lock` is already used for cross-context shared state (`l2tp.c`, search `pthread_mutex_lock(&target->lock)`) — mirror that pattern, don't invent a new one.

## Task 1: Ground-truth checks before writing the watcher

**Files:** none (verification only)

- [ ] **Step 1: Confirm one-frame-per-`splice()`-chunk holds in practice**

The existing `l2tp_switch_link_read()` already implicitly relies on each `splice(src->fd, pipe_wr, ...)` call returning a chunk that maps cleanly to what gets written out (`n` bytes in, `n` bytes out, looped explicitly, `l2tp.c:4279-4381`) — this has worked correctly in production for arbitrary PPP frame sequences already, which is reassuring, but the watcher's frame parser explicitly assumes each `tee()`'d chunk starts at a PPP frame boundary (proto field first). `sess->ppp.fd` is `SOCK_DGRAM` (`socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP)`, `l2tp.c:2536`), which is what makes this a reasonable assumption (datagram sockets don't coalesce messages across `recvmsg`-equivalent boundaries) — but confirm empirically with a packet capture + `strace -e splice,tee` (or add temporary debug logging) against a real switched call during Task 2 development, rather than trusting the assumption blind. If frames ever *do* span multiple chunks in practice, the parser (Task 2 Step 3) needs to buffer across `tee()` calls instead of assuming a clean frame per call — flag this back to the user if observed; do not silently add buffering complexity speculatively before confirming it's needed.

- [ ] **Step 2: Reconfirm the captured credential bytes need no further transform**

Already established from the live capture in this conversation: `PROXY_AUTH_RESP(7861626c617563697573)` decodes directly to ASCII with no further transform. Re-confirm this holds for `Proxy_Authen_Name` too (it should, same AVP family) by inspecting `struct l2tp_switch_avp_t`'s stored `val`/`len` for a live captured call (`l2tp.c:228-233`) — just a sanity check before Task 3 builds the frame from them directly.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/2026-09-18-l2tp-switch-downstream-pap.md
git commit -m "docs: confirm Task 1 ground truth for l2tp-switch downstream PAP watcher"
```

---

## Task 2: The passive watcher — tee/peek plumbing and frame detection

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c` (`struct l2tp_switch_link_t`, `l2tp_switch_link_create()`, `l2tp_switch_link_read()`, `l2tp_switch_link_free()`)
- Create: `accel-pppd/ctrl/l2tp/l2tp_switch_pap.c`, `accel-pppd/ctrl/l2tp/l2tp_switch_pap.h` (the watcher's own state and frame parsing — kept separate from `l2tp.c`'s already-large switch code, matching this codebase's stated preference for many small files)
- Modify: `accel-pppd/ctrl/l2tp/CMakeLists.txt`

**Interfaces:**
- Consumes: `link->pipe_rd` (existing, read-only peek target for `tee()`), `sess->switch_avps` (existing, credentials), `struct lcp_hdr_t` from `ppp_lcp.h` if includable (Task 1 note), else a local mirror.
- Produces: `struct l2tp_switch_pap_watcher_t` (new, one per pairing, pointer stored on the **downstream** `struct l2tp_sess_t` — add a field near `switch_link`/`switch_avps`, `l2tp.c:209-218`), `void l2tp_switch_pap_observe(struct l2tp_switch_pap_watcher_t *w, int from_upstream, const uint8_t *buf, size_t len)` (called from `l2tp_switch_link_read()` with the `tee()`'d peek copy).

- [ ] **Step 1: Decide on including `ppp_lcp.h` vs. mirroring `struct lcp_hdr_t`/`CONFACK`**

Check what `ppp_lcp.h` pulls in (`triton.h`, `ppp.h`, `ppp_fsm.h`) and whether any of that conflicts with or unnecessarily couples `l2tp_switch_pap.c` to the generic PPP layer framework this plan deliberately avoids. If it's clean, `#include "ppp_lcp.h"` and use `struct lcp_hdr_t`/`CONFACK`/`PPP_LCP` directly. If it drags in layer-framework symbols/state that don't belong in a file that never touches `ppp_t`, mirror just the three needed values locally instead (matching the existing `auth_pap.c`-mirroring precedent already used for `pap_hdr`), with a comment explaining the choice either way.

- [ ] **Step 2: Define the watcher struct and lifecycle**

```c
// l2tp_switch_pap.h
#ifndef L2TP_SWITCH_PAP_H
#define L2TP_SWITCH_PAP_H

#include <stdint.h>
#include <pthread.h>

struct l2tp_sess_t;
struct l2tp_switch_link_t;

struct l2tp_switch_pap_watcher_t;

/* Creates a watcher for a freshly-paired call, called once both splice
 * links exist (Task 2 Step 4's hook point). Returns NULL on allocation
 * failure -- caller must decide whether that's fatal to the pairing (it
 * should be: without a watcher, PAP never gets sent and the call always
 * times out downstream anyway, so failing the pairing outright here is
 * more honest than limping on). */
struct l2tp_switch_pap_watcher_t *l2tp_switch_pap_watcher_create(struct l2tp_sess_t *downstream);

/* Called from l2tp_switch_link_read() with a tee()'d, read-only peek copy
 * of a chunk that just passed through in the given direction. Does nothing
 * once the watcher has already resolved (success, failure, or freed). */
void l2tp_switch_pap_observe(struct l2tp_switch_pap_watcher_t *w, int from_upstream,
			     const uint8_t *buf, size_t len);

/* Tears down watcher state early -- called from any teardown path that can
 * interrupt a pairing before PAP resolves on its own (Task 4). Safe to call
 * more than once and safe to call after the watcher already resolved. */
void l2tp_switch_pap_watcher_free(struct l2tp_switch_pap_watcher_t *w);

#endif
```

- [ ] **Step 3: Implement frame detection in `l2tp_switch_pap_observe()`**

Parse only the first `sizeof(struct lcp_hdr_t)` (4) bytes of `buf` (bounds-check `len` first; a chunk shorter than 4 bytes can't be a control frame header, ignore it) to read `proto`(2, network order)/`code`(1). Track two flags on the watcher (`seen_confack_from_upstream`, `seen_confack_from_downstream`), guarded by the watcher's own mutex (see "Concurrency" above) since this function is called from two different triton contexts depending on `from_upstream`. When `proto == htons(PPP_LCP) && code == CONFACK`, set the flag for that direction. Once both are set (check under the same lock), proceed to Task 3's injection — but do the actual injection (a `write()` plus arming a timer) via `triton_context_call()` into the downstream leg's own context if this call is running in the upstream context, per the Concurrency section; if already in the downstream context, call directly. Do not write to `downstream->ppp.fd` from the upstream tunnel's context directly, even though the fd itself would tolerate it — the *watcher's own state* (timer, retry bookkeeping) must only be touched from one context, and mixing "sometimes direct, sometimes crossed" for the write itself invites exactly the kind of inconsistency this codebase's comments warn against elsewhere.

Once the watcher has resolved (Task 3/4), have it set an internal `resolved` flag (under the same lock) that makes this function an immediate no-op — this is what gives "zero ongoing overhead after resolution" from Task's architecture summary; `l2tp_switch_link_read()` can also check a cheap `watcher == NULL || watcher->resolved` before bothering to `tee()` at all (Step 5) rather than relying on `_observe()`'s internal early-return alone, to avoid the `tee()`/`read()` syscall cost entirely once done, not just the parsing cost.

- [ ] **Step 4: Wire watcher creation into `l2tp_switch_link_create()`'s call site**

In `l2tp_switch_finish_upstream()` (`l2tp.c:4575`), after both `l2tp_switch_link_create()` calls succeed (`l2tp.c:4615-4629`) and before the function's normal return, create the watcher and store it (e.g. `downstream->switch_pap_watcher = l2tp_switch_pap_watcher_create(downstream);`). If creation fails, fail the pairing the same way an `l2tp_switch_link_create()` failure already does just above (free both links, `goto err`) — do not let a pairing exist that will never send PAP and will always dead-end at the downstream target's own timeout.

- [ ] **Step 5: Add the `tee()`/peek call to `l2tp_switch_link_read()`**

Right after the existing input-side `splice(link->src->ppp.fd, NULL, link->pipe_wr, NULL, ...)` succeeds with `n > 0` bytes (`l2tp.c:4280-4297`) and before the existing output-side drain loop begins, if `link->dst`'s (for `from_upstream=1`) or `link->src`'s (for `from_upstream=0` — whichever end is the downstream session; derive this once at link-creation time and store it as a plain field on `l2tp_switch_link_t` rather than re-deriving it per read, e.g. `struct l2tp_sess_t *downstream_sess`) `switch_pap_watcher` is non-NULL and unresolved:
```c
uint8_t peek[16]; /* only the first few bytes of one frame matter */
int peek_fd[2];
if (pipe(peek_fd) == 0) {
	fcntl(peek_fd[0], F_SETFL, O_NONBLOCK);
	fcntl(peek_fd[1], F_SETFL, O_NONBLOCK);
	ssize_t teed = tee(link->pipe_rd, peek_fd[1], sizeof(peek), SPLICE_F_NONBLOCK);
	if (teed > 0) {
		ssize_t got = read(peek_fd[0], peek, sizeof(peek));
		if (got > 0)
			l2tp_switch_pap_observe(watcher, link->from_upstream, peek, (size_t)got);
	}
	close(peek_fd[0]);
	close(peek_fd[1]);
}
```
Creating/destroying a pipe pair on every single read call is wasteful (matches "KISS first, but not wastefully" — this is a real perf concern for a link carrying steady-state data traffic after PAP resolves, which is exactly why Step 3's early-exit-before-`tee()`-at-all matters). Prefer allocating the peek pipe **once**, alongside the two splice pipes, in `l2tp_switch_link_create()` (Task 2 Step 6 below) and reusing it for the watcher's lifetime, closing it once the watcher resolves (or immediately skip this whole block once `watcher->resolved`, per Step 3, so the long-lived peek pipe just sits idle and unused rather than being torn down/recreated — simpler, and the fd cost of one extra idle pipe per call for its lifetime is negligible).

- [ ] **Step 6: Add the peek pipe and `downstream_sess`/watcher-reference fields to `struct l2tp_switch_link_t`**

```c
struct l2tp_switch_link_t {
	...(existing fields)...
	struct l2tp_sess_t *downstream_sess; /* set at create time: whichever
		of src/dst is the downstream leg, for reaching its
		switch_pap_watcher without re-deriving from_upstream each read */
	int peek_pipe_rd, peek_pipe_wr; /* Task 2 Step 5 */
};
```
Close `peek_pipe_rd`/`peek_pipe_wr` in `l2tp_switch_link_free()` (`l2tp.c:4384-4428`) alongside the existing `pipe_rd`/`pipe_wr` close calls.

- [ ] **Step 7: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c accel-pppd/ctrl/l2tp/l2tp_switch_pap.c accel-pppd/ctrl/l2tp/l2tp_switch_pap.h accel-pppd/ctrl/l2tp/CMakeLists.txt
git commit -m "feat(l2tp): passively watch switch call legs for LCP settling"
```

---

## Task 3: Build and send the injected PAP request; handle the reply

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp_switch_pap.c`/`.h`

**Interfaces:**
- Consumes: `sess->switch_avps` (`Proxy_Authen_Name`/`Proxy_Authen_Response` AVP `val`/`len`), `write(2)` on `downstream->ppp.fd`.
- Produces: the watcher's resolution (success/failure), which Task 4 acts on.

- [ ] **Step 1: Mirror the wire structs**

```c
/* Mirrors accel-pppd/auth/auth_pap.c's struct pap_hdr/pap_ack exactly (RFC
 * 1334 §2.1/§2.2) -- that file is a self-contained static translation unit,
 * so this is a deliberate field-for-field copy, not a divergence. */
#define PAP_REQ 1
#define PAP_ACK 2
#define PAP_NAK 3

struct pap_hdr {
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));
```
(`Authenticate-Request`'s body after this header is `Peer-ID-Length`(1) + `Peer-ID` + `Passwd-Length`(1) + `Password`, per RFC 1334 §2.1 — not a fixed struct, build it into a flat buffer directly.)

- [ ] **Step 2: Build and send the request**

```c
uint8_t buf[256]; /* Proxy-Authen-Name/Response are both bounded well under
	this in every observed call; if a future one isn't, fail closed
	(log + treat as watcher failure) rather than truncating credentials
	silently -- truncated auth data must never be sent as if complete. */
struct pap_hdr *hdr = (struct pap_hdr *)buf;
uint8_t *p = buf + sizeof(*hdr);
struct l2tp_switch_avp_t *name = /* find Proxy_Authen_Name in switch_avps */;
struct l2tp_switch_avp_t *resp = /* find Proxy_Authen_Response in switch_avps */;

if (!name || !resp || sizeof(*hdr) + 1 + name->len + 1 + resp->len > sizeof(buf)) {
	/* log + fail the watcher (Task 3 Step 4) */
}

hdr->proto = htons(PPP_PAP);
hdr->code = PAP_REQ;
hdr->id = w->next_id++; /* start at 1, per session -- matches auth_pap.c's own req_id convention */
*p++ = (uint8_t)name->len;
memcpy(p, name->val, name->len); p += name->len;
*p++ = (uint8_t)resp->len;
memcpy(p, resp->val, resp->len); p += resp->len;
hdr->len = htons((uint16_t)(p - buf - 2)); /* everything after proto, per RFC 1334 + auth_pap.c's own HDR_LEN convention */

write(downstream->ppp.fd, buf, p - buf);
```
Note `sess->switch_avps`'s AVP array/`count` and the `Proxy_Authen_Name`/`Proxy_Authen_Response` `enum`/`#define` values already exist (`l2tp.c:228-239`, capture switch at `l2tp.c:5686-5690`) — use those exact identifiers, don't re-derive AVP type numbers.

Arm a `triton_timer_t` at this point (mirroring `auth_pap.c`'s own `conf_timeout = 5` seconds default, but per the prior revision's own reasoning, strictly *less* than the ~5s Luiz's LNS is observed to wait, so our own timeout fires first and produces an attributable log line instead of racing his CDN — e.g. 3000ms) via `triton_context_call()` into the downstream context if not already there (Concurrency section).

- [ ] **Step 3: Detect and handle the reply**

Extend `l2tp_switch_pap_observe()` (Task 2 Step 3): once the request has been sent (new watcher state, e.g. `w->request_sent`), also check incoming `from_upstream=0` (downstream→upstream direction — i.e., frames *from* the downstream target) chunks for `proto == htons(PPP_PAP)`. On `code == PAP_ACK`: cancel the timer, mark `w->resolved = 1`, log success, done — splicing continues exactly as it already has been (this frame itself also continues on to be spliced to the real upstream client via the existing, untouched output-side `splice()` in the same read call — the real client silently ignoring an unexpected PAP-Ack it never requested is expected and harmless per RFC 1661's general "silently discard unexpected/unmatched control frames" behavior; note this explicitly in the code comment so a future reader doesn't "fix" it). On `code == PAP_NAK`: cancel the timer, mark `w->resolved = 1`, proceed to Task 4's teardown path.

- [ ] **Step 4: Timeout handling**

On the timer firing before either ACK or NAK is seen: same as NAK — mark resolved, log a specific "downstream never answered our PAP within Xms" message (distinct from the NAK log line, since this is a different failure mode worth telling apart when debugging), proceed to Task 4's teardown path.

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp_switch_pap.c accel-pppd/ctrl/l2tp/l2tp_switch_pap.h
git commit -m "feat(l2tp): inject live PAP request on switch downstream leg, handle reply"
```

---

## Task 4: Teardown on NAK/timeout, and cleanup on any other early death

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c` (call `l2tp_switch_pap_watcher_free()` from every existing teardown path that can interrupt a pairing)
- Modify: `accel-pppd/ctrl/l2tp/l2tp_switch_pap.c`

**Interfaces:**
- Consumes: this codebase's existing switch-teardown conventions — re-read `l2tp_switch_place_call_on()`'s `err_no_pairing`/`err_pairing_done` paths and `l2tp_switch_teardown_peer()` in full (`l2tp.c:5257-5396`, `l2tp.c:4441-4473`) before writing this; mirror them exactly rather than inventing a third teardown shape for this one new failure mode.

- [ ] **Step 1: NAK/timeout → disconnect both legs**

Since the watcher's resolution runs in (or has been `triton_context_call()`'d into) the downstream leg's own tunnel context, disconnecting the downstream session directly is legal there (`l2tp_session_disconnect(downstream, 2, 6)`, matching every other in-context failure path already in this file). Crossing into the paired **upstream** session's own context to disconnect it too must copy the exact existing pattern from `l2tp_switch_place_call_on`'s failure paths — do not write a new cross-context helper for this.

- [ ] **Step 2: Free the watcher (and its peek pipes, via the links, which already get freed on any teardown) from every path that can end a pairing early**

Mirror exactly how `switch_link`/`switch_avps` are already cleaned up in `l2tp_session_free()`'s existing Task-8-equivalent teardown hook (`l2tp.c` — read the full surrounding function fresh, field names may have shifted slightly since the prior investigation) — add `l2tp_switch_pap_watcher_free(sess->switch_pap_watcher)` alongside those existing cleanup calls, not as a new, separately-triggered path. Must be safe to call when the watcher never got created (allocation failure, Task 2 Step 4), already resolved, or is mid-flight.

- [ ] **Step 3: Write the failing test — upstream dies mid-PAP**

Extend/adapt the standalone `l2tp_switch_peer_test.c`-style harness (see Task 6): script the fake upstream call to disconnect (send a CDN on the upstream leg) while the injected `PAP_REQ` is outstanding on the downstream leg. Assert the downstream leg is torn down too, with no orphaned tunnel and no leaked watcher — matching the "confirmed on a real VM: active stuck at 1 indefinitely" class of bug this codebase has fixed before elsewhere (comment block at `l2tp.c:5275-5291` describes the shape of this exact failure mode).

- [ ] **Step 4: Run it, confirm it fails, fix, confirm it passes**

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c accel-pppd/ctrl/l2tp/l2tp_switch_pap.c
git commit -m "fix(l2tp): tear down switch downstream PAP watcher cleanly on any early pairing death"
```

---

## Task 5: On-demand connect/drain-pending-calls interaction — verify, don't reimplement

**Files:** none expected — verification only.

- [ ] **Step 1: Confirm both call-placement paths converge above this change**

Both the "fast path" (`l2tp_switch_place_downstream_call()`'s immediate branch) and the "on-demand drain" path (`l2tp_switch_drain_pending_calls()` → `l2tp_switch_place_call_on()`) already funnel into the same `l2tp_switch_finish_upstream()` → `l2tp_switch_link_create()` call site that Task 2 Step 4 hooks watcher creation into. Confirm this after Tasks 2-4 are done — if either placement path turns out to need its own watcher-awareness, that's a sign the hook is in the wrong place, not something to patch around here.

- [ ] **Step 2: Add one test for the on-demand path specifically**

Confirm a call arriving while the target's on-demand tunnel is still connecting also gets the watcher attached and PAP injected once the tunnel comes up, not just the fast-path call.

- [ ] **Step 3: Commit** (test-only, if anything needed touching to make this path testable)

---

## Task 6: Standalone test harness

**Files:**
- Create: `accel-pppd/ctrl/l2tp/l2tp_switch_downstream_pap_test.c` (new, standalone — not part of the cmake build, following the exact convention of `l2tp_switch_peer_test.c`/`packet_test.c` in the same directory)

- [ ] **Step 1: Script a fake downstream LNS and a fake upstream peer**

Reuse `l2tp_switch_peer_test.c`'s existing role (fake upstream, per its own doc comment) for the upstream side; add a fake downstream role (or reuse/extend the existing `--listen` mode, described as "a downstream l2tp-switch target, accepting the switch's own outbound SCCRQ instead of sending one" — check if this already fits before adding a new mode) that does real LCP (`Configure-Request`/`Ack`) with whatever the switch relays, then waits for a PAP `Authenticate-Request` and responds with `Ack` (happy path) or `Nak` (failure path) per a command-line flag.

- [ ] **Step 2: Assert on both paths**

Happy path: assert the fake downstream LNS receives a well-formed `Authenticate-Request` containing the exact Name/Response bytes the fake upstream's ICCN proxied, and that after `Ack`ing it, ordinary data continues to splice through untouched (send a probe payload each direction post-auth, assert it arrives). Failure path (`Nak`): assert both legs get torn down (CDN/StopCCN observed on both sides).

- [ ] **Step 3: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp_switch_downstream_pap_test.c
git commit -m "test(l2tp): add standalone harness for switch downstream PAP watcher"
```

---

## Task 7: Documentation

**Files:**
- Modify: `docs/l2tp_switching.md`
- Modify: `CHANGELOG.md` (under `[Unreleased]`, matching this repo's existing convention — confirm from recent commits, e.g. `2b467b86`)

- [ ] **Step 1: Document the new behavior**

Explain: switched calls now get live PAP injected on the downstream leg by passively watching the already-spliced stream for LCP settling, using credentials captured from the upstream ICCN's Proxy-Authen AVPs — no local PPP session, no local auth decision, works against any unmodified downstream LNS. Note the PAP-only limitation explicitly (Global Constraints) and the one-injected-frame mechanism (so a future reader troubleshooting "why does the downstream leg see one PPP frame accel-ppp itself never relayed" isn't confused — this is the one deliberate exception to "pure transparent pipe").

- [ ] **Step 2: Commit**

```bash
git add docs/l2tp_switching.md CHANGELOG.md
git commit -m "docs: document live PAP injection on l2tp-switch downstream leg"
```

---

## Self-Review Notes

- **Spec coverage:** works against unmodified downstream LNS (no local PPP session needed at all — stronger than the prior revision's version of this requirement); no local auth decision (hard user constraint, satisfied structurally — we never look at whether credentials are "correct", only relay bytes and relay the verdict); PAP-only (explicit); reuses captured credentials and existing wire structs; respects cross-context-call discipline (the Concurrency section is new and is the single most important addition versus the prior revision); integrates with on-demand connect (Task 5).
- **What got simpler versus the prior revision, concretely:** zero touches to `accel-pppd/ppp/*.c`; no new `struct ppp_t` flag; no fighting the generic layer-chain driver to make it stop early; no need to answer "does Luiz's LNS demand CI_AUTH from us" at all, since we never negotiate LCP options ourselves.
- **What got *more* precisely specified than before:** the Concurrency section — the prior revision's design ran everything in a single leg's context by construction (a real local `ppp_t` naturally lives in one context); this design's core mechanism (watching *both* directions) inherently spans two contexts, so this needed to be nailed down explicitly rather than inherited for free. Flagging this prominently rather than letting it be discovered mid-implementation is the main risk-reduction this revision adds beyond "simpler."
- **Known gaps:** CHAP client support (explicitly out of scope). The `tee()`-based peek assumes frame-boundary-per-`splice()`-chunk (Task 1 Step 1) — plausible and consistent with existing code's own implicit assumption, but flagged for empirical confirmation rather than asserted.
- **Placeholder scan:** every step above has concrete code, a concrete syscall sequence, or a concrete file/line to read before writing — nothing deferred to "figure it out during implementation" except Task 1 Step 1's empirical confirmation (deliberately data-gathering, not code) and Task 2 Step 1's `ppp_lcp.h`-include-or-mirror decision (deliberately left as a first-five-minutes-of-Task-2 call once the header's actual contents are in front of the implementer).
