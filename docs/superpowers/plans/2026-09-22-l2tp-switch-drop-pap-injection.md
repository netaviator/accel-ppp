# L2TP switch: remove live-PAP injection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the l2tp-switch live-PAP-injection watcher (two confirmed production bugs: a watcher-creation race, and redundant injection against calls that already authenticated live) and replace it with a documented partner requirement plus stateless diagnostic logging.

**Architecture:** The watcher (`struct l2tp_switch_pap_watcher_t` and ~25 functions/fields built around it in `accel-pppd/ctrl/l2tp/l2tp.c`) is deleted outright — its `pap-timeout` config knob, its per-session pointer, its cross-context injection/timeout machinery. In its place, the existing `tee()`-based peek mechanism on the downstream-fed splice link is kept but reduced to a small, stateless, single-context function that only logs what the target's own LCP asks for (PAP/CHAP/other/none), for operator diagnosis — no timers, no locks, no injected traffic, no effect on the call.

**Tech Stack:** C (accel-ppp / triton event loop), Python/pytest E2E tests using the repo's own `l2tp_switch_peer_test` harness binary.

**Spec:** `docs/superpowers/specs/2026-09-22-l2tp-switch-drop-pap-injection-design.md`

## Global Constraints

- **Build and test environment:** the host is macOS; building and running this suite requires a Linux container (linuxkit's kernel has PPPoL2TP built in; macOS does not). Every build/test step in this plan assumes a running privileged container named `accel` with the repo mounted at `/src`:
  ```bash
  docker ps --filter name=^accel$ --format '{{.Names}}' | grep -q accel || \
    docker run -d --name accel --privileged -v <repo-path>:/src debian:12 sleep infinity
  docker exec accel bash -c 'command -v cmake || (apt update && apt install -y build-essential cmake libpcre2-dev libssl-dev liblua5.1-0-dev python3-pytest python3-pytest-dependency python3-pytest-order iproute2 ppp pppoe tcpdump timelimit libxml2-dev zlib1g-dev)'
  docker exec accel bash -c 'mkdir -p /build'
  ```
  Build: `docker exec -w /build accel bash -c 'cmake -DCMAKE_INSTALL_PREFIX=/usr -DLUA=TRUE -DSHAPER=TRUE -DRADIUS=TRUE /src && make -j8 && echo rc=$? && make install && echo rc=$?'` — check the printed `rc=0`, never just grep output for `error` (a stale binary from a silently-failed build has bitten this project before).
  Test: `docker exec -w /src/tests accel python3 -m pytest -q -m l2tp_switch accel-pppd/l2tp_switch/<file-or-dir>`.
  Every plan step below that says "run the build" or "run the tests" means through this container, not directly on the host.
- Touch only what this removal requires. Do not refactor unrelated code in `l2tp.c`, even if you notice something that could be improved (per this repo's own convention — see `feedback_scope_only_our_changes` in project memory).
- Every task must leave the tree in a state that builds and (where applicable) passes its own new/updated tests before moving to the next task.
- Never bypass git hooks or signing. If a commit's pre-commit hook fails, fix the issue and create a new commit — do not amend.
- Config compatibility: an existing `pap-timeout=` line in `[l2tp-switch]` becomes a silently-ignored no-op after this change, matching this parser's existing behavior for every other unrecognized option (there is no catch-all "reject unknown option" in `l2tp_switch_conf_load()` today — see Task 1). This is called out explicitly in the docs update (Task 5), not treated as a bug to special-case.
- `Proxy-Authen-*` AVP **capture and re-injection into the outbound ICCN** (`l2tp_switch_capture_avp()`, the `case Proxy_Authen_*:` block around `l2tp.c:6747-6751`, and the re-injection loop in `l2tp_send_ICCN()` around `l2tp.c:3356-3371`) is used by `match=Proxy-Authen-Name,...` routing rules and is **completely independent of PAP injection**. Do not touch it. Only the *consumption* of these AVPs inside the deleted `l2tp_switch_pap_send_request()` goes away.

---

## Task 1: Remove the `pap-timeout` config option

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp_switch_conf.h`
- Modify: `accel-pppd/ctrl/l2tp/l2tp_switch_conf.c`
- Modify: `accel-pppd/accel-ppp.conf`
- Modify: `accel-pppd/accel-ppp.conf.5`
- Test: `tests/accel-pppd/l2tp_switch/test_switch_config.py` (read-only check, see Step 4)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing later tasks depend on — this is a pure removal. Confirm no other file references `l2tp_switch_conf_pap_timeout_ms` before finishing (Step 1).

- [ ] **Step 1: Confirm the function has exactly the callers this plan already knows about**

Run: `grep -rn "l2tp_switch_conf_pap_timeout_ms\|conf_pap_timeout_sec\|L2TP_SWITCH_DEFAULT_PAP_TIMEOUT_SEC" accel-pppd/`

Expected: only `l2tp_switch_conf.h` (declaration + `#define`), `l2tp_switch_conf.c` (definition + two uses), and `accel-pppd/ctrl/l2tp/l2tp.c` (the watcher's `l2tp_switch_pap_timeout()`, which Task 3 removes). If anything else shows up, stop and re-scope this task before continuing.

- [ ] **Step 2: Remove the declaration and default from the header**

In `accel-pppd/ctrl/l2tp/l2tp_switch_conf.h`, remove this line from the `#define` block:

```c
#define L2TP_SWITCH_DEFAULT_PAP_TIMEOUT_SEC 3
```

and remove this doc comment + declaration:

```c
/* How long the live-PAP watcher waits for the downstream target's Ack/Nak to
 * the request it injected before it gives up and disconnects the call. Keep
 * it below the ~5s a downstream LNS has been observed to wait for PAP itself
 * (so our timeout produces an attributable log line instead of racing its
 * CDN), but long enough for a target whose authentication backend (RADIUS)
 * is slow to answer. */
int l2tp_switch_conf_pap_timeout_ms(void);
```

- [ ] **Step 3: Remove the storage, getter, parsing, and reset in `l2tp_switch_conf.c`**

Remove the static variable:

```c
static int conf_pap_timeout_sec = L2TP_SWITCH_DEFAULT_PAP_TIMEOUT_SEC;
```

Remove the getter function:

```c
int l2tp_switch_conf_pap_timeout_ms(void)
{
	return conf_pap_timeout_sec * 1000;
}
```

Remove the reset line inside `switch_conf_clear()`:

```c
	conf_pap_timeout_sec = L2TP_SWITCH_DEFAULT_PAP_TIMEOUT_SEC;
```

Remove the parsing block inside the options loop:

```c
		if (!strcmp(opt->name, "pap-timeout") && opt->val)
			if (parse_timing_sec(opt->name, opt->val,
					     &conf_pap_timeout_sec) < 0)
				return -1;
```

- [ ] **Step 4: Confirm the config test suite doesn't reference `pap-timeout`**

Run: `grep -n "pap-timeout" tests/accel-pppd/l2tp_switch/test_switch_config.py`

Expected: no output. (If it does reference it, read that test and remove only the `pap-timeout`-specific assertions, keeping the rest of the file — do not do this blindly; report back if this happens since it wasn't expected from Task 1's own file scan.)

- [ ] **Step 5: Remove the option from the shipped example config and the man page**

In `accel-pppd/accel-ppp.conf`, remove these two lines:

```
# how long to wait for the target to answer the injected PAP request (default 3)
#pap-timeout=3
```

In `accel-pppd/accel-ppp.conf.5`, remove this block:

```
.TP
.BI "pap-timeout=" seconds
How long the live-PAP watcher waits for the downstream target's Ack/Nak to
the PAP request it injected before it disconnects the call. Whole seconds,
1-3600. Default: 3.
```

- [ ] **Step 6: Build**

Run the container build from Global Constraints (`cmake ... && make -j8 && make install` in `/build`, inside the `accel` container). Confirm `rc=0` printed after both `make` and `make install`.

Expected: builds cleanly, no undefined-reference errors for `l2tp_switch_conf_pap_timeout_ms`.

- [ ] **Step 7: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp_switch_conf.h accel-pppd/ctrl/l2tp/l2tp_switch_conf.c accel-pppd/accel-ppp.conf accel-pppd/accel-ppp.conf.5
git commit -m "$(cat <<'EOF'
refactor(l2tp): remove the pap-timeout config option

Dead weight ahead of removing the live-PAP-injection watcher itself
(next commit) -- nothing reads conf_pap_timeout_sec once that watcher
is gone. An existing pap-timeout= line in [l2tp-switch] now becomes a
silently-ignored no-op, matching this parser's existing behavior for
every other unrecognized option.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add the failing test for the new (no-injection) behavior

**Files:**
- Create: `tests/accel-pppd/l2tp_switch/test_switch_downstream_no_pap_help.py`

**Interfaces:**
- Consumes: `alloc_ports`, `start_instance`, `read_log`, `wait_up`, `switch_show`, `wait_for`, `finish_harness` from `tests/accel-pppd/l2tp_switch/helpers.py` (all pre-existing, used exactly as in `test_switch_downstream_pap.py`); `config`, `accel_pppd_process`, `l2tp_peer_process` from `common` (pre-existing).
- Produces: a test that fails against the current (pre-removal) code, and must pass once Task 3 is done. It asserts on two log strings that Task 3's new logging function must produce/must-not-produce — see Task 3's exact wording, which this test's assertions are written against verbatim.

This test intentionally does **not** delete `test_switch_downstream_pap.py` or `test_switch_downstream_pap_race.py` yet — those still exist and still pass against the current code. They're removed in Task 4, once the behavior they test no longer exists.

- [ ] **Step 1: Write the new test file**

```python
import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, read_log, wait_up, switch_show, wait_for, finish_harness


@pytest.mark.l2tp_switch
def test_switch_downstream_no_pap_help(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """accel-ppp does not authenticate a switched call on the downstream
    target's behalf (see docs/l2tp_switching.md's Authentication section
    and docs/superpowers/specs/2026-09-22-l2tp-switch-drop-pap-injection-design.md).
    A target that asks for PAP gets that fact logged for operator
    visibility, but the switch never injects a PAP request and never tears
    the call down on the target's behalf -- it stays a transparent pipe.
    """
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        switch_cli,
        "127.0.0.1",
        switch_l2tp,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started

    try:
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_l2tp),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--hold-seconds", "6",
                "--minimal-lcp",
                "--lcp-auth", "pap",
            ],
        )

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "injected-user",
                    "--proxy-password", "injected-pass",
                    "--minimal-lcp",
                    "--hold-seconds", "5",
                ],
            )

            out = ""

            def still_up():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 1" in out

            # Negative check (scale=False, per wait_for's own docstring):
            # nothing on our side should ever tear this call down over the
            # whole hold window -- proves no injected PAP request, no
            # reply-timeout, no CDN sent by the switch itself.
            assert wait_for(still_up, 4.0, scale=False), (
                f"switch tore the call down on its own:\n{out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{harness_out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            log = read_log(s_cfg)
            assert "downstream LCP Configure-Request asks for PAP" in log, (
                "expected the visibility log line for the target's own PAP"
                f" request, got:\n{log}"
            )
            assert "injected live PAP request" not in log, (
                f"switch injected a PAP request -- this feature was removed:\n{log}"
            )
        finally:
            finish_harness(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        config.delete_tmp(s_cfg)
```

- [ ] **Step 2: Run it and confirm it fails against the current code**

First rebuild/install so the container's installed `accel-pppd` matches the working tree (Global Constraints build command — Task 2 makes no C changes, but the container's installed binary must reflect whatever Task 1 already changed). Then:

Run: `docker exec -w /src/tests accel python3 -m pytest -q -m l2tp_switch accel-pppd/l2tp_switch/test_switch_downstream_no_pap_help.py -v`

Expected: FAIL. Against the current watcher, this should fail either on the `still_up` assertion (the watcher's own 3s `pap-timeout` tears the call down since the test's downstream peer never Acks the injected request) or on `"injected live PAP request" not in log` (the string is present). Read the actual failure output and confirm it's one of these two — if it fails for a different reason (e.g. a harness/config error), fix the test itself before proceeding, since Task 3 must not be the first place this test is exercised.

- [ ] **Step 3: Commit**

```bash
git add tests/accel-pppd/l2tp_switch/test_switch_downstream_no_pap_help.py
git commit -m "$(cat <<'EOF'
test(l2tp): add failing test for no-PAP-injection behavior

Encodes the target behavior for the upcoming watcher removal: a
switched call to a target asking for PAP just sits on the transparent
pipe (no injected request, no switch-side teardown), with the
target's own auth request still logged for operator visibility.
Fails against the current live-PAP-injection watcher.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Remove the live-PAP-injection watcher, keep stateless LCP-auth logging

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c`

**Interfaces:**
- Consumes: `struct l2tp_switch_link_t` (existing, gets one field removed and one added), `l2tp_switch_lcp_find_auth()` (existing, unchanged, kept — pure buffer parsing, no watcher dependency), `struct l2tp_switch_lcp_hdr` (existing, unchanged, kept).
- Produces: `l2tp_switch_link_log_lcp_auth()` — the new function Task 2's test asserts the log output of. Signature: `static void l2tp_switch_link_log_lcp_auth(struct l2tp_switch_link_t *link, const uint8_t *buf, size_t len)`. No other task calls it directly; it's wired into `l2tp_switch_link_peek()` in this same task.

This task is one coherent change (the struct, the removal, and the replacement logging function are too entangled to split further and still compile), broken into ordered steps.

- [ ] **Step 1: Remove the `switch_pap_watcher` field from `struct l2tp_sess_t`**

In `accel-pppd/ctrl/l2tp/l2tp.c`, remove:

```c
	struct l2tp_switch_pap_watcher_t *switch_pap_watcher; /* live-PAP
		injection watcher for this pairing's downstream leg; only
		ever set on the downstream session, NULL everywhere else
		(see l2tp_switch_pap_watcher_create()) */
```

(It sits between `switch_link` and `switch_pending_entry` in the struct — leave both of those alone.)

- [ ] **Step 2: Remove the forward declaration and its doc comment**

Remove:

```c
/* l2tp-switch: live-PAP injection watcher (see the big comment above its
 * implementation, next to l2tp_switch_link_read() below). Forward-declared
 * here for the same reason as l2tp_switch_link_t just above: the teardown
 * hook in l2tp_session_free() needs to free it well before its natural
 * definition point. */
struct l2tp_switch_pap_watcher_t;
static void l2tp_switch_pap_watcher_detach(struct l2tp_sess_t *sess);
```

Leave the `struct l2tp_switch_link_t;` forward declaration and its own comment directly above (lines 305-314) untouched — that type isn't going away.

- [ ] **Step 3: Remove the teardown call and update the threading-rule comment**

In `l2tp_session_free()`, remove this line:

```c
	l2tp_switch_pap_watcher_detach(sess);
```

(It sits between `u = l2tp_switch_unpair(sess, 1);` and `if (u.link)` — leave both of those.)

In the comment above `l2tp_switch_pair_lock`'s declaration, update:

```c
/* Threading rule for the l2tp-switch pairing state of a session
 * (switch_upstream/switch_downstream, switch_link, switch_pap_watcher,
 * switch_avps): the fields are only ever *torn down* on the session's own
```

to:

```c
/* Threading rule for the l2tp-switch pairing state of a session
 * (switch_upstream/switch_downstream, switch_link, switch_avps): the
 * fields are only ever *torn down* on the session's own
```

- [ ] **Step 4: Replace the `l2tp_switch_link_t` struct fields**

Change:

```c
	struct l2tp_sess_t *downstream_sess; /* whichever of src/dst is the
		downstream leg, set once at create time so
		l2tp_switch_link_read() can reach switch_pap_watcher without
		re-deriving it from from_upstream on every read */
	int ack_pending; /* the frame just peeked was an upstream LCP Configure-Ack
		the PAP watcher wants to be told has been forwarded */
	int peek_pipe_rd, peek_pipe_wr; /* small side pipe tee() duplicates a
		peek copy of in-flight frames into, for the live-PAP watcher;
		always created alongside pipe_rd/pipe_wr and closed the same
		way, whether or not a watcher ever actually gets attached */
```

to:

```c
	struct l2tp_sess_t *downstream_sess; /* whichever of src/dst is the
		downstream leg -- used for log_session() in
		l2tp_switch_link_log_lcp_auth() below */
	unsigned int logged_conf_req:1; /* the target's first LCP
		Configure-Request has already been logged (see
		l2tp_switch_link_log_lcp_auth()) -- only meaningful on the
		downstream-fed (from_upstream == 0) link */
	int peek_pipe_rd, peek_pipe_wr; /* small side pipe tee() duplicates a
		peek copy of in-flight frames into, purely so the
		downstream-fed link can log what the target's own LCP asks
		for -- see l2tp_switch_link_log_lcp_auth(). Always created
		alongside pipe_rd/pipe_wr and closed the same way. */
```

- [ ] **Step 5: Delete the entire watcher subsystem block**

Delete everything from the big doc comment starting with:

```c
/* l2tp-switch: live-PAP injection watcher for a switched call's downstream
 * leg (see docs/l2tp_switching.md). A switched call never runs a local PPP
```

through the end of `l2tp_switch_pap_watcher_create()`:

```c
static struct l2tp_switch_pap_watcher_t *l2tp_switch_pap_watcher_create(struct l2tp_sess_t *downstream)
{
	struct l2tp_switch_pap_watcher_t *w = _malloc(sizeof(*w));

	if (!w)
		return NULL;

	memset(w, 0, sizeof(*w));
	pthread_mutex_init(&w->lock, NULL);
	w->downstream = downstream;
	w->next_id = 1;
	w->refcount = 1; /* the owning session's pointer */

	return w;
}
```

This removes: the doc comment, `struct l2tp_switch_pap_watcher_t`, `struct l2tp_switch_pap_hdr`, the `L2TP_SWITCH_PROXY_AUTHEN_TEXT`/`L2TP_SWITCH_PROXY_AUTHEN_PAP`/`L2TP_SWITCH_PAP_REQ`/`L2TP_SWITCH_PAP_ACK`/`L2TP_SWITCH_PAP_NAK` `#define`s, and `l2tp_switch_pap_watcher_create()`. **Do not delete** the six `#define`s just above that block that this task's new logging function still needs:

```c
#define L2TP_SWITCH_PPP_LCP 0xc021
#define L2TP_SWITCH_PPP_PAP 0xc023
#define L2TP_SWITCH_PPP_CHAP 0xc223
#define L2TP_SWITCH_LCP_CONFREQ 1
#define L2TP_SWITCH_LCP_CONFACK 2
#define L2TP_SWITCH_LCP_TERMREQ 5
#define L2TP_SWITCH_LCP_PROTREJ 8
#define L2TP_SWITCH_LCP_OPT_AUTH 3 /* Authentication-Protocol */
```

`L2TP_SWITCH_LCP_CONFACK` (value 2) is only used by code being deleted in this task — safe to delete it too, along with `struct l2tp_switch_lcp_hdr`'s own neighbors; but **keep** `struct l2tp_switch_lcp_hdr` itself (defined a few lines below these `#define`s) and `l2tp_switch_lcp_find_auth()` (defined further below still) — both are reused by this task's new logging function. Delete `L2TP_SWITCH_LCP_CONFACK` specifically since nothing keeps using it.

- [ ] **Step 6: Delete the rest of the watcher's functions, in order**

Delete each of the following functions in full (they run from `l2tp_switch_pap_watcher_hold()` through `l2tp_switch_pap_log_skip()`, i.e. everything between the just-deleted `l2tp_switch_pap_watcher_create()` and `l2tp_switch_lcp_find_auth()`, **except** `l2tp_switch_lcp_find_auth()` itself and `l2tp_switch_pap_log_lcp()`, which step 7 replaces rather than deletes outright):

- `l2tp_switch_pap_watcher_hold()`
- `l2tp_switch_pap_watcher_put()`
- `l2tp_switch_pap_watcher_free()`
- `l2tp_switch_pap_ptr_lock` (the `static pthread_mutex_t` — its own three-line doc comment too)
- `l2tp_switch_pap_watcher_get()`
- `l2tp_switch_pap_watcher_detach()`
- `l2tp_switch_pap_disconnect_cb()`
- `l2tp_switch_pap_disconnect()`
- `l2tp_switch_pap_send_request()` (including its doc comment)
- `l2tp_switch_pap_timeout()` and its own forward declaration (`static void l2tp_switch_pap_timeout(struct triton_timer_t *t);`, which sits just before `l2tp_switch_pap_watcher_create()` — already gone as part of Step 5, confirm it didn't survive)
- `l2tp_switch_pap_decide_locked()`
- `l2tp_switch_pap_log_skip()`
- `l2tp_switch_pap_start_send()`
- `l2tp_switch_pap_upstream_ack_delivered()`
- `l2tp_switch_pap_observe()` (including its doc comment)

Leave `l2tp_switch_lcp_find_auth()` exactly as-is — it has zero watcher dependency (pure `buf`/`len` parsing) and is reused by the new logging function.

- [ ] **Step 7: Replace `l2tp_switch_pap_log_lcp()` with a link-based, stateless equivalent**

Delete `l2tp_switch_pap_log_lcp()`:

```c
static void l2tp_switch_pap_log_lcp(struct l2tp_switch_pap_watcher_t *w,
				    const uint8_t *buf, size_t len)
{
	/* ... existing body ... */
}
```

Replace it with:

```c
/* Purely observational: logs what the downstream target's own LCP traffic
 * says about authentication, so an operator can tell from the log why a
 * switched call to a target that expects live authentication isn't
 * authenticating -- accel-ppp does not perform or relay authentication on
 * the target's behalf (see docs/l2tp_switching.md's Authentication
 * section). Stateless beyond link->logged_conf_req (dedup for the target's
 * first Configure-Request); never touches either leg's traffic. Called only
 * for frames fed by the downstream leg (from_upstream == 0), from
 * l2tp_switch_link_peek() on that link's own context -- no lock needed. */
static void l2tp_switch_link_log_lcp_auth(struct l2tp_switch_link_t *link,
					  const uint8_t *buf, size_t len)
{
	const struct l2tp_switch_lcp_hdr *lcp = (const struct l2tp_switch_lcp_hdr *)buf;
	uint16_t proto;
	uint8_t algo;
	int truncated;
	size_t end, o;

	if (link->from_upstream || len < sizeof(*lcp) ||
	    lcp->proto != htons(L2TP_SWITCH_PPP_LCP))
		return;

	if (lcp->code == L2TP_SWITCH_LCP_CONFREQ) {
		if (link->logged_conf_req)
			return;
		link->logged_conf_req = 1;
	} else if (lcp->code != L2TP_SWITCH_LCP_PROTREJ &&
		   lcp->code != L2TP_SWITCH_LCP_TERMREQ) {
		return;
	}

	end = sizeof(lcp->proto) + ntohs(lcp->len);
	o = sizeof(*lcp);
	if (end > len)
		end = len;

	switch (lcp->code) {
	case L2TP_SWITCH_LCP_CONFREQ:
		if (l2tp_switch_lcp_find_auth(buf, len, &proto, &algo, &truncated)) {
			if (proto == L2TP_SWITCH_PPP_PAP)
				log_session(log_info1, link->downstream_sess,
					    "l2tp-switch: downstream LCP"
					    " Configure-Request asks for PAP\n");
			else if (proto == L2TP_SWITCH_PPP_CHAP)
				log_session(log_info1, link->downstream_sess,
					    "l2tp-switch: downstream LCP"
					    " Configure-Request asks for CHAP"
					    " (algorithm 0x%02x)\n", algo);
			else
				log_session(log_info1, link->downstream_sess,
					    "l2tp-switch: downstream LCP"
					    " Configure-Request asks for"
					    " authentication protocol 0x%04x\n",
					    proto);
			break;
		}
		log_session(log_info1, link->downstream_sess,
			    "l2tp-switch: downstream LCP Configure-Request has"
			    " no authentication-protocol option%s\n",
			    truncated ? " in the bytes inspected" : "");
		break;
	case L2TP_SWITCH_LCP_PROTREJ:
		if (o + 2 <= end)
			log_session(log_warn, link->downstream_sess,
				    "l2tp-switch: downstream rejected PPP"
				    " protocol 0x%04x (LCP Protocol-Reject)\n",
				    (buf[o] << 8) | buf[o + 1]);
		break;
	case L2TP_SWITCH_LCP_TERMREQ:
		log_session(log_warn, link->downstream_sess,
			    "l2tp-switch: downstream sent an LCP"
			    " Terminate-Request\n");
		break;
	}
}
```

- [ ] **Step 8: Simplify `l2tp_switch_link_peek()`**

Replace:

```c
static void l2tp_switch_link_peek(struct l2tp_switch_link_t *link)
{
	struct l2tp_switch_pap_watcher_t *w =
		l2tp_switch_pap_watcher_get(link->downstream_sess);
	uint8_t peek[64]; /* enough for an LCP Configure-Request's common
			     options (l2tp_switch_pap_log_lcp()); the watcher
			     itself only needs the first 6 bytes */
	ssize_t teed, got;

	if (!w)
		return;

	if (!__atomic_load_n(&w->resolved, __ATOMIC_RELAXED)) {
		teed = tee(link->pipe_rd, link->peek_pipe_wr, sizeof(peek),
			   SPLICE_F_NONBLOCK);
		if (teed > 0) {
			got = read(link->peek_pipe_rd, peek, sizeof(peek));
			if (got > 0 &&
			    l2tp_switch_pap_observe(w, link->from_upstream,
						    peek, (size_t)got))
				link->ack_pending = 1;
		}
	}
	l2tp_switch_pap_watcher_put(w);
}
```

with:

```c
/* live-PAP-auth logging: peek at what just landed in link->pipe_rd --
 * tee(2) duplicates, it does not consume, so the real splice(out) that
 * follows sees pipe_rd exactly as if this were not here. Must run before
 * that splice drains pipe_rd. Only the downstream-fed direction is ever
 * worth inspecting -- see l2tp_switch_link_log_lcp_auth(). */
static void l2tp_switch_link_peek(struct l2tp_switch_link_t *link)
{
	uint8_t peek[64]; /* enough for an LCP Configure-Request's common
			     options -- see l2tp_switch_link_log_lcp_auth() */
	ssize_t teed, got;

	if (link->from_upstream)
		return;

	teed = tee(link->pipe_rd, link->peek_pipe_wr, sizeof(peek),
		   SPLICE_F_NONBLOCK);
	if (teed > 0) {
		got = read(link->peek_pipe_rd, peek, sizeof(peek));
		if (got > 0)
			l2tp_switch_link_log_lcp_auth(link, peek, (size_t)got);
	}
}
```

- [ ] **Step 9: Remove `l2tp_switch_link_ack_forwarded()` and simplify `l2tp_switch_link_read()`**

Delete in full:

```c
/* Tells the PAP watcher that the upstream LCP Configure-Ack it saw in
 * l2tp_switch_link_peek() has now been written to the downstream socket. */
static void l2tp_switch_link_ack_forwarded(struct l2tp_switch_link_t *link)
{
	struct l2tp_switch_pap_watcher_t *w =
		l2tp_switch_pap_watcher_get(link->downstream_sess);

	link->ack_pending = 0;
	if (!w)
		return;
	l2tp_switch_pap_upstream_ack_delivered(w);
	l2tp_switch_pap_watcher_put(w);
}
```

In `l2tp_switch_link_read()`, remove the trailing check:

```c
		if (link->ack_pending)
			l2tp_switch_link_ack_forwarded(link);
```

so the loop body ends right after the `l2tp_switch_link_write_out()` call.

- [ ] **Step 10: Remove watcher attachment in `l2tp_switch_finish_downstream()`**

Change:

```c
	pthread_mutex_lock(&l2tp_switch_pap_ptr_lock);
	downstream->switch_pap_watcher = l2tp_switch_pap_watcher_create(downstream);
	pthread_mutex_unlock(&l2tp_switch_pap_ptr_lock);
	if (!downstream->switch_pap_watcher) {
		log_session(log_error, downstream,
			    "l2tp-switch: creating live-PAP watcher failed\n");
		goto err;
	}

	if (l2tp_switch_link_create(downstream, upstream,
				    upstream->switch_target, 0) < 0) {
```

to:

```c
	if (l2tp_switch_link_create(downstream, upstream,
				    upstream->switch_target, 0) < 0) {
```

Also update the function's own doc comment just above it — remove this sentence (leave the rest of the comment intact):

```c
 * The watcher goes first: the downstream link's read handler is what feeds
 * it the downstream leg's Configure-Ack, so it must exist before that
 * handler can run.
 *
```

- [ ] **Step 11: Build**

Run the container build (Global Constraints). Confirm `rc=0` after both `make` and `make install`.

Expected: builds cleanly. If there are undefined-reference or unused-variable errors, they mean Step 5/6 left something behind (or removed something Step 7/8 still needs) — fix by re-reading the surrounding code, not by adding back anything from the deleted subsystem.

Run: `grep -n "l2tp_switch_pap_\|switch_pap_watcher\|ack_pending\b" accel-pppd/ctrl/l2tp/l2tp.c`

Expected: no output at all — every symbol from the removed subsystem is gone.

- [ ] **Step 12: Run Task 2's test and confirm it now passes**

Run: `docker exec -w /src/tests accel python3 -m pytest -q -m l2tp_switch accel-pppd/l2tp_switch/test_switch_downstream_no_pap_help.py -v`

Expected: PASS.

- [ ] **Step 13: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c
git commit -m "$(cat <<'EOF'
fix(l2tp): remove the live-PAP-injection watcher

Two confirmed production failure modes: a watcher-creation race that
silently blinds it against fast targets (the upstream->downstream
splice link goes live a full triton_context_call() hop before the
watcher does, so a fast target's Configure-Ack round-trips through
the already-armed link unobserved), and redundant injection against
calls that already authenticated live through the transparent pipe on
their own (the watcher has no way to know that happened, so it
injects a stray duplicate and its own 3s timeout kills an otherwise
fully-working call). The second broke at least one previously-working
partner setup.

Replaced with a stateless, single-context peek that only logs what
the target's own LCP asks for, so a hung call still shows up in the
log immediately -- no timers, no locks, no injected traffic, no
effect on the call. accel-ppp no longer authenticates a switched call
on the downstream target's behalf; see docs/l2tp_switching.md.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Remove the obsolete PAP-injection tests

**Files:**
- Delete: `tests/accel-pppd/l2tp_switch/test_switch_downstream_pap.py`
- Delete: `tests/accel-pppd/l2tp_switch/test_switch_downstream_pap_race.py`
- Modify (conditionally): `accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c`, `accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.h`, `tests/accel-pppd/l2tp_switch/helpers.py` — only if Step 2 finds injection-only harness code with no remaining callers.

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Delete the two obsolete test files**

```bash
git rm tests/accel-pppd/l2tp_switch/test_switch_downstream_pap.py tests/accel-pppd/l2tp_switch/test_switch_downstream_pap_race.py
```

- [ ] **Step 2: Check whether any harness code is now dead**

Run: `grep -rn "expect_pap_name\|expect_pap_password\|expect-pap-name\|expect-pap-password\|wait_for_pap_request" accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.h tests/accel-pppd/l2tp_switch/`

These CLI flags/fields/functions in the peer test harness exist only to intercept and validate an *injected* PAP request — Task 2's new test does not use `--expect-pap-name`/`--expect-pap-password` (it uses plain `--lcp-auth pap` with no expectation). If this grep now shows no test file referencing `--expect-pap-name`/`--expect-pap-password` (only the harness's own C source defining them), remove from `l2tp_switch_peer_test.c`/`.h`:
  - the `expect_pap_name`/`expect_pap_password` fields and their `getopt_long` entries (`'E'`/`'P'`, `"expect-pap-name"`/`"expect-pap-password"`)
  - the validation checks referencing them (`--expect-pap-name and --expect-pap-password must be given together`, `--expect-pap-name requires --listen and --minimal-lcp`, `--expect-pap-name and --cdn-after-lcp-ms are...`)
  - `wait_for_pap_request()` and its call site
  - the corresponding lines in the usage string

Do **not** remove `--lcp-auth`/`lcp_auth`/`LCP_AUTH_PAP`/`LCP_AUTH_CHAP`/`LCP_AUTH_NONE`, `--minimal-lcp`, or anything else the harness uses for plain LCP negotiation — Task 2's test and other switch tests (e.g. `test_switch_splice.py`, `test_switch_avp_forward.py`) still need those. If the grep shows any *other* test file still referencing the expect-pap flags, stop and re-check — that means something beyond the two deleted files still depends on them, and this step should not touch the harness.

- [ ] **Step 3: Build the test harness binary if it was changed**

If Step 2 made changes: run the container build (Global Constraints) and confirm `rc=0` — this rebuilds and reinstalls `l2tp_switch_peer_test`/`peer_bin` along with the rest.

- [ ] **Step 4: Run the full switch test suite**

Run: `docker exec -w /src/tests accel python3 -m pytest -q -m l2tp_switch accel-pppd/l2tp_switch -v`

Expected: everything passes; the two deleted files no longer appear; `test_switch_downstream_no_pap_help.py` passes. (This is the serial ~6 min run per project memory; `tests/run_l2tp_switch_sharded.sh accel-img 5` is available for a faster sharded run against a committed image, per its own header comment, but requires `docker commit`-ing this container first — not necessary for a single verification pass.)

- [ ] **Step 5: Commit**

```bash
git add -A tests/accel-pppd/l2tp_switch/ accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.h
git commit -m "$(cat <<'EOF'
test(l2tp): remove PAP-injection-specific switch tests

Both tested behavior that no longer exists after the previous commit.
Trims the peer test harness's injected-PAP interception code
(--expect-pap-name/--expect-pap-password, wait_for_pap_request()) if
it has no remaining callers -- the harness's plain --lcp-auth/
--minimal-lcp support stays, still used by other switch tests.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Update docs and CHANGELOG

**Files:**
- Modify: `docs/l2tp_switching.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Remove the `pap-timeout=` bullet from the Configuration section**

In `docs/l2tp_switching.md`, remove this bullet (it sits between the `reconnect-interval=` bullet and the `match=` bullet):

```
- `pap-timeout=<seconds>` — how long the live-PAP watcher (see
  Authentication below) waits for the downstream target's Ack/Nak to the
  request it injected before disconnecting the call; default `3`, whole
  seconds 1–3600. Raise it for a target whose authentication backend is slow
  to answer, but keep it below the roughly 5 seconds a downstream LNS may
  wait for PAP before giving up itself.
```

- [ ] **Step 2: Rewrite the Authentication section**

Replace the entire section (from `## Authentication` through the paragraph ending `...an LCP Terminate-Request.`, i.e. everything up to but not including the next `## Operational constraints` heading) with:

```markdown
## Authentication

A switched call's two legs never run a local PPP session — both real
peers (the actual calling client, relayed via the upstream LAC, and the
downstream target LNS) negotiate LCP, authentication, and NCP with each
other directly through the existing `splice(2)` byte pipe, with accel-ppp
acting as a transparent pipe. **accel-ppp does not perform, complete, or
relay authentication on the target's behalf** — it is a byte pipe, not a
PPP peer, for this phase of the call.

**accel-ppp plays both L2TP roles, one per leg — never one role for the
whole call.** Upstream, it is the **LNS**: the real upstream LAC (whatever
originally accepted the call — a DSLAM/BNG, another L2TP switch, etc.)
tunnels the call to accel-ppp, which receives it. Downstream, it is the
**LAC**: accel-ppp originates the outbound tunnel to the target, and per
RFC 2661 it is specifically the LAC's role to send `Proxy-Authen-*` AVPs
to the LNS when it already holds the client's credentials — which is
exactly what accel-ppp does in the proxied path below. Bear this in mind
when talking to a downstream partner about their configuration: their LNS
platform's own documentation will use "LAC" to describe what accel-ppp is
doing on this leg.

**Requirement: exactly one of the following two conditions must hold, or
the call will not authenticate.**

1. **Live path.** The upstream LAC relays the real client's actual PAP or
   CHAP frames through the tunnel instead of proxying them (no
   `Proxy-Authen-*` AVPs on the ICCN, or AVPs present but redundant with a
   live exchange also on the wire). In this case nothing extra is needed:
   the downstream target LNS just authenticates the call exactly as if the
   client were connected to it directly, using its own normal PAP/CHAP
   configuration.
2. **Proxied path.** The upstream LAC instead sends `Proxy-Authen-Type`
   (AVP 29), `Proxy-Authen-Name` (AVP 30), and `Proxy-Authen-Response` (AVP
   33) — optionally `Proxy-Authen-Challenge` (AVP 31) and
   `Proxy-Authen-ID` (AVP 32) for CHAP — on the call's ICCN (RFC 2661
   §4.4.2/§4.4.4), and never puts a live PAP/CHAP frame on the wire at all.
   accel-ppp captures these AVPs off the *upstream* ICCN it received (as
   the LNS for that leg) and re-injects them verbatim into the ICCN it
   sends *downstream* to the target (as the LAC for that leg — see
   `Configuration` above) — that is the entire extent of what this switch
   does with them. **The downstream target's own LNS software must consume
   these AVPs itself** — treating the call as already authenticated from
   `Proxy-Authen-Name`/`Proxy-Authen-Response` — for the proxied path to
   work at all. accel-ppp has no way to do this on the target's behalf.

If neither condition holds — the upstream proxies via AVPs *and* the
downstream target doesn't consume them, expecting a live exchange instead
— the call will hang in the Authentication phase until the target's own
native auth timeout tears it down. This is expected behavior, not a bug.
**Before routing calls to a new downstream partner, confirm with them
which of the two conditions above their LNS satisfies** — asking "does
your LNS platform support RFC 2661 proxy-LCP / proxy-authentication AVPs,
or do you need to receive a live PAP/CHAP exchange" is enough to know
in advance whether a given target will work.

**Diagnosing a hung call.** The switch logs (at info level, once per call
for the target's first Configure-Request) what the target's own LCP asks
for: `downstream LCP Configure-Request asks for PAP` / `asks for CHAP
(algorithm 0x..)` / `asks for authentication protocol 0x....` / `has no
authentication-protocol option`, and, as warnings, `downstream rejected
PPP protocol 0x....` (LCP Protocol-Reject) and `downstream sent an LCP
Terminate-Request`. If a target's calls consistently show "asks for PAP"
(or CHAP) followed some seconds later by a Terminate-Request, that
target's LNS needs to be configured — or its software needs to gain
support — for consuming `Proxy-Authen-*` AVPs directly, rather than
expecting a live exchange this switch does not provide.

> An earlier version of this feature tried to paper over the gap by
> watching the spliced traffic and injecting a synthesized PAP request on
> the target's behalf. In production this had two independent failure
> modes — a race that silently blinded it against fast targets, and a
> redundant injection against calls that had already authenticated live on
> their own, which broke at least one previously-working partner setup —
> so it was removed. See
> `docs/superpowers/specs/2026-09-22-l2tp-switch-drop-pap-injection-design.md`
> for the full incident writeup.
```

- [ ] **Step 3: Add a CHANGELOG entry**

Read `CHANGELOG.md`'s existing format/most recent entries first (`head -30 CHANGELOG.md`) and add a new entry in the same style, near the top, noting: the live-PAP-injection mechanism was removed due to two confirmed production failure modes (a watcher-creation race, and redundant injection against already-authenticated calls); downstream LNS targets must now consume `Proxy-Authen-*` AVPs themselves or receive live authentication from the upstream side.

- [ ] **Step 4: Commit**

```bash
git add docs/l2tp_switching.md CHANGELOG.md
git commit -m "$(cat <<'EOF'
docs(l2tp): document the removal of live-PAP injection

Rewrites the Authentication section to state the actual requirement:
the downstream LNS must consume Proxy-Authen-* AVPs itself, or the
upstream must relay live authentication -- accel-ppp does not do
either on the target's behalf. Points to the design spec for the
incident history.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Full verification

**Files:** none (verification only).

- [ ] **Step 1: Run the complete l2tp_switch test suite**

Run: `docker exec -w /src/tests accel python3 -m pytest -q -m l2tp_switch accel-pppd/l2tp_switch -v`

Expected: all pass, including `test_switch_downstream_no_pap_help.py`; no reference to the deleted test files.

- [ ] **Step 2: Run the general/pppoe suites that reference switch-adjacent behavior**

Run: `docker exec -w /src/tests accel python3 -m pytest -q accel-pppd/general/test_basic.py accel-pppd/pppoe/test_pppoe_session_wo_auth.py -v` (these showed up in the earlier grep for "pap"-adjacent files; confirm they're unrelated to the removed subsystem and still pass unchanged).

- [ ] **Step 3: Full repo build, clean**

Run: `docker exec accel rm -rf /build` then the container build from Global Constraints, fresh, to confirm nothing else references removed symbols in a clean build (not an incremental one that might mask a stale object file).

- [ ] **Step 4: Grep for any remaining stray references**

Run: `grep -rn "l2tp_switch_pap_\|switch_pap_watcher\|pap-timeout\|pap_timeout" accel-pppd/ docs/ tests/ CHANGELOG.md`

Expected: no output, except this plan file and the design spec themselves (which are expected to mention the removed names historically) — if run from the repo root, exclude `docs/superpowers/` from this check: `grep -rn "l2tp_switch_pap_\|switch_pap_watcher\|pap-timeout\|pap_timeout" accel-pppd/ tests/ CHANGELOG.md docs/l2tp_switching.md`.

- [ ] **Step 5: Report**

No commit for this task — it's verification only. Summarize the final state (all tests passing, build clean, no stray references) back to the user.
