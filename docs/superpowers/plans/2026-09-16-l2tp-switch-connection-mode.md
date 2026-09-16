# L2TP Switch Connection Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each `[l2tp-switch]` `target=` a per-target connection **mode** — `persistent` (today's only behavior: eager connect at startup, reconnect forever) or `on-demand` (new: connect only when a call needs the target, tear the tunnel back down after a short idle linger) — with `on-demand` becoming the default once implemented. This exists because a real downstream peer (Juniper JunOS, default `idle-timeout` 60s) tears down any of `persistent` mode's proactively-opened, session-less tunnels the moment they go idle, which every one of them always does until a real call happens to route through it — causing a permanent, noisy ~60s-up/torn-down flap cycle.

**Companion fix, out of scope here:** a narrower change shrinking the delay between receiving a peer StopCCN and `persistent` mode's own reconnect (`l2tp_tunnel_finwait()`/`l2tp_recv_StopCCN` in `l2tp.c`) is landing separately. It makes `persistent` mode's flapping *cheap* when it happens; it does not stop the flapping, and does nothing for peers with a stricter idle policy than JunOS's default. Do not touch those two functions as part of this plan.

**Architecture:** No new files. `l2tp_switch_conf.c`/`.h` (self-contained config table, already existing from the original L2TP switching plan) grows one enum and one struct field for the mode itself. All the new *runtime* lifecycle logic — connect-on-demand, call queueing while connecting, the bounded connect-timeout, and the idle-linger teardown — lives in `l2tp.c` next to the existing `l2tp_switch_target_connect()`/`l2tp_switch_place_downstream_call()`/`l2tp_switch_link_create()`/`l2tp_switch_link_free()` it extends, following this file's own single-large-file-per-protocol convention (see the original L2TP switching plan's own Global Constraints for why, preserved in git history at `git show a8abf900^:docs/superpowers/plans/2026-09-07-l2tp-switching.md`, deleted from the tree in commit `a8abf900` as scaffolding superseded by `docs/l2tp_switching.md` — still readable via `git show` for background/convention reference, not re-added here).

**Tech Stack:** C (accel-pppd core), triton (this project's single-loop-per-context, multi-thread event model), pthread mutexes for cross-context-shared non-atomic state (mirroring this file's own existing `l2tp_lock`/`conn->ctx_lock`), pytest + existing `tests/common/`/`tests/accel-pppd/l2tp_switch/` fixtures for integration tests.

**Spec:** `docs/l2tp_switching.md` — this plan modifies the behavior that doc describes; read it first (in particular the "brings up one persistent outbound tunnel per target at startup" line under Configuration, and the whole Observability section, both of which this plan changes). `accel-pppd/ctrl/l2tp/l2tp_switch_conf.c`/`.h` and the switch-related code in `accel-pppd/ctrl/l2tp/l2tp.c` are the code this plan extends, not replaces.

## Global Constraints

- **Backward-compatible config parsing.** Every existing 4-field `target=<name>,<peer-addr>,<peer-port>,<secret>` line must keep parsing exactly as today, with no `mode=` given defaulting sensibly (see the default-flip note below for exactly when that default becomes `on-demand`).
- **No change to the switched-call data plane.** Splicing, AVP capture/forwarding, sequencing mirroring, and teardown cascading (Tasks 6-8 of the original plan) are entirely unaffected — this plan only changes *when* a target's own outbound control tunnel exists, never how a call's PPP frames are relayed once it does.
- **The default flips late, not immediately.** Tasks 1-5 keep the *interim* default `mode=persistent` (i.e. unchanged from today) so the working tree stays fully backward-compatible and testable after every intermediate commit, even though on-demand logic exists and is independently testable via an explicit `mode=on-demand`. Task 6 flips the default to `on-demand` only once on-demand has been fully implemented, exercised, and every existing test's implicit assumption about eager connection has been made explicit (Task 5). This mirrors this codebase's own established precedent of shipping an interim shape in one task and finalizing it in a later one (the original plan's Task 3 registered a 2-level `l2tp switch` CLI command, finalized to the 3-level `l2tp switch show` in Task 9).
- **Downstream-unreachable/rejected/timed-out always CDNs the upstream call** (matches the original plan's own constraint) — on-demand mode does not change this invariant, it only changes *how long* accel-ppp is willing to wait before giving up: today's `persistent` mode fails a call instantly if `target->tunnel` isn't already up (an on-demand target's normal resting state); on-demand mode instead queues the call and gives the connect a bounded window (10s) to succeed before CDNing it.
- **Concurrency.** `l2tp_switch_place_downstream_call()` always runs on the *upstream* session's own tunnel context — essentially never the target's own tunnel context, and often no tunnel/context exists for the target at all yet. New per-target on-demand state (`pending_calls`, `pending_count`, `connecting`) is therefore protected by a dedicated `pthread_mutex_t lock` on `struct l2tp_switch_target_t`, mirroring this file's own existing `l2tp_lock` (global tid-table lock, `l2tp.c:264`) and `conn->ctx_lock` (per-tunnel cross-context-call guard, `l2tp.c:221`) precedents — plain `__atomic_*` ops (already used for `active`/`rx_bytes`/`tx_bytes`) are not sufficient for linked-list mutation. Kicking off a connect attempt itself needs no context-crossing: `l2tp_tunnel_alloc()`/`l2tp_tunnel_start()`/`triton_timer_add(NULL, ...)` are already safe to call from an arbitrary thread/context — confirmed by their existing use both from `l2tp_switch_target_reconnect_timer()` (a default-context timer callback) and from the CLI-thread-invoked `l2tp_create_tunnel_exec()`. Touching an *existing* tunnel's own state from elsewhere (aborting a stalled connect, closing an idle tunnel) still needs `triton_context_call(&conn->ctx, ...)` plus `tunnel_hold()`/`tunnel_put()`, exactly like this file's existing `l2tp_switch_finish_upstream()`/`l2tp_switch_teardown_peer()` cross-context patterns.
- Use this file's existing conventions throughout: `_malloc`/`_free`/`_strdup`, `log_session`/`log_tunnel`/`log_error`, `session_hold`/`session_put`/`tunnel_hold`/`tunnel_put`, `container_of`, `triton_context_call` to cross contexts, `list_for_each_entry`/`list_add_tail`/`list_first_entry` (no `list_for_each_entry_safe` in this project's `list.h` — use the existing while/`list_first_entry` idiom for "drain a whole list", as `l2tp_switch_conf.c`'s own `switch_conf_clear()` already does).

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `accel-pppd/ctrl/l2tp/l2tp_switch_conf.h` | Modify | `enum l2tp_switch_conn_mode`; `mode` field on `struct l2tp_switch_target_t`. |
| `accel-pppd/ctrl/l2tp/l2tp_switch_conf.c` | Modify | Parse the optional 5th `target=` field; validate/reject unknown mode values. |
| `accel-pppd/ctrl/l2tp/l2tp.c` | Modify | Everything else: connect-on-demand, call queueing, connect-timeout, idle-linger teardown, `l2tp switch show` display states, native-metrics semantics. |
| `docs/l2tp_switching.md` | Modify | Document both modes, the new default, the idle-linger window, and the `[idle]`/`[connecting]` display states. |
| `accel-pppd/accel-ppp.conf.5` | Modify | `.BI "target="` synopsis gains the optional mode field. |
| `README.md`, `CHANGELOG.md`, `accel-pppd/accel-ppp.conf` (sample) | Modify | Brief mentions kept in sync (matching the original plan's own Task 10 precedent of updating all four together). |
| `tests/accel-pppd/l2tp_switch/*.py` | Modify | Pin `mode=persistent` on every test whose own subject is something else but which relies on eager-connect-at-startup as a readiness gate (Task 5); rewrite `test_switch_tunnel.py` to cover both modes explicitly; add new tests for queueing/timeout/idle-teardown/display states (Tasks 2-4). |

No `CMakeLists.txt` change — no new source files.

---

### Task 1: `mode=` config field, interim default `persistent`

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp_switch_conf.h`
- Modify: `accel-pppd/ctrl/l2tp/l2tp_switch_conf.c`
- Test: `tests/accel-pppd/l2tp_switch/test_switch_config.py`

**Interfaces:**
- Produces: `enum l2tp_switch_conn_mode { L2TP_SWITCH_MODE_PERSISTENT, L2TP_SWITCH_MODE_ON_DEMAND }`; `target->mode`, readable by `l2tp.c` (no new function needed — `struct l2tp_switch_target_t` is already fully visible to `l2tp.c` via the existing `#include "l2tp_switch_conf.h"`).
- Consumes: nothing new.

This task is purely config-parsing — no runtime connection behavior changes yet (every existing target still connects exactly as `persistent` mode does today, since that stays the interim default).

- [ ] **Step 1: Write the failing test**

Add to `tests/accel-pppd/l2tp_switch/test_switch_config.py` (mirroring its existing config-load-only style — these targets use unreachable TEST-NET-3 addresses purely to validate parsing, never waiting on `[up]`):

```python
def test_switch_target_mode_persistent_explicit(pytestconfig, accel_cmd, accel_pppd):
    # explicit "persistent" parses and target still shows in `l2tp switch show`
    ...  # target=acme,203.0.113.50,1701,targetsecret,persistent

def test_switch_target_mode_on_demand_explicit(pytestconfig, accel_cmd, accel_pppd):
    ...  # target=acme,203.0.113.50,1701,targetsecret,on-demand

def test_switch_target_mode_omitted_defaults_persistent(pytestconfig, accel_cmd, accel_pppd):
    # interim default -- Task 6 changes this same assertion to on-demand
    ...  # target=acme,203.0.113.50,1701,targetsecret  (4 fields, unchanged)

def test_switch_target_mode_unknown_rejected(pytestconfig, accel_pppd):
    # target=acme,203.0.113.50,1701,targetsecret,bogus -- daemon must fail
    # to start (config-load error), same as an unknown match= mode today
    ...
```

- [ ] **Step 2: Run, verify it fails**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_config.py`
Expected: FAIL on the new tests — `mode` doesn't exist yet, a 5th field is silently ignored by `strtok_r`'s existing 4-token parse (confirm this "just ignored" behavior directly, since it's the actual pre-Task-1 failure mode, not a parse error).

- [ ] **Step 3: Implement**

`l2tp_switch_conf.h` — add near the top, before `struct l2tp_switch_target_t`:

```c
enum l2tp_switch_conn_mode {
	L2TP_SWITCH_MODE_PERSISTENT,
	L2TP_SWITCH_MODE_ON_DEMAND,
};
```

Add to `struct l2tp_switch_target_t` (right after `secret_len`, before the `l2tp.c`-owned fields):

```c
	enum l2tp_switch_conn_mode mode;
```

`l2tp_switch_conf.c`'s `parse_target()` (~line 250) — add a 5th, optional token:

```c
	name = strtok_r(copy, ",", &save);
	addr = strtok_r(NULL, ",", &save);
	port = strtok_r(NULL, ",", &save);
	secret = strtok_r(NULL, ",", &save);
	mode_str = strtok_r(NULL, ",", &save); /* optional; NULL if omitted */
```

and after the existing `t->peer_addr` validation, before `list_add_tail`:

```c
	/* Interim default: persistent, matching today's only behavior.
	 * Changed to L2TP_SWITCH_MODE_ON_DEMAND once on-demand mode is fully
	 * implemented and every existing test's implicit "tunnel is already
	 * up" assumption has been made explicit -- see this plan's Task 6. */
	if (!mode_str || !strcmp(mode_str, "persistent")) {
		t->mode = L2TP_SWITCH_MODE_PERSISTENT;
	} else if (!strcmp(mode_str, "on-demand")) {
		t->mode = L2TP_SWITCH_MODE_ON_DEMAND;
	} else {
		log_error("l2tp-switch: unknown mode \"%s\" in target=\"%s\","
			  " expected \"persistent\" or \"on-demand\"\n",
			  mode_str, val);
		free_target(t);
		goto err;
	}
```

- [ ] **Step 4: Run, verify it passes**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_config.py`
Expected: PASS — all four new cases, plus every pre-existing config test in this file (regression check: 4-field lines still parse).

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp_switch_conf.h accel-pppd/ctrl/l2tp/l2tp_switch_conf.c tests/accel-pppd/l2tp_switch/test_switch_config.py
git commit -m "feat(l2tp): parse optional target= connection mode (persistent/on-demand)"
```

---

### Task 2: On-demand connect-on-demand, call queueing, bounded connect-timeout

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c`
- Test: `tests/accel-pppd/l2tp_switch/test_switch_on_demand_connect.py` (new)

**Interfaces:**
- Consumes: `target->mode` (Task 1).
- Produces: an on-demand target's tunnel connects only when a call needs it; a call arriving while the connect is in flight queues instead of failing immediately; a call is CDN'd only if the connect doesn't complete within 10s.

**Struct additions** (`l2tp.c`):

Add to `struct l2tp_sess_t`, next to the other `switch_*` fields (~line 194):

```c
	struct list_head switch_pending_entry; /* linked into
		target->pending_calls while an on-demand connect for this
		call's target is in flight; unused otherwise */
```

(`INIT_LIST_HEAD(&sess->switch_pending_entry)` wherever `l2tp_sess_t` is allocated/zeroed — check the existing session-alloc path, e.g. `l2tp_tunnel_alloc_session()`, for where other list fields on a fresh session are initialized and add it there.)

Add to `struct l2tp_switch_target_t` (`l2tp_switch_conf.h`, after `reconnect_timer`):

```c
	/* on-demand only (owned by l2tp.c): guards pending_calls/pending_count/
	 * connecting below. These are mutated from whichever upstream
	 * session's own tunnel context happens to place a call against this
	 * target -- essentially never this target's own tunnel context, and
	 * often no context at all while the target is cold -- so a plain
	 * list_head is not safe here without a lock, mirroring l2tp_lock/
	 * conn->ctx_lock's existing role elsewhere in l2tp.c for exactly this
	 * kind of cross-context-shared, non-atomic-friendly state. */
	pthread_mutex_t lock;
	struct list_head pending_calls; /* l2tp_sess_t.switch_pending_entry */
	unsigned int pending_count;
	int connecting;
	struct triton_timer_t connect_timeout_timer;
```

(`pthread_mutex_init(&t->lock, NULL)` and `INIT_LIST_HEAD(&t->pending_calls)` added to `parse_target()` right after the existing `memset(t, 0, sizeof(*t))`; `pthread_mutex_destroy(&t->lock)` added to `free_target()`.)

Add near the top with the other constants:

```c
#define L2TP_SWITCH_ON_DEMAND_CONNECT_TIMEOUT_MS 10000
#define L2TP_SWITCH_PENDING_MAX 64
```

- [ ] **Step 1: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_on_demand_connect.py`, reusing `helpers.start_instance()`/the MK-simulator harness (`l2tp_switch_peer_test.c` via `tests/common/l2tp_peer_process.py`) the same way `test_switch_avp_forward.py`/`test_switch_splice.py` already do:

```python
@pytest.mark.l2tp_switch
def test_on_demand_target_stays_down_until_a_call_needs_it(pytestconfig, accel_cmd, accel_pppd):
    # start downstream + switch instance with target=...,on-demand
    # assert `l2tp switch show` shows the target NOT up (no eager connect)
    # place a call via the MK-simulator harness
    # assert the target reaches up within a few seconds of the call arriving
    ...

@pytest.mark.l2tp_switch
def test_on_demand_call_queues_while_tunnel_is_connecting(pytestconfig, accel_cmd, accel_pppd):
    # a slow-to-accept downstream (harness --listen with an artificial
    # delay before completing SCCRP, if the harness supports one -- add a
    # --sccrp-delay-ms flag to l2tp_switch_peer_test.c if it doesn't yet)
    # place a call; assert it still completes successfully once the
    # delayed SCCRP/SCCCN finishes, rather than being CDN'd immediately
    ...

@pytest.mark.l2tp_switch
def test_on_demand_call_cdns_after_connect_timeout(pytestconfig, accel_cmd, accel_pppd):
    # target points at a closed port (nothing listening) -- connect can
    # never succeed; assert the placed call is CDN'd (upstream tunnel/
    # session torn down) within ~10-11s, not instantly and not never
    ...
```

- [ ] **Step 2: Run, verify it fails**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_on_demand_connect.py`
Expected: FAIL — today's `l2tp_switch_place_downstream_call()` returns `-1` immediately whenever `target->tunnel` is `NULL` (true for every on-demand target at rest), so every placed call is CDN'd instantly regardless of the target's actual reachability.

- [ ] **Step 3: Implement**

Rewrite `l2tp_switch_place_downstream_call()` (`l2tp.c` ~4628):

```c
static void l2tp_switch_on_demand_timeout(struct triton_timer_t *t);

static int l2tp_switch_place_downstream_call(struct l2tp_sess_t *upstream)
{
	struct l2tp_switch_target_t *target = upstream->switch_target;
	struct l2tp_conn_t *conn;
	int need_connect = 0;

	pthread_mutex_lock(&target->lock);
	conn = target->tunnel;
	if (conn && conn->state == STATE_ESTB) {
		/* Fast path: tunnel already usable (persistent mode always
		 * takes this path when it's going to succeed at all; on-demand
		 * takes it once its own idle/lingering tunnel is reused).
		 * Cancel any linger-teardown armed for it (Task 3) before this
		 * call starts using it again. */
		if (target->idle_timer.tpd)
			triton_timer_del(&target->idle_timer);
		pthread_mutex_unlock(&target->lock);

		session_hold(upstream);
		if (triton_context_call(&conn->ctx, l2tp_switch_place_call, upstream) < 0) {
			session_put(upstream);
			return -1;
		}
		return 0;
	}

	if (target->mode == L2TP_SWITCH_MODE_PERSISTENT) {
		/* Unchanged from before this feature: a persistent target's
		 * tunnel is expected to already be up. */
		pthread_mutex_unlock(&target->lock);
		return -1;
	}

	/* on-demand, no usable tunnel right now: queue and make sure a
	 * connect attempt is in flight. */
	if (target->pending_count >= L2TP_SWITCH_PENDING_MAX) {
		pthread_mutex_unlock(&target->lock);
		log_session(log_error, upstream, "l2tp-switch: target \"%s\""
			    " pending-call queue full, disconnecting"
			    " upstream call\n", target->name);
		return -1;
	}

	session_hold(upstream);
	list_add_tail(&upstream->switch_pending_entry, &target->pending_calls);
	target->pending_count++;

	if (!target->connecting) {
		target->connecting = 1;
		need_connect = 1;
		target->connect_timeout_timer.expire = l2tp_switch_on_demand_timeout;
		target->connect_timeout_timer.period = L2TP_SWITCH_ON_DEMAND_CONNECT_TIMEOUT_MS;
		if (triton_timer_add(NULL, &target->connect_timeout_timer, 0) < 0)
			log_error("l2tp-switch: target \"%s\": failed to arm"
				  " on-demand connect timeout\n", target->name);
	}
	pthread_mutex_unlock(&target->lock);

	if (need_connect)
		l2tp_switch_target_connect(target); /* safe from any context --
			same precedent as the existing CLI "l2tp create tunnel"
			path, which already calls this indirectly from a
			CLI-thread context */

	return 0;
}
```

Add a shared retry-gate helper, replacing the two places that currently unconditionally re-arm `reconnect_timer`:

```c
static int l2tp_switch_target_should_retry(struct l2tp_switch_target_t *target)
{
	int pending;

	if (target->mode == L2TP_SWITCH_MODE_PERSISTENT)
		return 1;

	pthread_mutex_lock(&target->lock);
	pending = target->pending_count > 0;
	pthread_mutex_unlock(&target->lock);
	return pending;
}
```

In `l2tp_switch_target_connect()`'s `retry:` label (~line 2006):

```c
retry:
	target->tunnel = NULL;
	if (l2tp_switch_target_should_retry(target)) {
		if (triton_timer_add(NULL, &target->reconnect_timer, 0) < 0)
			log_error("l2tp-switch: target \"%s\": failed to schedule"
				  " reconnect\n", target->name);
	}
```

(`l2tp_switch_targets_connect()`, the startup sweep at ~line 2022, must also skip on-demand targets entirely: `if (target->mode == L2TP_SWITCH_MODE_PERSISTENT) l2tp_switch_target_connect(target);` — on-demand targets stay cold until a call needs them.)

In `l2tp_tunnel_free()`'s existing `switch_target` hook (~line 1374), apply the same gate:

```c
	if (conn->switch_target) {
		conn->switch_target->tunnel = NULL;
		if (l2tp_switch_target_should_retry(conn->switch_target)) {
			if (triton_timer_add(NULL, &conn->switch_target->reconnect_timer, 0) < 0)
				log_error("l2tp-switch: target \"%s\": failed to"
					  " schedule reconnect\n",
					  conn->switch_target->name);
		}
	}
```

Hook the successful-connect drain into `l2tp_tunnel_connect()` (~line 2457), right after `conn->state = STATE_ESTB;` — this already runs inside `conn->ctx` (reached from `l2tp_recv_SCCRP`/`l2tp_recv_SCCCN`, both message handlers on that tunnel's own context), so queued calls can be placed with a *direct* function call, no `triton_context_call` needed:

```c
	l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_active);
	conn->state = STATE_ESTB;

	if (conn->switch_target) {
		struct l2tp_switch_target_t *target = conn->switch_target;
		LIST_HEAD(drained);
		struct l2tp_sess_t *sess;

		pthread_mutex_lock(&target->lock);
		if (target->connect_timeout_timer.tpd)
			triton_timer_del(&target->connect_timeout_timer);
		target->connecting = 0;
		list_splice_init(&target->pending_calls, &drained);
		target->pending_count = 0;
		pthread_mutex_unlock(&target->lock);

		while (!list_empty(&drained)) {
			sess = list_first_entry(&drained, typeof(*sess),
						switch_pending_entry);
			list_del(&sess->switch_pending_entry);
			/* Already on conn->ctx -- l2tp_switch_place_call()'s own
			 * STATE_CLOSE guard (added in Task 6 of the original
			 * plan) already handles a queued upstream session
			 * having died while it waited; no extra guard needed
			 * here. Any ICRQs these enqueue get flushed by the
			 * normal receive-loop flush that follows, since (unlike
			 * the persistent-mode fast path reached via a scheduled
			 * triton_context_call from a *different* context) this
			 * runs inline within the SCCRP/SCCCN receive-processing
			 * call stack -- no explicit
			 * l2tp_tunnel_push_sendqueue() needed here. */
			l2tp_switch_place_call(sess);
		}
	}

	return 0;
```

Add the connect-timeout callback, near `l2tp_switch_target_reconnect_timer()`:

```c
static void l2tp_switch_on_demand_timeout(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), connect_timeout_timer);
	LIST_HEAD(drained);
	struct l2tp_sess_t *sess;
	struct l2tp_conn_t *stalled = NULL;

	triton_timer_del(t);

	pthread_mutex_lock(&target->lock);
	target->connecting = 0;
	list_splice_init(&target->pending_calls, &drained);
	target->pending_count = 0;
	if (target->tunnel && target->tunnel->state != STATE_ESTB)
		stalled = target->tunnel; /* still mid-negotiation past budget */
	pthread_mutex_unlock(&target->lock);

	if (list_empty(&drained) && !stalled)
		return; /* connect actually succeeded and drained the queue
			 * itself (see l2tp_tunnel_connect() above) before this
			 * timer got a chance to fire; nothing left to do */

	log_error("l2tp-switch: target \"%s\": on-demand connect timed out,"
		  " disconnecting queued call(s)\n", target->name);

	while (!list_empty(&drained)) {
		sess = list_first_entry(&drained, typeof(*sess), switch_pending_entry);
		list_del(&sess->switch_pending_entry);
		/* Cross into this call's own upstream tunnel context -- mirrors
		 * l2tp_switch_place_call()'s existing err_no_pairing path
		 * exactly, reusing the same hold taken when this session was
		 * queued. */
		if (triton_context_call(&sess->paren_conn->ctx,
					l2tp_switch_disconnect_upstream, sess) < 0)
			session_put(sess);
	}

	if (stalled) {
		tunnel_hold(stalled);
		triton_context_call(&stalled->ctx, l2tp_switch_abort_stalled_tunnel, stalled);
	}
}

static void l2tp_switch_abort_stalled_tunnel(void *data)
{
	struct l2tp_conn_t *conn = data;

	if (conn->state != STATE_CLOSE && conn->state != STATE_ESTB)
		l2tp_tunnel_disconnect(conn, 2, 0); /* result 2: general error,
			matching this file's existing convention for aborting a
			tunnel that failed to establish (see the res/err codes
			already used throughout l2tp_recv_SCCRQ/SCCRP/SCCCN's
			own error paths) */
	tunnel_put(conn);
}
```

- [ ] **Step 4: Run, verify it passes**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_on_demand_connect.py`
Expected: PASS. Also re-run the full `l2tp_switch` suite (`pytest -m l2tp_switch`) to confirm no regression in the still-persistent-by-default existing tests.

**Manually verify beyond the automated tests**, matching this repo's established practice: build with ASan/UBSan, run the connect-timeout test directly against a closed port and confirm via `journalctl`/log output that (a) the queued call is genuinely CDN'd around 10s later, not instantly and not indefinitely stuck, and (b) `l2tp switch show` shows the target back at rest (no lingering half-open tunnel) afterward.

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c tests/accel-pppd/l2tp_switch/test_switch_on_demand_connect.py
git commit -m "feat(l2tp): connect on-demand targets lazily, queue calls during connect, bound the wait"
```

---

### Task 3: On-demand idle-linger teardown

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c`
- Test: `tests/accel-pppd/l2tp_switch/test_switch_on_demand_idle_teardown.py` (new)

**Interfaces:**
- Consumes: `target->active` (existing, Task 7 of the original plan), `target->mode` (Task 1).
- Produces: an on-demand target's tunnel closes itself ~20s after its last active call ends, unless a new call arrives first (which cancels the pending teardown).

**Struct addition** (`l2tp_switch_conf.h`, next to `connect_timeout_timer`):

```c
	struct triton_timer_t idle_timer;
```

Add near the other constants:

```c
#define L2TP_SWITCH_ON_DEMAND_IDLE_LINGER_MS 20000
```

- [ ] **Step 1: Write the failing test**

`tests/accel-pppd/l2tp_switch/test_switch_on_demand_idle_teardown.py`, reusing Task 7-of-the-original-plan's active-switched-call setup (same harness pattern as `test_switch_splice.py`/`test_switch_teardown.py`), with `target=...,on-demand`:

```python
@pytest.mark.l2tp_switch
def test_on_demand_tunnel_closes_after_idle_linger(pytestconfig, accel_cmd, accel_pppd):
    # place a call, let it complete, then end it (CDN from the harness side)
    # assert `l2tp switch show` still shows the target up/idle-but-tunnel-
    # present immediately after the call ends
    # poll for up to ~25s; assert the target's tunnel eventually closes
    # (target->tunnel becomes NULL / CLI reports the resting state) well
    # before 30s, and NOT before ~18s (a too-early teardown would defeat
    # "absorb back-to-back calls")
    ...

@pytest.mark.l2tp_switch
def test_on_demand_linger_cancelled_by_a_new_call(pytestconfig, accel_cmd, accel_pppd):
    # end a call, then -- within the 20s linger window -- place a second
    # call on the same target; assert it succeeds using the still-open
    # tunnel (no new SCCRQ observed on the harness side) and that the
    # tunnel does NOT close early despite the first call's linger timer
    # having been armed
    ...
```

- [ ] **Step 2: Run, verify it fails**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_on_demand_idle_teardown.py`
Expected: FAIL — today (even after Task 2) an on-demand target's tunnel, once up, behaves exactly like a persistent one and never closes itself.

- [ ] **Step 3: Implement**

Arm the linger timer in `l2tp_switch_link_free()` (~line 4045), right after the existing `active` decrement:

```c
	if (link->from_upstream) {
		struct l2tp_switch_target_t *target = link->target;
		unsigned int now = __atomic_sub_fetch(&target->active, 1,
						      __ATOMIC_RELAXED);

		if (now == 0 && target->mode == L2TP_SWITCH_MODE_ON_DEMAND) {
			pthread_mutex_lock(&target->lock);
			if (target->tunnel && !target->idle_timer.tpd &&
			    !target->connecting) {
				target->idle_timer.expire = l2tp_switch_target_idle_timer;
				target->idle_timer.period = L2TP_SWITCH_ON_DEMAND_IDLE_LINGER_MS;
				triton_timer_add(NULL, &target->idle_timer, 0);
			}
			pthread_mutex_unlock(&target->lock);
		}
	}
```

(The fast path added in Task 2's `l2tp_switch_place_downstream_call()` already cancels `idle_timer` the instant a new call reuses an up tunnel, before this arm logic could ever race a fresh call — see that step's comment.)

Add the fire callback, near `l2tp_switch_on_demand_timeout()`:

```c
static void l2tp_switch_close_idle_tunnel(void *data)
{
	struct l2tp_conn_t *conn = data;

	if (conn->state != STATE_CLOSE)
		l2tp_tunnel_disconnect(conn, 1, 0); /* result 1: "general
			request to clear the control connection" (RFC 2661
			§5.4) -- this is a voluntary, administrative close, not
			an error; l2tp_tunnel_free()'s own switch_target hook
			(Task 2) already leaves the target cold afterward
			without scheduling a reconnect, since
			l2tp_switch_target_should_retry() finds pending_count
			== 0 */
	tunnel_put(conn);
}

static void l2tp_switch_target_idle_timer(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), idle_timer);
	struct l2tp_conn_t *conn;

	triton_timer_del(t);

	pthread_mutex_lock(&target->lock);
	conn = target->tunnel;
	pthread_mutex_unlock(&target->lock);

	/* Authoritative re-check: __atomic_load_n on target->active, not just
	 * "was the timer still armed" -- covers the narrow race where a new
	 * call's fast path (Task 2) hasn't reached its triton_timer_del(...)
	 * cancellation yet but has already re-incremented active. */
	if (!conn || __atomic_load_n(&target->active, __ATOMIC_RELAXED) > 0)
		return;

	log_tunnel(log_info1, conn, "l2tp-switch: target \"%s\" idle for %ds,"
		   " closing on-demand tunnel\n", target->name,
		   L2TP_SWITCH_ON_DEMAND_IDLE_LINGER_MS / 1000);
	tunnel_hold(conn);
	triton_context_call(&conn->ctx, l2tp_switch_close_idle_tunnel, conn);
}
```

- [ ] **Step 4: Run, verify it passes**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_on_demand_idle_teardown.py`
Expected: PASS.

**Manually verify beyond the automated tests**: build with ASan/UBSan (this path adds a new `tunnel_hold`/`tunnel_put` pair and a new cross-context call — exactly the kind of thing this repo's own history shows catching real use-after-free/leak bugs), run both new tests directly against a real downstream instance on a VM, and confirm via log evidence that the StopCCN for the idle-teardown case carries result code 1 (not indistinguishable from an error-triggered close) and that the target genuinely goes cold (no lingering socket, `l2tp switch show` back to resting state) afterward.

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c tests/accel-pppd/l2tp_switch/test_switch_on_demand_idle_teardown.py
git commit -m "feat(l2tp): close on-demand target tunnels after a 20s idle linger"
```

---

### Task 4: CLI/metrics observability for on-demand states

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp.c`
- Test: `tests/accel-pppd/l2tp_switch/test_switch_show.py`, `tests/accel-pppd/l2tp_switch/test_switch_metrics.py`

**Interfaces:**
- Produces: `l2tp switch show`'s per-target status field gains two new values for on-demand targets, `[idle]` (resting: no active calls; covers both "never connected" and "post-linger, tunnel closed" states, and — for a human glancing at the CLI — the brief still-connecting tail too, since none of those are actionable faults) and `[connecting]` (a connect is actively in flight with calls queued on it, i.e. `target->connecting` is true — kept as a distinct, more diagnostically useful CLI value even though it folds into the same metrics signal as `[idle]`, see below); persistent targets keep the existing binary `[up]`/`[down]`. The `accel_ppp_l2tp_switch_target_up` gauge's semantics are tightened to literally mean "this target's tunnel is currently established" (`STATE_ESTB`) for both modes — already almost true today, this task makes it exactly true, including through an on-demand tunnel's idle-lingering tail. No new metric is added: `target_up=1` together with the existing `target_active` gauge already fully reconstructs an on-demand target's state for anyone scripting alerts (`up=1,active>0` → busy; `up=1,active=0` → idle-but-still-open/lingering; `up=0` → cold or connecting) — deliberately not adding a fourth label value to keep the metrics surface as intentional as this feature's existing "no tunnel-ID labels" design choice already is (see `docs/l2tp_switching.md`'s own Observability section).

- [ ] **Step 1: Write the failing test**

Add to `test_switch_show.py`: place a call on an on-demand target, assert `[connecting]` appears briefly (best-effort/racy — acceptable to assert loosely or skip if too flaky in CI, matching this suite's own existing tolerance for timing-sensitive assertions elsewhere), then `[up]` once active, then `[idle]` some time after the call ends but before the tunnel actually closes, and finally back to resting `[idle]` (no tunnel) once Task 3's linger fires.

Add to `test_switch_metrics.py`: assert `accel_ppp_l2tp_switch_target_up{target="..."}` reads `0` at rest, `1` once connected, and stays `1` through the idle-linger window (only dropping to `0` once the linger timer actually closes the tunnel) — asserting the tightened, literal `STATE_ESTB`-based semantics rather than "tunnel object exists".

- [ ] **Step 2: Run, verify it fails**

Expected: FAIL — today's display is a plain `t->tunnel ? "up" : "down"`, with no on-demand-aware wording and no `STATE_ESTB` check.

- [ ] **Step 3: Implement**

In `l2tp_switch_show_exec()` (~line 6277), replace the status derivation:

```c
	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		const char *status;

		if (t->mode == L2TP_SWITCH_MODE_PERSISTENT) {
			status = (t->tunnel && t->tunnel->state == STATE_ESTB) ?
				"up" : "down";
		} else {
			pthread_mutex_lock(&t->lock);
			int connecting = t->connecting;
			pthread_mutex_unlock(&t->lock);

			if (t->tunnel && t->tunnel->state == STATE_ESTB)
				status = "up"; /* active > 0 is implied by a
					fresh call always taking the fast path
					in l2tp_switch_place_downstream_call(),
					so "up" here always means genuinely
					busy for on-demand -- an idle-but-still
					-lingering tunnel is reported as "idle"
					below instead, matching this being a
					human-facing summary, not the raw
					tunnel-established bit (that's what
					the target_up metric is for) */
			else if (connecting)
				status = "connecting";
			else
				status = "idle";
		}

		cli_sendv(client, "  %s -> %s:%hu [%s] active=%u"
				   " bytes_in=%llu bytes_out=%llu\r\n",
			 t->name, inet_ntoa(t->peer_addr.sin_addr),
			 ntohs(t->peer_addr.sin_port), status,
			 __atomic_load_n(&t->active, __ATOMIC_RELAXED),
			 (unsigned long long)__atomic_load_n(&t->rx_bytes, __ATOMIC_RELAXED),
			 (unsigned long long)__atomic_load_n(&t->tx_bytes, __ATOMIC_RELAXED));
		...
```

Wait — re-derive "up" for on-demand strictly from `active > 0` rather than `tunnel && STATE_ESTB`, since a tunnel can be `STATE_ESTB` while idle-lingering (Task 3) and should show `[idle]`, not `[up]`, in that case:

```c
			if (__atomic_load_n(&t->active, __ATOMIC_RELAXED) > 0)
				status = "up";
			else if (connecting)
				status = "connecting";
			else
				status = "idle"; /* covers both "never
					connected" and "post-linger, tunnel
					closed" AND "tunnel technically still
					open during the last seconds of its
					own linger window" -- all three are
					the same "nothing needs this target
					right now" signal to a human reading
					this line */
```

In `metrics.c`'s (or wherever `target_up` is resolved from — the existing `l2tp_switch_stat_targets_foreach()` callback in `l2tp.c`, ~line 383) per-target callback, tighten the `up` argument the same way for both modes:

```c
	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		cb(t->name, t->tunnel != NULL && t->tunnel->state == STATE_ESTB,
		   __atomic_load_n(&t->active, __ATOMIC_RELAXED),
		   __atomic_load_n(&t->rx_bytes, __ATOMIC_RELAXED),
		   __atomic_load_n(&t->tx_bytes, __ATOMIC_RELAXED),
		   arg);
	}
```

(This is the one-line correctness fix flagged in this plan's Global Constraints — today's `t->tunnel != NULL` alone is technically true from the moment `l2tp_tunnel_start()` succeeds, before `STATE_ESTB`; tightening it is low-risk and makes the metric's literal name accurate for both modes.)

- [ ] **Step 4: Run, verify it passes**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_show.py accel-pppd/l2tp_switch/test_switch_metrics.py`
Expected: PASS, plus a full `pytest -m l2tp_switch` regression run (the `STATE_ESTB` tightening touches every existing test that polls for `[up]`, including the ones still on `mode=persistent`).

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp.c tests/accel-pppd/l2tp_switch/test_switch_show.py tests/accel-pppd/l2tp_switch/test_switch_metrics.py
git commit -m "feat(l2tp): show idle/connecting states for on-demand targets, tighten target_up semantics"
```

---

### Task 5: Fix existing tests' implicit "tunnel is already up" assumption

**Files:**
- Modify: `tests/accel-pppd/l2tp_switch/test_switch_avp_forward.py`, `test_switch_match.py`, `test_switch_metrics.py`, `test_switch_mixed_tunnel.py`, `test_switch_teardown.py`, `test_switch_teardown_upstream.py`, `test_switch_match_called_number.py`, `test_switch_match_username_prefix.py`, `test_switch_splice.py`, `test_switch_show.py`, `test_switch_downstream_idle_stopccn.py`
- Rewrite: `test_switch_tunnel.py`

**Why these and not others:** `grep -rn '\[up\]' tests/accel-pppd/l2tp_switch/*.py` finds every test in this suite that polls `l2tp switch show` for `[up]` *before placing any call* — using it purely as a "downstream instance is ready" readiness gate. Every one of them is actually testing something else (AVP forwarding, matching rules, splicing, teardown cascades, metrics values, or — for `test_switch_downstream_idle_stopccn.py` specifically — `persistent` mode's own reconnect-after-idle-StopCCN timing, i.e. the exact behavior the companion fix mentioned in this plan's header targets). None of them are testing connection-mode itself, so once the default flips to `on-demand` (Task 6) they would all fail or hang waiting for a tunnel that no longer opens until a call arrives. `test_switch_config.py` needs no change (its targets are unreachable-by-design, config-parse-only fixtures that never wait on `[up]`). `test_switch_cli.py` needs no change (no target= tunnel involved at all — `l2tp switch add`/`del` operate purely on match rules).

- [ ] **Step 1: Pin `mode=persistent` on the eleven files above**

For each, find its own `[l2tp-switch]` `target=...` line (each test builds its own config string via `config.make_tmp()`/`helpers.start_instance(..., extra=...)`, not a shared fixture — confirmed via `helpers.py`, which only centralizes the `[l2tp]`/`[cli]`/`[client-ip-range]` boilerplate, not the `[l2tp-switch]` block itself) and append `,persistent`:

```diff
-    target=downstream,127.0.0.1,{downstream_port},downstreamsecret
+    target=downstream,127.0.0.1,{downstream_port},downstreamsecret,persistent
```

Add a one-line comment at each site explaining why, e.g.:

```python
    # Pinned to persistent: this test's own subject is AVP forwarding, not
    # connection mode -- it relies on the target's tunnel already being up
    # before any call is placed, which is on-demand mode's default *not*
    # to do. See docs/superpowers/plans/2026-09-16-l2tp-switch-connection-mode.md.
```

- [ ] **Step 2: Run, verify the full suite still passes unchanged (regression only)**

Run: `sudo python3 -m pytest -v -m l2tp_switch accel-pppd/l2tp_switch/`
Expected: PASS, identical results to before this task — this step is purely defensive (confirms pinning `persistent` explicitly didn't change any of these tests' actual behavior, since it was already the implicit default).

- [ ] **Step 3: Rewrite `test_switch_tunnel.py`**

Split `test_switch_tunnel_comes_up` into two explicit cases:

```python
@pytest.mark.l2tp_switch
def test_switch_tunnel_persistent_comes_up_with_no_calls(pytestconfig, accel_cmd, accel_pppd):
    # target=downstream,...,persistent -- unchanged from the original test,
    # just the mode made explicit; still asserts "[up]" within a few
    # seconds with zero calls placed
    ...

@pytest.mark.l2tp_switch
def test_switch_tunnel_on_demand_stays_idle_with_no_calls(pytestconfig, accel_cmd, accel_pppd):
    # target=downstream,...,on-demand -- assert the target reports "[idle]"
    # (Task 4), NOT "[up]", for several seconds with no call placed; this
    # is the direct behavioral regression test for the bug motivating this
    # whole plan (a session-less tunnel sitting there for a downstream
    # peer's own idle-timeout to eventually flap)
    ...
```

- [ ] **Step 4: Run, verify it passes**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_tunnel.py`
Expected: PASS, both cases.

- [ ] **Step 5: Commit**

```bash
git add tests/accel-pppd/l2tp_switch/
git commit -m "test(l2tp): make existing switch tests' connection-mode assumption explicit"
```

---

### Task 6: Flip the default to `on-demand`

**Files:**
- Modify: `accel-pppd/ctrl/l2tp/l2tp_switch_conf.c`
- Modify: `tests/accel-pppd/l2tp_switch/test_switch_config.py`

**Interfaces:**
- Changes: a `target=` line with no 5th field now parses to `L2TP_SWITCH_MODE_ON_DEMAND` instead of `L2TP_SWITCH_MODE_PERSISTENT`.

**Why this is safe to do without a deprecation path.** L2TP switching's own `CHANGELOG.md` entry is still listed under `## Unreleased` (confirmed: `CHANGELOG.md` line 14) — it has never shipped in a numbered accel-ppp release. There is therefore no installed base of operators whose `target=` lines (with no `mode=`) would silently start behaving differently under them; every existing user of this feature so far is this repo's own active development/test setup, per the history in `docs/l2tp_switching.md` and the (now-removed-from-tree, git-history-only) original implementation plan. This plan treats the default flip as a normal, in-development design decision, not a breaking change requiring a migration story or a deprecation window.

- [ ] **Step 1: Update the failing test**

In `test_switch_config.py`, flip `test_switch_target_mode_omitted_defaults_persistent` (Task 1) to `test_switch_target_mode_omitted_defaults_on_demand`, asserting the opposite: `l2tp switch show` reports `[idle]` (Task 4's new on-demand-at-rest wording), not `[up]`, for a `target=` line with no 5th field.

- [ ] **Step 2: Run, verify it fails**

Expected: FAIL — the parser still defaults to `persistent` until this task's implementation step.

- [ ] **Step 3: Implement**

One-line change in `parse_target()` (`l2tp_switch_conf.c`):

```diff
-	if (!mode_str || !strcmp(mode_str, "persistent")) {
-		t->mode = L2TP_SWITCH_MODE_PERSISTENT;
-	} else if (!strcmp(mode_str, "on-demand")) {
+	if (!mode_str || !strcmp(mode_str, "on-demand")) {
+		t->mode = L2TP_SWITCH_MODE_ON_DEMAND;
+	} else if (!strcmp(mode_str, "persistent")) {
 		t->mode = L2TP_SWITCH_MODE_PERSISTENT;
-	} else if (!strcmp(mode_str, "on-demand")) {
-		t->mode = L2TP_SWITCH_MODE_ON_DEMAND;
 	} else {
 		log_error(...);
```

- [ ] **Step 4: Run, verify it passes**

Run: `sudo python3 -m pytest -v accel-pppd/l2tp_switch/test_switch_config.py`, then the **entire** `l2tp_switch` suite: `sudo python3 -m pytest -v -m l2tp_switch accel-pppd/l2tp_switch/`.
Expected: PASS across the board — this is exactly why Task 5 had to land first; every test that depends on eager connection now says so explicitly via `mode=persistent`, so this default flip should change nothing about any existing test's outcome except the two `test_switch_config.py`/`test_switch_tunnel.py` cases written specifically to exercise the default.

- [ ] **Step 5: Commit**

```bash
git add accel-pppd/ctrl/l2tp/l2tp_switch_conf.c tests/accel-pppd/l2tp_switch/test_switch_config.py
git commit -m "feat(l2tp): default switch target connection mode to on-demand"
```

---

### Task 7: Documentation

**Files:**
- Modify: `docs/l2tp_switching.md`
- Modify: `accel-pppd/accel-ppp.conf.5`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `accel-pppd/accel-ppp.conf` (sample)

- [ ] **Step 1: `docs/l2tp_switching.md`**

Replace the Configuration section's `target=` bullet (currently: "accel-ppp brings up one persistent outbound tunnel per target at startup and reconnects automatically if it drops") with a description of both modes, e.g.:

```markdown
- `target=<name>,<peer-addr>,<peer-port>,<secret>[,<mode>]` — a downstream
  LNS. Repeatable. `<mode>` is `persistent` or `on-demand` (default:
  `on-demand`):
  - `on-demand` (default) — the outbound tunnel to this target opens only
    once a call actually needs it, and closes itself again after the
    target has had no active calls for 20 seconds (a fresh call within
    that window reuses the tunnel and cancels the pending close). Chosen
    as the default because many real downstream peers (e.g. Juniper
    JunOS, whose own tunnel `idle-timeout` defaults to 60 seconds) tear
    down a session-less tunnel on their own idle policy; `on-demand`
    tears its own side down first, on its own terms, comfortably inside
    that window, rather than flapping forever against the peer's policy.
    A call placed while the tunnel is still connecting queues rather than
    failing immediately, and is only given up on (CDNing the upstream
    call) if the connect hasn't completed within 10 seconds.
  - `persistent` — the original behavior: accel-ppp opens the tunnel
    eagerly at startup and keeps it open indefinitely with automatic
    reconnect, regardless of whether any call is currently using it. Use
    this only if the downstream peer is known to tolerate (or is itself
    configured to tolerate, e.g. JunOS `idle-timeout 0`) an idle,
    session-less control tunnel, and avoiding tunnel-setup latency on a
    call's critical path matters more than the idle-tunnel cost above.
```

Update the Observability section's target-status wording: `[up]`/`[down]` for `persistent` targets are unchanged; `on-demand` targets additionally report `[idle]` (no active calls right now — the expected, healthy resting state, not a fault) and `[connecting]` (a connect is in flight with at least one call waiting on it). Note explicitly that `accel_ppp_l2tp_switch_target_up` means "this target's tunnel is currently established" for both modes (including through an on-demand tunnel's idle-lingering tail before it closes itself) — combine it with the existing `accel_ppp_l2tp_switch_target_active` gauge to distinguish "up and busy" from "up but currently idle" from "on-demand and at rest"; there is deliberately no separate metric for the `[connecting]` CLI state, since it is brief and bounded by the 10s connect-timeout.

- [ ] **Step 2: `accel-pppd/accel-ppp.conf.5`**

Update the `.BI "target="` synopsis and body:

```
.BI "target=" name,peer-addr,peer-port,secret[,mode]
Defines a downstream LNS. Repeatable.
.B mode
is
.B persistent
(eager connect at startup, reconnect forever, regardless of active calls)
or
.B on-demand
(default: connect only when a call needs it, close again after 20s idle).
See docs/l2tp_switching.md for the full rationale and lifecycle.
```

- [ ] **Step 3: `README.md`, `CHANGELOG.md`, sample `accel-pppd/accel-ppp.conf`**

`README.md`: no change needed to the basic `target=acme,203.0.113.50,1701,targetsecret` getting-started example (it already works unchanged under the new default); optionally add one sentence noting the default and pointing at `docs/l2tp_switching.md`.

`CHANGELOG.md`: since L2TP switching itself is still under `## Unreleased`, amend its existing bullet in place (not a new bullet) to mention the mode toggle and default, e.g. append: "; each target can be `persistent` (eager, reconnect forever) or `on-demand` (default: connect only when needed, idle-teardown after 20s)."

Sample config (`accel-pppd/accel-ppp.conf`, ~line 161): add a commented illustration of the optional field:

```diff
 #[l2tp-switch]
-#target=acme,203.0.113.50,1701,targetsecret
+#target=acme,203.0.113.50,1701,targetsecret            # mode defaults to on-demand
+#target=acme2,203.0.113.60,1701,targetsecret,persistent # eager, reconnect forever
 #match=Calling-Number,exact,472913,acme
```

- [ ] **Step 4: Verify**

Render the man page (`man ./accel-pppd/accel-ppp.conf.5` or `groff -man -Tascii`) to confirm no `.BI`/`.TP` macro errors; spot-check `docs/l2tp_switching.md` renders sensibly (no broken markdown list nesting) by eye.

- [ ] **Step 5: Commit**

```bash
git add docs/l2tp_switching.md accel-pppd/accel-ppp.conf.5 README.md CHANGELOG.md accel-pppd/accel-ppp.conf
git commit -m "docs: document persistent/on-demand switch target connection modes"
```

---

### Note on scope/fidelity

This plan is concrete and directly actionable (exact struct fields, exact existing hook functions/line anchors as of this writing, exact concurrency reasoning with cited evidence from `l2tp.c`/`triton/timer.c`), but — matching this repo's own historical plan doc's practice — a few micro-details (e.g. the MK-simulator harness's exact flag for injecting an artificial SCCRP delay in Task 2's queueing test, exact RFC 2661 result/error code conventions already used elsewhere in `l2tp_recv_SCCRQ`/etc.) are flagged for the implementer to confirm against the real build/headers rather than asserted as already-verified fact, since this plan was written in a read-only planning pass with no compile/run access.

### Critical Files for Implementation

- `accel-pppd/ctrl/l2tp/l2tp_switch_conf.h`
- `accel-pppd/ctrl/l2tp/l2tp_switch_conf.c`
- `accel-pppd/ctrl/l2tp/l2tp.c`
- `docs/l2tp_switching.md`
- `tests/accel-pppd/l2tp_switch/test_switch_tunnel.py`
- `tests/accel-pppd/l2tp_switch/test_switch_downstream_idle_stopccn.py`
