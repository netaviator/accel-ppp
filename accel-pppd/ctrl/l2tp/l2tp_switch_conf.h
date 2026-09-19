#ifndef __L2TP_SWITCH_CONF_H
#define __L2TP_SWITCH_CONF_H

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>

#include "list.h"
#include "triton.h"

struct l2tp_dict_attr_t;
struct l2tp_conn_t;

enum l2tp_switch_conn_mode {
	L2TP_SWITCH_MODE_PERSISTENT,
	L2TP_SWITCH_MODE_ON_DEMAND,
};

/* Lifetime: targets are created by l2tp_switch_conf_load() at startup and
 * are never freed while the daemon runs (only switch_conf_clear(), at the
 * next config load, before anything can hold one). Everything that keeps a
 * `struct l2tp_switch_target_t *` -- match rules, sessions, the metrics
 * scraper walking l2tp_switch_targets from its own thread -- relies on that
 * instead of a reference count, and the list itself is never modified after
 * load, so iterating it needs no lock. The mutable fields inside a target
 * have their own rules, noted per field below. */
struct l2tp_switch_target_t {
	struct list_head entry;
	char *name;
	struct sockaddr_in peer_addr;
	char *secret;
	size_t secret_len;
	enum l2tp_switch_conn_mode mode;

	/* Owned by l2tp.c: this target's current outbound tunnel, or NULL
	 * when it has none. What NULL means depends on the mode: for a
	 * persistent target it is a transient state (down, or reconnecting),
	 * while for an on-demand target it is the normal resting state --
	 * no tunnel exists until a call needs one, and the idle linger
	 * returns the target to it once the last call is gone. A non-NULL
	 * value also doubles as the "one connect attempt at a time"
	 * exclusion in l2tp_switch_target_connect(), so it is set as soon as
	 * an attempt starts, not once it establishes: use
	 * `tunnel->state == STATE_ESTB` to test for a usable tunnel. */
	struct l2tp_conn_t *tunnel;
	struct triton_timer_t reconnect_timer;

	/* Guards everything below, plus the `tunnel` pointer and
	 * `reconnect_timer`'s armed/not-armed state above. These are mutated
	 * from whichever upstream session's own tunnel context happens to
	 * place a call against this target, from the target tunnel's own
	 * context, and from the default context (both timers below are armed
	 * with a NULL context) -- so a plain list_head is not safe here
	 * without a lock, mirroring l2tp_lock/conn->ctx_lock's existing role
	 * elsewhere in l2tp.c for exactly this kind of cross-context-shared,
	 * non-atomic-friendly state. */
	pthread_mutex_t lock;
	struct list_head pending_calls; /* l2tp_sess_t.switch_pending_entry */
	unsigned int pending_count;
	/* "A connect budget is open": calls are queued waiting for this
	 * target to produce a usable tunnel, and connect_timeout_timer is
	 * armed to bound that wait. Deliberately NOT "a connect attempt is
	 * running right now" -- the budget stays open across a failed attempt
	 * and the idle gap before the next reconnect_timer tick. Anything
	 * wanting the narrower "negotiating right now" (e.g. a future
	 * [connecting] CLI state) should derive it from
	 * `tunnel && tunnel->state != STATE_ESTB` instead. */
	int connect_budget_open;
	/* Monotonic ms at which the currently-open budget expires. Lets
	 * l2tp_switch_on_demand_timeout() tell a genuine expiry from a
	 * dispatch left over from a budget that has since been closed and
	 * reopened -- triton hands the callback nothing that identifies which
	 * arming of this (single, embedded) timer it belongs to. */
	uint64_t connect_deadline;
	struct triton_timer_t connect_timeout_timer;
	/* Monotonic ms at which the armed idle_timer's current linger
	 * expires, or 0 when no linger is pending. Plays exactly the two
	 * roles connect_deadline plays for connect_timeout_timer: cancelling
	 * a linger (a new call reusing the tunnel, from that call's own
	 * context) is a matter of zeroing this under the lock, leaving the
	 * timer for the default context that owns it to retire on its next
	 * tick -- deleting a triton timer from a foreign context races its
	 * dispatch; and a dispatch left over from an earlier, shorter linger
	 * is told apart from a genuine expiry by comparing against it, since
	 * triton hands the callback nothing identifying which arming of this
	 * single embedded timer it belongs to. */
	uint64_t idle_deadline;
	/* Fires once idle_deadline has passed, closing an on-demand target's
	 * now-callless tunnel. Armed and re-armed on the default context by
	 * l2tp_switch_target_arm_idle_linger(), and retired only by its own
	 * callback, l2tp_switch_target_idle_timer(), which runs there too.
	 * Unused for persistent targets, whose tunnels are never closed for
	 * being idle. */
	struct triton_timer_t idle_timer;

	/* Owned by l2tp.c: live/cumulative stats for this target,
	 * from this target's own point of view -- rx is bytes received FROM
	 * this target's downstream LNS, tx is bytes sent TO it. Monotonic:
	 * never reset, never decremented, so they stay valid Prometheus
	 * counters across calls starting and ending. */
	unsigned int active;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

extern struct list_head l2tp_switch_targets;

/* On-demand connection-mode timing, from the [l2tp-switch] `idle-linger=` and
 * `connect-timeout=` options (seconds). Fixed after l2tp_switch_conf_load(),
 * so the getters need no lock. */
#define L2TP_SWITCH_DEFAULT_IDLE_LINGER_SEC 20
#define L2TP_SWITCH_DEFAULT_CONNECT_TIMEOUT_SEC 10
#define L2TP_SWITCH_DEFAULT_RECONNECT_INTERVAL_SEC 5
#define L2TP_SWITCH_DEFAULT_PAP_TIMEOUT_SEC 3
#define L2TP_SWITCH_MAX_TIMING_SEC 3600

/* How long an on-demand target's tunnel stays up after its last call ends.
 * Long enough that back-to-back calls reuse it instead of paying a fresh
 * SCCRQ round trip each time (and instead of making accel-ppp itself the
 * source of a connect/disconnect flap), short enough that accel-ppp closes
 * the session-less tunnel on its own terms well before a downstream peer's
 * own idle policy does it for us -- JunOS' default idle-timeout, the
 * shortest one this feature is known to face, is 60s. */
int l2tp_switch_conf_idle_linger_ms(void);
/* How long a call placed against a cold on-demand target may wait for that
 * target's tunnel to finish connecting before the call is given up on. Long
 * enough to absorb a normal SCCRQ retransmission round or two against a
 * briefly unresponsive peer, short enough that a caller facing a genuinely
 * dead target gets a clear failure instead of a silent hang. */
int l2tp_switch_conf_connect_timeout_ms(void);
/* Delay between connection attempts to a target whose tunnel failed to come
 * up (or, for a persistent target, dropped). Keep it below connect-timeout
 * if a queued call should get more than one attempt. */
int l2tp_switch_conf_reconnect_interval_ms(void);
/* How long the live-PAP watcher waits for the downstream target's Ack/Nak to
 * the request it injected before it gives up and disconnects the call. Keep
 * it below the ~5s a downstream LNS has been observed to wait for PAP itself
 * (so our timeout produces an attributable log line instead of racing its
 * CDN), but long enough for a target whose authentication backend (RADIUS)
 * is slow to answer. */
int l2tp_switch_conf_pap_timeout_ms(void);

int l2tp_switch_conf_load(void);
struct l2tp_switch_target_t *l2tp_switch_target_find(const char *name);

/* Generic AVP-based call routing: each rule names its own AVP (by dictionary
 * name, e.g. "Calling-Number" or "Proxy-Authen-Name") and a match mode
 * ("exact" or "prefix") -- callers (l2tp.c) don't need to know which
 * message an AVP normally arrives in, or track match state themselves;
 * they just offer every AVP they see, for every message, until one call
 * returns non-NULL. */
struct l2tp_switch_target_t *l2tp_switch_match(const struct l2tp_dict_attr_t *attr,
					       const uint8_t *val, int len);
int l2tp_switch_rule_add(const char *attr_name, const char *mode_name,
			 const uint8_t *val, int len, const char *target_name);
int l2tp_switch_rule_del(const char *attr_name, const char *mode_name,
			 const uint8_t *val, int len);

#endif
