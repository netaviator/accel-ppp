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

	/* Owned by l2tp.c (Task 7): live/cumulative stats for this target,
	 * from this target's own point of view -- rx is bytes received FROM
	 * this target's downstream LNS, tx is bytes sent TO it. Monotonic:
	 * never reset, never decremented, so they stay valid Prometheus
	 * counters across calls starting and ending. */
	unsigned int active;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

extern struct list_head l2tp_switch_targets;

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
