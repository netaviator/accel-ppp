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

	/* Owned by l2tp.c (Task 3): the persistent outbound tunnel for this
	 * target, or NULL while down/reconnecting. */
	struct l2tp_conn_t *tunnel;
	struct triton_timer_t reconnect_timer;

	/* on-demand only (owned by l2tp.c): guards pending_calls/pending_count/
	 * connecting below, and the tunnel pointer above. These are mutated
	 * from whichever upstream session's own tunnel context happens to
	 * place a call against this target -- essentially never this target's
	 * own tunnel context, and often no context at all while the target is
	 * cold -- so a plain list_head is not safe here without a lock,
	 * mirroring l2tp_lock/conn->ctx_lock's existing role elsewhere in
	 * l2tp.c for exactly this kind of cross-context-shared,
	 * non-atomic-friendly state. */
	pthread_mutex_t lock;
	struct list_head pending_calls; /* l2tp_sess_t.switch_pending_entry */
	unsigned int pending_count;
	int connecting;
	struct triton_timer_t connect_timeout_timer;
	struct triton_timer_t idle_timer; /* armed by Task 3; declared here
		because this task's own l2tp_switch_place_downstream_call()
		fast path already references target->idle_timer (to cancel a
		linger-teardown when a call reuses an up tunnel) before Task 3
		exists -- the field has to exist for this task to compile on
		its own. */

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
