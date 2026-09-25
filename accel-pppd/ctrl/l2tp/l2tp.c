#include <unistd.h>
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>

#include <openssl/md5.h>

#include "triton.h"
#include "mempool.h"
#include "log.h"
#include "ppp.h"
#include "events.h"
#include "utils.h"
#include "iprange.h"
#include "cli.h"

#include "connlimit.h"

#include "memdebug.h"

#include "l2tp.h"
#include "attr_defs.h"
#include "l2tp_switch_conf.h"

#ifndef SOL_PPPOL2TP
#define SOL_PPPOL2TP 273
#endif

#define STATE_INIT       1
#define STATE_WAIT_SCCRP 2
#define STATE_WAIT_SCCCN 3
#define STATE_WAIT_ICRP  4
#define STATE_WAIT_ICCN  5
#define STATE_WAIT_OCRP  6
#define STATE_WAIT_OCCN  7
#define STATE_ESTB       8
#define STATE_FIN        9
#define STATE_FIN_WAIT   10
#define STATE_CLOSE      11

#define APSTATE_INIT      1
#define APSTATE_STARTING  2
#define APSTATE_STARTED   3
#define APSTATE_FINISHING 4

/* Default size of receive window for peer not sending the
 * Receive Window Size AVP (defined in RFC 2661 section 4.4.3).
 */
#define DEFAULT_PEER_RECV_WINDOW_SIZE 4

/* Maximum value of the Receive Window Size AVP.
 * The Ns field value of received messages must lie in the range of the tunnel
 * Nr field and the following 32768 values inclusive. Other values mean that
 * the message is a duplicate (see comment in nsnr_cmp()).
 * So it wouldn't make sense to have a receive window larger than 32768, as
 * messages that could fill the 32768+ slots would be rejected as duplicates.
 */
#define RECV_WINDOW_SIZE_MAX 32768

#define DEFAULT_RECV_WINDOW 16
#define DEFAULT_PPP_MAX_MTU 1420
#define DEFAULT_RTIMEOUT 1
#define DEFAULT_RTIMEOUT_CAP 16
#define DEFAULT_RETRANSMIT 5

/* Ceiling on calls queued behind a single in-flight on-demand connect: a
 * target that cannot be reached must not let the upstream side accumulate
 * unbounded held sessions while it keeps retrying. */
#define L2TP_SWITCH_PENDING_MAX 64

int conf_verbose = 0;
int conf_hide_avps = 0;
int conf_avp_permissive = 0;
static uint16_t conf_recv_window = DEFAULT_RECV_WINDOW;
static int conf_ppp_max_mtu = DEFAULT_PPP_MAX_MTU;
static int conf_port = L2TP_PORT;
static int conf_ephemeral_ports = 0;
static int conf_timeout = 60;
static int conf_rtimeout = DEFAULT_RTIMEOUT;
static int conf_rtimeout_cap = DEFAULT_RTIMEOUT_CAP;
static int conf_retransmit = DEFAULT_RETRANSMIT;
static int conf_hello_interval = 60;
static int conf_dir300_quirk = 0;
static const char *conf_host_name = "accel-ppp";
static const char *conf_secret = NULL;
static size_t conf_secret_len = 0;
static int conf_mppe = MPPE_UNSET;
static int conf_dataseq = L2TP_DATASEQ_ALLOW;
static int conf_reorder_timeout = 0;
static int conf_session_timeout;
static const char *conf_ip_pool;
static const char *conf_ipv6_pool;
static const char *conf_dpv6_pool;
static const char *conf_ifname;

struct l2tp_stat_t
{
	unsigned int conn_starting;
	unsigned int conn_active;
	unsigned int conn_finishing;

	unsigned int sess_starting;
	unsigned int sess_active;
	unsigned int sess_finishing;

	unsigned int data_starting;
	unsigned int data_active;
	unsigned int data_finishing;

	/* l2tp-switch (Tasks 5-9) */
	unsigned int switch_matched;             /* ICRQ matched a target */
	unsigned int switch_placed;              /* downstream call placed */
	unsigned int switch_downstream_connected; /* downstream ICRP handled */

	/* No switch_active field here, deliberately: "currently bridged
	 * pairs" already has exactly one correct source of truth --
	 * l2tp_switch_target_t.active, kept accurate by symmetric
	 * increment/decrement in l2tp_switch_link_create()/_free(),
	 * including every partial-failure path. A second, independently
	 * incremented/decremented copy here would be redundant at best and
	 * silently wrong at worst if the two ever drift. The
	 * aggregate is derived by summing every target's `active` on read instead. */

	/* LNS-side aggregate byte counters -- named after
	 * lns_mode/the existing `mode <lac|lns>` CLI terminology already in
	 * this file, not "upstream": in ISP/BNG contexts "upstream" usually
	 * means upload-vs-download traffic direction, which would collide
	 * with the rx/tx direction these very counters carry. This is the
	 * side facing the upstream LAC, from that side's own point of view: rx is bytes
	 * received FROM the upstream LAC (which then get spliced out to whichever target
	 * each call belongs to), tx is bytes sent back TO the upstream LAC. Deliberately
	 * aggregated across every target rather than split by the upstream LAC's own
	 * tunnel ID: those IDs are ephemeral (renegotiated on every
	 * reconnect), so they make poor identity for a long-lived counter.
	 * Per-target rx/tx (from that target's own point of view) live on
	 * l2tp_switch_target_t itself, not here -- there can be
	 * several targets, and this struct is a single global snapshot.
	 * Both are monotonic: never decremented, so Prometheus scraping
	 * behaves correctly. */
	uint64_t switch_lns_rx_bytes;
	uint64_t switch_lns_tx_bytes;
};

static struct l2tp_stat_t l2tp_stat;

struct l2tp_serv_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct sockaddr_in addr;
};

struct l2tp_sess_t
{
	struct l2tp_conn_t *paren_conn;
	uint16_t sid;
	uint16_t peer_sid;
/* We will keep l2tp attributes Calling-Number/Called-Number and their length while the session exists */
	char *calling_num;
	int calling_num_len;
	char *called_num;
	int called_num_len;

	unsigned int ref_count;
	int state1;
	uint16_t lns_mode:1;
	uint16_t hide_avps:1;
	uint16_t send_seq:1;
	uint16_t recv_seq:1;
	int reorder_timeout;

	struct triton_timer_t timeout_timer;
	struct list_head send_queue;

	pthread_mutex_t apses_lock;
	struct triton_context_t apses_ctx;
	int apses_state;
	struct ap_ctrl ctrl;
	struct ppp_t ppp;

	struct l2tp_switch_target_t *switch_target; /* NULL: normal session */
	struct l2tp_switch_avps *switch_avps; /* captured from upstream ICCN */
	struct l2tp_sess_t *switch_downstream; /* the outbound leg, once placed */
	struct l2tp_sess_t *switch_upstream;   /* back-pointer from the outbound leg */
	struct l2tp_switch_link_t *switch_link; /* this session's own
						  * read-and-forward link,
						  * once paired */
	struct list_head switch_pending_entry; /* linked into
		target->pending_calls while an on-demand connect for this
		call's target is in flight; unused otherwise */
};

/* Full body defined here (not just the forward tag near the top of this
 * file) because l2tp_send_ICCN() -- defined well before l2tp_recv_ICCN()
 * and the capture/place-call helpers that also use this type -- needs to
 * dereference ->count/->avp[] to re-inject captured AVPs, not just hold a
 * pointer to it. A pointer field (l2tp_sess_t.switch_avps above) only
 * needs the incomplete forward-declared type; member access needs the
 * complete one available at every use site. */
struct l2tp_switch_avp_t {
	int id;
	int M;
	uint8_t *val;
	int len;
};

struct l2tp_switch_avps {
	struct l2tp_switch_avp_t avp[8]; /* Init/Last-Sent/Last-Recv LCP,
					   * 5x Proxy-Authen-* */
	int count;
};

struct l2tp_conn_t
{
	pthread_mutex_t ctx_lock;
	pthread_mutex_t sessions_lock; /* guards WRITES to ->sessions (tsearch/
		tdelete/tdestroy, all on this tunnel's own context) against the
		`l2tp switch show` walk of it on the CLI thread; reads on the
		tunnel's own context need no lock */
	struct triton_context_t ctx;

	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout_timer;
	struct triton_timer_t rtimeout_timer;
	struct triton_timer_t hello_timer;
	int rtimeout;
	int rtimeout_cap;
	int max_retransmit;

	struct sockaddr_in peer_addr;
	struct sockaddr_in host_addr;
	uint16_t tid;
	uint16_t peer_tid;
	uint32_t framing_cap;
	uint16_t lns_mode:1;
	uint16_t hide_avps:1;
	uint16_t port_set:1;
	uint16_t challenge_len;
	uint8_t *challenge;
	size_t secret_len;
	char *secret;

	int retransmit;
	uint16_t Ns, Nr;
	uint16_t peer_Nr;
	struct list_head send_queue;
	struct list_head rtms_queue;
	unsigned int send_queue_len;
	struct l2tp_packet_t **recv_queue;
	uint16_t recv_queue_sz;
	uint16_t recv_queue_offt;
	uint16_t peer_rcv_wnd_sz;

	unsigned int ref_count;
	int state;
	void *sessions;
	unsigned int sess_count;

	struct l2tp_switch_target_t *switch_target; /* NULL for ordinary tunnels */
};

static pthread_mutex_t l2tp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct l2tp_conn_t **l2tp_conn;

static mempool_t l2tp_conn_pool;
static mempool_t l2tp_sess_pool;

static void l2tp_tunnel_timeout(struct triton_timer_t *t);
static void l2tp_rtimeout(struct triton_timer_t *t);
static void l2tp_send_HELLO(struct triton_timer_t *t);
static int l2tp_conn_read(struct triton_md_handler_t *);
static void l2tp_session_free(struct l2tp_sess_t *sess);
static void l2tp_tunnel_free(struct l2tp_conn_t *conn);
static void apses_stop(void *data);
/* l2tp-switch: l2tp_switch_target_connect(), defined right after
 * l2tp_tunnel_alloc() below, starts an outbound tunnel the same way
 * l2tp_create_tunnel_exec() does much further down in this file -- where
 * l2tp_send_SCCRQ() is actually defined. */
static void l2tp_send_SCCRQ(void *peer_addr);
/* l2tp-switch: l2tp_switch_place_call(), defined right above
 * l2tp_recv_ICCN below, places the downstream leg's call using the same
 * function the manual "l2tp create session" CLI path already uses --
 * l2tp_session_place_call() itself isn't defined until much further down
 * in this file. */
static int l2tp_session_place_call(struct l2tp_sess_t *sess);

/* l2tp-switch: struct l2tp_sess_t (above) holds a pointer to
 * struct l2tp_switch_link_t before its full body is defined, and
 * l2tp_session_free()'s teardown hook calls the two functions
 * below before their natural definition point near the rest of the
 * splice/pairing code, so they are declared here together, matching this file's own existing forward-declaration
 * convention above. (struct l2tp_switch_avps itself is fully defined
 * just above, right after struct l2tp_sess_t -- its actual body is
 * needed this early, not just a forward tag, since
 * l2tp_send_ICCN() dereferences it well before l2tp_recv_ICCN().) */
struct l2tp_switch_link_t;

static unsigned int l2tp_switch_active_total(void);
static void l2tp_switch_link_free(struct l2tp_switch_link_t *link);
static void l2tp_switch_teardown_peer(void *data);
/* l2tp-switch: defined right above l2tp_recv_ICCN below, next to the rest of
 * the call-placing code. Declared here because l2tp_tunnel_connect() -- far
 * earlier in this file -- drains an on-demand target's queued calls onto the
 * tunnel that has just come up, and places each of them with it. */
static void l2tp_switch_place_call_on(struct l2tp_sess_t *upstream,
				      struct l2tp_conn_t *conn);
/* l2tp-switch: the idle linger that closes an on-demand target's tunnel once
 * its last call is gone. l2tp_session_free() -- above the rest of the switch
 * code -- arms it for the tunnel it has just left session-less, in place of
 * the immediate disconnect an ordinary tunnel gets there. The timer callback
 * itself is defined much further down, next to the connect-timeout one it
 * mirrors, because it needs tunnel_hold()/l2tp_tunnel_disconnect_push(). */
static int l2tp_switch_target_arm_idle_linger(struct l2tp_switch_target_t *target,
					      struct l2tp_conn_t *conn);
static void l2tp_switch_target_idle_timer(struct triton_timer_t *t);

static void l2tp_stat_inc(unsigned int *stat)
{
	__atomic_add_fetch(stat, 1, __ATOMIC_RELAXED);
}

static void l2tp_stat_dec(unsigned int *stat)
{
	__atomic_sub_fetch(stat, 1, __ATOMIC_RELAXED);
}

static void l2tp_stat_move(unsigned int *from, unsigned int *to)
{
	l2tp_stat_dec(from);
	l2tp_stat_inc(to);
}

static void l2tp_stat_get(struct l2tp_stat_t *stat)
{
	stat->conn_starting = __atomic_load_n(&l2tp_stat.conn_starting, __ATOMIC_RELAXED);
	stat->conn_active = __atomic_load_n(&l2tp_stat.conn_active, __ATOMIC_RELAXED);
	stat->conn_finishing = __atomic_load_n(&l2tp_stat.conn_finishing, __ATOMIC_RELAXED);
	stat->sess_starting = __atomic_load_n(&l2tp_stat.sess_starting, __ATOMIC_RELAXED);
	stat->sess_active = __atomic_load_n(&l2tp_stat.sess_active, __ATOMIC_RELAXED);
	stat->sess_finishing = __atomic_load_n(&l2tp_stat.sess_finishing, __ATOMIC_RELAXED);
	stat->data_starting = __atomic_load_n(&l2tp_stat.data_starting, __ATOMIC_RELAXED);
	stat->data_active = __atomic_load_n(&l2tp_stat.data_active, __ATOMIC_RELAXED);
	stat->data_finishing = __atomic_load_n(&l2tp_stat.data_finishing, __ATOMIC_RELAXED);
	stat->switch_matched = __atomic_load_n(&l2tp_stat.switch_matched, __ATOMIC_RELAXED);
	stat->switch_placed = __atomic_load_n(&l2tp_stat.switch_placed, __ATOMIC_RELAXED);
	stat->switch_downstream_connected = __atomic_load_n(&l2tp_stat.switch_downstream_connected, __ATOMIC_RELAXED);
	stat->switch_lns_rx_bytes = __atomic_load_n(&l2tp_stat.switch_lns_rx_bytes, __ATOMIC_RELAXED);
	stat->switch_lns_tx_bytes = __atomic_load_n(&l2tp_stat.switch_lns_tx_bytes, __ATOMIC_RELAXED);
}

unsigned int __export l2tp_stat_starting(void)
{
	return __atomic_load_n(&l2tp_stat.data_starting, __ATOMIC_RELAXED);
}

unsigned int __export l2tp_stat_active(void)
{
	return __atomic_load_n(&l2tp_stat.data_active, __ATOMIC_RELAXED);
}

unsigned int __export l2tp_switch_stat_active(void)
{
	return l2tp_switch_active_total(); /* summed across targets, not a
					     * stored counter -- see the note
					     * on struct l2tp_stat_t above */
}

uint64_t __export l2tp_switch_stat_lns_rx_bytes(void)
{
	return __atomic_load_n(&l2tp_stat.switch_lns_rx_bytes, __ATOMIC_RELAXED);
}

uint64_t __export l2tp_switch_stat_lns_tx_bytes(void)
{
	return __atomic_load_n(&l2tp_stat.switch_lns_tx_bytes, __ATOMIC_RELAXED);
}

typedef void (*l2tp_switch_target_stat_cb)(const char *name, int up,
					   unsigned int active,
					   uint64_t rx_bytes, uint64_t tx_bytes,
					   void *arg);

/* metrics.c cannot iterate l2tp_switch_targets itself -- that list, and
 * struct l2tp_switch_target_t's layout, are internal to this module;
 * sharing them across the module boundary would tie the two modules'
 * binary layouts together, exactly what the dlsym-based design elsewhere
 * in this file avoids. Exporting an iteration function instead means
 * metrics.c only ever needs a function pointer plus plain scalars. */
void __export l2tp_switch_stat_targets_foreach(l2tp_switch_target_stat_cb cb,
					       void *arg)
{
	struct l2tp_switch_target_t *t;

	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		int up;

		/* Same reason as l2tp_switch_show_exec()'s snapshot: this runs
		 * on whichever thread is scraping metrics, not on the context
		 * that owns the tunnel pointer. No reference/hold needed here
		 * (unlike that function's cross-lock-boundary use of the
		 * pointer for twalk()) -- ->state is read strictly inside this
		 * same locked section, never after unlocking, so nothing can
		 * free the tunnel out from under this read. Checking ->state
		 * instead of mere non-NULL-ness is this task's whole point:
		 * target_up is meant to literally mean "genuinely STATE_ESTB",
		 * for both modes -- a tunnel object exists from the moment
		 * l2tp_tunnel_start() is called, well before that. */
		pthread_mutex_lock(&t->lock);
		up = t->tunnel != NULL && t->tunnel->state == STATE_ESTB;
		pthread_mutex_unlock(&t->lock);

		cb(t->name, up,
		   __atomic_load_n(&t->active, __ATOMIC_RELAXED),
		   __atomic_load_n(&t->rx_bytes, __ATOMIC_RELAXED),
		   __atomic_load_n(&t->tx_bytes, __ATOMIC_RELAXED),
		   arg);
	}
}


#define log_tunnel(log_func, conn, fmt, ...)				\
	do {								\
		char addr[17];						\
		u_inet_ntoa(conn->peer_addr.sin_addr.s_addr, addr);	\
		log_func("l2tp tunnel %hu-%hu (%s:%hu): " fmt,		\
			 conn->tid, conn->peer_tid, addr,		\
			 ntohs(conn->peer_addr.sin_port),		\
			 ##__VA_ARGS__);				\
	} while (0)

#define log_session(log_func, sess, fmt, ...)				\
	do {								\
		log_func("l2tp session %hu-%hu, %hu-%hu: "		\
			 fmt, sess->paren_conn->tid,			\
			 sess->paren_conn->peer_tid, sess->sid,		\
			 sess->peer_sid, ##__VA_ARGS__);		\
	} while (0)

static inline void comp_chap_md5(uint8_t *md5, uint8_t ident,
				 const void *secret, size_t secret_len,
				 const void *chall, size_t chall_len)
{
	MD5_CTX md5_ctx;

	memset(md5, 0, MD5_DIGEST_LENGTH);

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, &ident, sizeof(ident));
	MD5_Update(&md5_ctx, secret, secret_len);
	MD5_Update(&md5_ctx, chall, chall_len);
	MD5_Final(md5, &md5_ctx);
}

static inline int nsnr_cmp(uint16_t ns, uint16_t nr)
{
/*
 * RFC 2661, section 5.8:
 *
 * The sequence number in the header of a received message is considered
 * less than or equal to the last received number if its value lies in
 * the range of the last received number and the preceding 32767 values,
 * inclusive. For example, if the last received sequence number was 15,
 * then messages with sequence numbers 0 through 15, as well as 32784
 * through 65535, would be considered less than or equal.
 */
	uint16_t sub_nsnr = ns - nr;
	uint16_t ref = -32767;        /* 32769 */

	/* Compare Ns - Nr with -32767 (which equals 32769 for uint16_t):
	 *
	 * Ns == Nr  <==>  Ns - Nr == 0,
	 * Ns > Nr   <==>  Ns - Nr in ]0, 32769[   <==>  0 < Ns - Nr < ref
	 * Ns < Nr   <==>  Ns - Nr in [-32767, 0[  <==> (Ns - Nr) >= ref,
	 */
	return (sub_nsnr != 0 && sub_nsnr < ref) - (sub_nsnr >= ref);
}

static void l2tp_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	struct ap_session *apses = arg;

	if (apses)
		net = apses->net;
	else
		net = def_net;

	log_switch(ctx, arg);
}

static inline struct l2tp_conn_t *l2tp_tunnel_self(void)
{
	return container_of(triton_context_self(), struct l2tp_conn_t, ctx);
}

static int sess_cmp(const void *a, const void *b)
{
	const struct l2tp_sess_t *sess_a = a;
	const struct l2tp_sess_t *sess_b = b;

	return (sess_a->sid > sess_b->sid) - (sess_a->sid < sess_b->sid);
}

static struct l2tp_sess_t *l2tp_tunnel_get_session(struct l2tp_conn_t *conn,
						   uint16_t sid)
{
	struct l2tp_sess_t sess = {.sid = sid, 0};
	struct l2tp_sess_t **res = NULL;

	res = tfind(&sess, &conn->sessions, sess_cmp);

	return (res) ? *res : NULL;
}

static int l2tp_tunnel_genchall(uint16_t chall_len,
				struct l2tp_conn_t *conn,
				struct l2tp_packet_t *pack)
{
	void *ptr = NULL;
	int err;

	if (chall_len == 0
	    || conn->secret == NULL || conn->secret_len == 0) {
		if (conn->challenge) {
			_free(conn->challenge);
			conn->challenge = NULL;
		}
		conn->challenge_len = 0;
		return 0;
	}

	if (conn->challenge_len != chall_len) {
		ptr = _realloc(conn->challenge, chall_len);
		if (ptr == NULL) {
			log_tunnel(log_error, conn,
				   "impossible to generate Challenge:"
				   " memory allocation failed\n");
			goto err;
		}
		conn->challenge = ptr;
		conn->challenge_len = chall_len;
	}

	if (u_randbuf(conn->challenge, chall_len, &err) < 0) {
		if (err)
			log_tunnel(log_error, conn,
				   "impossible to generate Challenge:"
				   " reading from urandom failed: %s\n",
				   strerror(err));
		else
			log_tunnel(log_error, conn,
				   "impossible to generate Challenge:"
				   " end of file reached while reading"
				   " from urandom\n");
		goto err;
	}

	if (l2tp_packet_add_octets(pack, Challenge, conn->challenge,
				   conn->challenge_len, 1) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to generate Challenge:"
			   " adding data to packet failed\n");
		goto err;
	}

	return 0;

err:
	if (conn->challenge) {
		_free(conn->challenge);
		conn->challenge = NULL;
	}
	conn->challenge_len = 0;
	return -1;
}

static int l2tp_tunnel_storechall(struct l2tp_conn_t *conn,
				  const struct l2tp_attr_t *chall)
{
	void *ptr = NULL;

	if (chall == NULL) {
		if (conn->challenge) {
			_free(conn->challenge);
			conn->challenge = NULL;
		}
		conn->challenge_len = 0;
		return 0;
	}

	if (conn->secret == NULL || conn->secret_len == 0) {
		log_tunnel(log_error, conn, "authentication required by peer,"
			   " but no secret has been set for this tunnel\n");
		goto err;
	}

	if (conn->challenge_len != chall->length) {
		ptr = _realloc(conn->challenge, chall->length);
		if (ptr == NULL) {
			log_tunnel(log_error, conn,
				   "impossible to store received"
				   " Challenge: memory allocation failed\n");
			goto err;
		}
		conn->challenge = ptr;
		conn->challenge_len = chall->length;
	}

	memcpy(conn->challenge, chall->val.octets, chall->length);

	return 0;

err:
	if (conn->challenge) {
		_free(conn->challenge);
		conn->challenge = NULL;
	}
	conn->challenge_len = 0;
	return -1;
}

static int l2tp_tunnel_genchallresp(uint8_t msgident,
				    const struct l2tp_conn_t *conn,
				    struct l2tp_packet_t *pack)
{
	uint8_t challresp[MD5_DIGEST_LENGTH];

	if (conn->challenge == NULL) {
		if (conn->secret && conn->secret_len > 0) {
			log_tunnel(log_warn, conn,
				   "no Challenge sent by peer\n");
		}
		return 0;
	}

	if (conn->secret == NULL || conn->secret_len == 0) {
		log_tunnel(log_error, conn,
			   "impossible to generate Challenge Response:"
			   " no secret set for this tunnel\n");
		return -1;
	}

	comp_chap_md5(challresp, msgident, conn->secret, conn->secret_len,
		      conn->challenge, conn->challenge_len);
	if (l2tp_packet_add_octets(pack, Challenge_Response, challresp,
				   MD5_DIGEST_LENGTH, 1) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to generate Challenge Response:"
			   " adding data to packet failed\n");
		return -1;
	}

	return 0;
}

static int l2tp_tunnel_checkchallresp(uint8_t msgident,
				      const struct l2tp_conn_t *conn,
				      const struct l2tp_attr_t *challresp)
{
	uint8_t challref[MD5_DIGEST_LENGTH];

	if (conn->secret == NULL || conn->secret_len == 0) {
		if (challresp) {
			log_tunnel(log_warn, conn,
				   "discarding unexpected Challenge Response"
				   " sent by peer\n");
		}
		return 0;
	}

	if (conn->challenge == NULL) {
		log_tunnel(log_error, conn, "impossible to authenticate peer:"
			   " Challenge is unavailable\n");
		return -1;
	}

	if (challresp == NULL) {
		log_tunnel(log_error, conn, "impossible to authenticate peer:"
			   " no Challenge Response sent by peer\n");
		return -1;
	} else if (challresp->length != MD5_DIGEST_LENGTH) {
		log_tunnel(log_error, conn, "impossible to authenticate peer:"
			   " invalid Challenge Response sent by peer"
			   " (inconsistent length: %i bytes)\n",
			   challresp->length);
		return -1;
	}

	comp_chap_md5(challref, msgident, conn->secret, conn->secret_len,
		      conn->challenge, conn->challenge_len);
	if (memcmp(challref, challresp->val.octets, MD5_DIGEST_LENGTH) != 0) {
		log_tunnel(log_error, conn, "impossible to authenticate peer:"
			   " invalid Challenge Response sent by peer"
			   " (wrong secret)\n");
		return -1;
	}

	return 0;
}

static void l2tp_tunnel_clear_recvqueue(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	uint16_t id;

	for (id = 0; id < conn->recv_queue_sz; ++id) {
		pack = conn->recv_queue[id];
		if (pack) {
			l2tp_packet_free(pack);
			conn->recv_queue[id] = NULL;
		}
	}
	conn->recv_queue_offt = 0;
}

static void l2tp_tunnel_clear_sendqueue(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	while (!list_empty(&conn->send_queue)) {
		pack = list_first_entry(&conn->send_queue, typeof(*pack),
					entry);
		if (pack->sess_entry.next)
			list_del(&pack->sess_entry);
		list_del(&pack->entry);
		l2tp_packet_free(pack);
	}
	conn->send_queue_len = 0;
}

static void l2tp_session_clear_sendqueue(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	while (!list_empty(&sess->send_queue)) {
		pack = list_first_entry(&sess->send_queue, typeof(*pack),
					sess_entry);
		list_del(&pack->sess_entry);
		list_del(&pack->entry);
		--sess->paren_conn->send_queue_len;
		l2tp_packet_free(pack);
	}
}

static int __l2tp_tunnel_send(const struct l2tp_conn_t *conn,
			      struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *msg_type;
	void (*log_func)(const char *fmt, ...);

	pack->hdr.Nr = htons(conn->Nr);

	if (conf_verbose) {
		if (l2tp_packet_is_ZLB(pack)) {
			log_func = log_debug;
		} else {
			msg_type = list_first_entry(&pack->attrs,
						    typeof(*msg_type), entry);
			if (msg_type->val.uint16 == Message_Type_Hello)
				log_func = log_debug;
			else
				log_func = log_info2;
		}
		log_tunnel(log_func, conn, "send ");
		l2tp_packet_print(pack, log_func);
	}

	return l2tp_packet_send(conn->hnd.fd, pack);
}

/* Drop acknowledged packets from tunnel's retransmission queue */
static int l2tp_tunnel_clean_rtmsqueue(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	unsigned int pkt_freed = 0;

	while (!list_empty(&conn->rtms_queue)) {
		pack = list_first_entry(&conn->rtms_queue, typeof(*pack),
					entry);
		if (nsnr_cmp(ntohs(pack->hdr.Ns), conn->peer_Nr) >= 0)
			break;

		list_del(&pack->entry);
		l2tp_packet_free(pack);
		++pkt_freed;
	}

	log_tunnel(log_debug, conn, "%u message%s acked by peer\n", pkt_freed,
		   pkt_freed > 1 ? "s" : "");

	if (pkt_freed == 0)
		return 0;

	/* Oldest message from retransmission queue has been acknowledged,
	 * reset retransmission counter and timer.
	 */
	conn->retransmit = 0;

	/* Stop timer if retransmission queue is empty */
	if (list_empty(&conn->rtms_queue)) {
		if (conn->rtimeout_timer.tpd)
			triton_timer_del(&conn->rtimeout_timer);

		return 0;
	}

	/* Some messages haven't been acknowledged yet, restart timer */
	conn->rtimeout_timer.period = conn->rtimeout;
	if (conn->rtimeout_timer.tpd) {
		if (triton_timer_mod(&conn->rtimeout_timer, 0) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to clean retransmission queue:"
				   " updating retransmission timer failed\n");

			return -1;
		}
	} else {
		if (triton_timer_add(&conn->ctx,
				     &conn->rtimeout_timer, 0) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to clean retransmission queue:"
				   " starting retransmission timer failed\n");

			return -1;
		}
	}

	return 0;
}

static int l2tp_tunnel_push_sendqueue(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	uint16_t Nr_max = conn->peer_Nr + conn->peer_rcv_wnd_sz;
	unsigned int pkt_sent = 0;

	while (!list_empty(&conn->send_queue)) {
		pack = list_first_entry(&conn->send_queue, typeof(*pack),
					entry);
		if (nsnr_cmp(conn->Ns, Nr_max) >= 0)
			break;

		pack->hdr.Ns = htons(conn->Ns);

		if (__l2tp_tunnel_send(conn, pack) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to process the send queue:"
				   " sending packet %hu failed\n", conn->Ns);

			return -1;
		}

		if (pack->sess_entry.next) {
			list_del(&pack->sess_entry);
			pack->sess_entry.next = NULL;
			pack->sess_entry.prev = NULL;
		}
		list_move_tail(&pack->entry, &conn->rtms_queue);
		--conn->send_queue_len;
		++conn->Ns;
		++pkt_sent;
	}

	log_tunnel(log_debug, conn, "%u message%s sent from send queue\n",
		   pkt_sent, pkt_sent > 1 ? "s" : "");

	if (pkt_sent == 0) {
		if (!list_empty(&conn->send_queue))
			log_tunnel(log_info2, conn,
				   "no message sent while processing the send queue (%u outstanding messages):"
				   " peer's receive window is full (%hu messages)\n",
				   conn->send_queue_len, conn->peer_rcv_wnd_sz);

		return 0;
	}

	/* At least one message sent, restart retransmission timer if necessary
	 * (timer may be stopped, e.g. because there was no message left in the
	 * retransmission queue).
	 */
	if (conn->rtimeout_timer.tpd == NULL) {
		conn->rtimeout_timer.period = conn->rtimeout;
		if (triton_timer_add(&conn->ctx,
				     &conn->rtimeout_timer, 0) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to process the send queue:"
				   " setting retransmission timer failed\n");

			return -1;
		}
	}

	return 1;
}

static int l2tp_tunnel_send(struct l2tp_conn_t *conn,
			    struct l2tp_packet_t *pack)
{
	if (conn->state == STATE_FIN || conn->state == STATE_FIN_WAIT ||
	    conn->state == STATE_CLOSE) {
		log_tunnel(log_info2, conn,
			   "discarding outgoing message, tunnel is closing\n");
		l2tp_packet_free(pack);

		return -1;
	}

	pack->hdr.tid = htons(conn->peer_tid);
	list_add_tail(&pack->entry, &conn->send_queue);
	++conn->send_queue_len;

	return 0;
}

static int l2tp_session_send(struct l2tp_sess_t *sess,
			     struct l2tp_packet_t *pack)
{
	if (sess->state1 == STATE_CLOSE) {
		log_session(log_info2, sess,
			    "discarding outgoing message,"
			    " session is closing\n");
		l2tp_packet_free(pack);

		return -1;
	}

	pack->hdr.sid = htons(sess->peer_sid);

	if (l2tp_tunnel_send(sess->paren_conn, pack) < 0)
		return -1;

	list_add_tail(&pack->sess_entry, &sess->send_queue);

	return 0;
}

static int l2tp_session_try_send(struct l2tp_sess_t *sess,
				 struct l2tp_packet_t *pack)
{
	if (sess->paren_conn->send_queue_len >= sess->paren_conn->peer_rcv_wnd_sz)
		return -1;

	l2tp_session_send(sess, pack);

	return 0;
}

static int l2tp_send_StopCCN(struct l2tp_conn_t *conn,
			     uint16_t res, uint16_t err)
{
	struct l2tp_packet_t *pack = NULL;
	struct l2tp_avp_result_code rc = {htons(res), htons(err)};

	log_tunnel(log_info2, conn, "sending StopCCN (res: %hu, err: %hu)\n",
		   res, err);

	pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (pack == NULL) {
		log_tunnel(log_error, conn, "impossible to send StopCCN:"
			   " packet allocation failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID,
				  conn->tid, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send StopCCN:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
				   sizeof(rc), 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send StopCCN:"
			   " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_tunnel_send(conn, pack);

	return 0;

out_err:
	if (pack)
		l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_CDN(struct l2tp_sess_t *sess, uint16_t res, uint16_t err)
{
	struct l2tp_packet_t *pack = NULL;
	struct l2tp_avp_result_code rc = {htons(res), htons(err)};

	log_session(log_info2, sess, "sending CDN (res: %hu, err: %hu)\n",
		    res, err);

	pack = l2tp_packet_alloc(2, Message_Type_Call_Disconnect_Notify,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == NULL) {
		log_session(log_error, sess, "impossible to send CDN:"
			    " packet allocation failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send CDN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
				   sizeof(rc), 1) < 0) {
		log_session(log_error, sess, "impossible to send CDN:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	if (pack)
		l2tp_packet_free(pack);
	return -1;
}

static int l2tp_tunnel_send_CDN(uint16_t sid, uint16_t peer_sid,
				uint16_t res, uint16_t err)
{
	struct l2tp_packet_t *pack = NULL;
	struct l2tp_avp_result_code rc = {htons(res), htons(err)};
	struct l2tp_conn_t *conn = l2tp_tunnel_self();

	log_tunnel(log_info2, conn, "sending CDN (res: %hu, err: %hu)\n",
		   res, err);

	pack = l2tp_packet_alloc(2, Message_Type_Call_Disconnect_Notify,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (pack == NULL) {
		log_tunnel(log_error, conn, "impossible to send CDN:"
			   " packet allocation failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, sid, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send CDN:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
				   sizeof(rc), 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send CDN:"
			   " adding data to packet failed\n");
		goto out_err;
	}

	pack->hdr.sid = htons(peer_sid);

	l2tp_tunnel_send(conn, pack);

	return 0;

out_err:
	if (pack)
		l2tp_packet_free(pack);
	return -1;
}

static void l2tp_session_free_ptr(void *ptr)
{
	l2tp_session_free((struct l2tp_sess_t *) ptr);
}

static void l2tp_tunnel_free_sessions(struct l2tp_conn_t *conn)
{
	void *sessions;

	pthread_mutex_lock(&conn->sessions_lock);
	sessions = conn->sessions;
	conn->sessions = NULL;
	pthread_mutex_unlock(&conn->sessions_lock);
	tdestroy(sessions, l2tp_session_free_ptr);
	/* Let l2tp_session_free() handle the session counter and
	 * the reference held by the tunnel.
	 */
}

static int l2tp_tunnel_disconnect(struct l2tp_conn_t *conn,
				  uint16_t res, uint16_t err)
{
	switch (conn->state) {
	case STATE_INIT:
	case STATE_WAIT_SCCRP:
	case STATE_WAIT_SCCCN:
		l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_finishing);
		break;
	case STATE_ESTB:
		l2tp_stat_move(&l2tp_stat.conn_active, &l2tp_stat.conn_finishing);
		break;
	case STATE_FIN:
	case STATE_FIN_WAIT:
	case STATE_CLOSE:
		return 0;
	default:
		log_tunnel(log_error, conn,
			   "impossible to disconnect tunnel:"
			   " invalid state %i\n",
			   conn->state);
		return 0;
	}

	/* Discard unsent messages so that StopCCN will be the only one in the
	 * send queue (to minimise delay in case of congestion).
	 */
	l2tp_tunnel_clear_sendqueue(conn);

	if (l2tp_send_StopCCN(conn, res, err) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to notify peer of tunnel disconnection:"
			   " sending StopCCN failed,"
			   " deleting tunnel anyway\n");

		conn->state = STATE_FIN;
		l2tp_tunnel_free(conn);

		return -1;
	}

	conn->state = STATE_FIN;

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	if (conn->sessions)
		l2tp_tunnel_free_sessions(conn);

	return 0;
}

static int l2tp_tunnel_disconnect_push(struct l2tp_conn_t *conn,
				       uint16_t res, uint16_t err)
{
	if (l2tp_tunnel_disconnect(conn, res, err) < 0)
		return -1;

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to notify peer of tunnel disconnection:"
			   " transmitting messages from send queue failed,"
			   " deleting tunnel anyway\n");
		l2tp_tunnel_free(conn);

		return -1;
	}

	return 0;
}

static void __tunnel_destroy(struct l2tp_conn_t *conn)
{
	pthread_mutex_destroy(&conn->ctx_lock);
	pthread_mutex_destroy(&conn->sessions_lock);

	if (conn->hnd.fd >= 0)
		close(conn->hnd.fd);
	if (conn->challenge)
		_free(conn->challenge);
	if (conn->secret)
		_free(conn->secret);
	if (conn->recv_queue)
		_free(conn->recv_queue);

	log_tunnel(log_info2, conn, "tunnel destroyed\n");

	mempool_free(conn);

	l2tp_stat_dec(&l2tp_stat.conn_finishing);
}

static void tunnel_put(struct l2tp_conn_t *conn)
{
	if (__sync_sub_and_fetch(&conn->ref_count, 1) == 0)
		__tunnel_destroy(conn);
}

static void tunnel_hold(struct l2tp_conn_t *conn)
{
	__sync_add_and_fetch(&conn->ref_count, 1);
}

static void __session_destroy(struct l2tp_sess_t *sess)
{
	struct l2tp_conn_t *conn = sess->paren_conn;

	pthread_mutex_destroy(&sess->apses_lock);

	if (sess->ppp.fd >= 0)
		close(sess->ppp.fd);
	if (sess->ppp.ses.chan_name)
		_free(sess->ppp.ses.chan_name);
	if (sess->ctrl.calling_station_id)
		_free(sess->ctrl.calling_station_id);
	if (sess->ctrl.called_station_id)
		_free(sess->ctrl.called_station_id);
	if (sess->calling_num)
		_free(sess->calling_num);
	if (sess->called_num)
		_free(sess->called_num);

	log_session(log_info2, sess, "session destroyed\n");

	mempool_free(sess);

	l2tp_stat_dec(&l2tp_stat.sess_finishing);

	/* Now that the session is fully destroyed,
	 * drop the reference to the tunnel.
	 */
	tunnel_put(conn);
}

static void session_put(struct l2tp_sess_t *sess)
{
	if (__sync_sub_and_fetch(&sess->ref_count, 1) == 0)
		__session_destroy(sess);
}

static void session_hold(struct l2tp_sess_t *sess)
{
	__sync_add_and_fetch(&sess->ref_count, 1);
}

/* Threading rule for the l2tp-switch pairing state of a session
 * (switch_upstream/switch_downstream, switch_link, switch_avps): the
 * fields are only ever *torn down* on the session's own
 * tunnel context (l2tp_session_free(), l2tp_switch_teardown_peer()), but a
 * pairing is *established* from the other leg's context -- the downstream
 * leg is created and cross-linked to the upstream leg from the downstream
 * tunnel's context. The two sides meet only through the session's state1
 * and the fields below, so every read-modify-write that spans "is this leg
 * still alive" and "link/unlink it to its peer" takes this lock. It is a
 * leaf lock: held only around plain field accesses, never while calling out
 * (no triton calls, no other lock, no free), so it cannot take part in a
 * lock-order cycle. */
static pthread_mutex_t l2tp_switch_pair_lock = PTHREAD_MUTEX_INITIALIZER;

/* Everything an unpaired session was holding, detached under the pair lock so
 * the caller can release it without holding the lock. */
struct l2tp_switch_unpaired {
	struct l2tp_sess_t *peer; /* the leg this one was paired with; the
		pointer hold that justified the link is still owed a
		session_put() by the caller */
	struct l2tp_switch_link_t *link;
	struct l2tp_switch_avps *avps;
};

/* Detaches sess's side of its pairing. With `close_it`, also marks the
 * session STATE_CLOSE in the same critical section, which is what makes
 * l2tp_switch_place_call_on()'s "upstream still alive?" check + pairing
 * atomic with respect to upstream's own teardown. */
static struct l2tp_switch_unpaired l2tp_switch_unpair(struct l2tp_sess_t *sess,
						      int close_it)
{
	struct l2tp_switch_unpaired u;

	pthread_mutex_lock(&l2tp_switch_pair_lock);
	if (close_it)
		sess->state1 = STATE_CLOSE;
	u.peer = sess->switch_downstream ? sess->switch_downstream :
		 sess->switch_upstream;
	u.link = sess->switch_link;
	u.avps = sess->switch_avps;
	sess->switch_downstream = NULL;
	sess->switch_upstream = NULL;
	sess->switch_avps = NULL;
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	return u;
}

static void l2tp_switch_avps_free(struct l2tp_switch_avps *avps)
{
	int i;

	if (!avps)
		return;

	for (i = 0; i < avps->count; i++) {
		/* Proxy-Authen-Response is the cleartext PAP password */
		explicit_bzero(avps->avp[i].val, avps->avp[i].len);
		_free(avps->avp[i].val);
	}
	_free(avps);
}

static void l2tp_session_free(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;
	struct l2tp_switch_unpaired u;
	intptr_t cause = TERM_NAS_REQUEST;
	int res = 1;

	switch (sess->state1) {
	case STATE_INIT:
	case STATE_WAIT_ICRP:
	case STATE_WAIT_ICCN:
	case STATE_WAIT_OCRP:
	case STATE_WAIT_OCCN:
		log_session(log_info2, sess, "deleting session\n");

		l2tp_stat_move(&l2tp_stat.sess_starting, &l2tp_stat.sess_finishing);
		break;
	case STATE_ESTB:
		log_session(log_info2, sess, "deleting session\n");

		triton_event_fire(EV_CTRL_FINISHED, &sess->ppp.ses);
		l2tp_stat_move(&l2tp_stat.sess_active, &l2tp_stat.sess_finishing);

		pthread_mutex_lock(&sess->apses_lock);
		if (sess->apses_ctx.tpd)
			res = triton_context_call(&sess->apses_ctx, apses_stop,
						  (void *)cause);
		pthread_mutex_unlock(&sess->apses_lock);

		if (res < 0)
			log_session(log_error, sess,
				    "impossible to delete data channel:"
				    " call to data channel context failed\n");
		else if (res == 0)
			log_session(log_info2, sess,
				    "deleting data channel\n");
		break;
	case STATE_CLOSE:
		/* Session already removed. Will be freed once its reference
		 * counter drops to 0.
		 */
		return;
	default:
		log_session(log_error, sess,
			    "impossible to delete session: invalid state %i\n",
			    sess->state1);
		return;
	}

	u = l2tp_switch_unpair(sess, 1);
	if (u.link)
		l2tp_switch_link_free(u.link);
	l2tp_switch_avps_free(u.avps);

	if (u.peer) {
		/* Decide, and take the hold that survives the context switch,
		 * BEFORE dropping the pointer hold: if the peer already ran its
		 * own l2tp_session_free(), that pointer hold is the last
		 * reference, and the put below would free the peer under the
		 * state1/paren_conn reads that follow. */
		int cascade = u.peer->state1 != STATE_CLOSE;

		if (cascade)
			session_hold(u.peer);
		session_put(u.peer); /* the hold justified by the pointer
				      * just cleared above -- see the
				      * reference-counting note before
				      * l2tp_switch_link_free() */

		if (cascade) {
			int res = -1;

			/* ctx_lock + ctx.tpd: the hold keeps the peer -- and so
			 * its l2tp_conn_t -- alive across the hop, but not that
			 * tunnel's triton context registered.
			 * l2tp_tunnel_free() NULLs ctx.tpd well before the last
			 * reference drops, and triton_context_call()
			 * dereferences it unchecked. Same guard
			 * l2tp_session_apses_*() already uses for this hop. */
			pthread_mutex_lock(&u.peer->paren_conn->ctx_lock);
			if (u.peer->paren_conn->ctx.tpd)
				res = triton_context_call(&u.peer->paren_conn->ctx,
							  l2tp_switch_teardown_peer,
							  u.peer);
			pthread_mutex_unlock(&u.peer->paren_conn->ctx_lock);
			if (res < 0)
				session_put(u.peer);
		}
	}

	if (sess->timeout_timer.tpd)
		triton_timer_del(&sess->timeout_timer);

	/* Packets in the send queue must not reference the session anymore.
	 * They aren't removed from tunnel's queue because they have to be sent
	 * even though session is getting destroyed (useless messages are
	 * dropped from send queues before calling l2tp_session_free()).
	 */
	while (!list_empty(&sess->send_queue)) {
		pack = list_first_entry(&sess->send_queue, typeof(*pack),
					sess_entry);
		list_del(&pack->sess_entry);
		pack->sess_entry.next = NULL;
		pack->sess_entry.prev = NULL;
	}

	pthread_mutex_lock(&sess->paren_conn->sessions_lock);
	if (sess->paren_conn->sessions) {
		if (!tdelete(sess, &sess->paren_conn->sessions, sess_cmp)) {
			pthread_mutex_unlock(&sess->paren_conn->sessions_lock);
			log_session(log_error, sess,
				    "impossible to delete session:"
				    " session unreachable from its parent tunnel\n");
			return;
		}
	}
	pthread_mutex_unlock(&sess->paren_conn->sessions_lock);
	/* Parent tunnel doesn't hold the session anymore. This is true even
	 * if sess->paren_conn->sessions was NULL (which means that
	 * l2tp_session_free() is being called by tdestroy()).
	 */
	session_put(sess);

	/* An on-demand l2tp-switch target's tunnel is the one kind of tunnel
	 * that deliberately outlives its last session: it closes itself
	 * the configured idle linger later (with this very same
	 * "general request to clear the control connection" result code),
	 * unless another call reuses it first -- which is the whole point,
	 * since re-running SCCRQ per call would trade the peer-driven flap
	 * this mode exists to stop for a self-inflicted one. Every other
	 * tunnel, including a persistent target's, keeps disconnecting the
	 * moment it goes empty. If the linger cannot be armed, this falls
	 * back to that immediate disconnect rather than leaking the tunnel. */
	if (--sess->paren_conn->sess_count == 0 &&
	    l2tp_switch_target_arm_idle_linger(sess->paren_conn->switch_target,
					       sess->paren_conn) < 0) {
		switch (sess->paren_conn->state) {
		case STATE_ESTB:
			log_tunnel(log_info1, sess->paren_conn,
				   "no more session, disconnecting tunnel\n");
			l2tp_tunnel_disconnect_push(sess->paren_conn, 1, 0);
			break;
		case STATE_FIN:
		case STATE_FIN_WAIT:
		case STATE_CLOSE:
			break;
		default:
			log_tunnel(log_warn, sess->paren_conn,
				   "avoiding disconnection of empty tunnel:"
				   " invalid state %i\n",
				   sess->paren_conn->state);
			break;
		}
	}

	/* Only drop the reference the session holds to itself.
	 * Reference to the parent tunnel will be dropped by
	 * __session_destroy().
	 */
	session_put(sess);
}

/* Monotonic milliseconds, same clock triton's own timers run on. triton.h's
 * _time() only offers second granularity, which is too coarse to compare a
 * connect budget's deadline against. */
static uint64_t l2tp_switch_monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Whether a target whose connection attempt just failed (or whose tunnel
 * just went away) should schedule another one. A persistent target always
 * does: its tunnel is meant to be up at all times, with or without calls. An
 * on-demand target only does while calls are actually waiting for it --
 * retrying with an empty queue would defeat the entire point of staying cold
 * until a call needs it, and would keep a permanently-unreachable target
 * hammering its peer forever. */
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

/* Timer rules for the switch code (checked against accel-pppd/triton/timer.c):
 * triton_timer_add() and triton_timer_mod() are safe from any context or
 * thread -- add takes the timer's context lock, mod is only a timerfd_settime()
 * on the kernel fd. What is NOT safe from a foreign context is
 * triton_timer_del() on a timer that may be dispatching, so the target's
 * reconnect/idle/connect-timeout timers all live on the default context and
 * are only ever deleted from their own callback there; other contexts
 * cancel by closing the window (idle_deadline = 0, connect_budget_open)
 * and let the callback retire the timer on its next tick. Every add/del of
 * these is additionally done under target->lock.
 *
 * Arms the shared reconnect cadence (reconnect-interval=, 5s by default), unless it is already armed.
 *
 * The armed/not-armed check has to happen under target->lock, like every
 * other field on the target: this runs from any tunnel's context, while
 * l2tp_switch_target_reconnect_timer() clears ->tpd from the default context
 * and l2tp_switch_on_demand_timeout() cancels the timer outright. Unlocked,
 * two callers can both see NULL and both add -- leaking a timerfd and a
 * context reference -- or one can see a stale non-NULL and skip arming,
 * leaving an on-demand target's queued calls with no further connect attempt
 * at all until their budget expires. */
static void l2tp_switch_target_schedule_retry(struct l2tp_switch_target_t *target)
{
	pthread_mutex_lock(&target->lock);
	if (!target->reconnect_timer.tpd) {
		if (triton_timer_add(NULL, &target->reconnect_timer, 0) < 0)
			log_error("l2tp-switch: target \"%s\": failed to"
				  " schedule reconnect\n", target->name);
	}
	pthread_mutex_unlock(&target->lock);
}

/* Arms -- or pushes out -- the linger after which an on-demand target's
 * tunnel closes itself, having just been left with nothing using it.
 *
 * Returns 0 only if a linger is now pending for `conn` specifically, which
 * is what lets l2tp_session_free() use this as its "leave this tunnel open"
 * test and fall back to its usual immediate disconnect on -1 (wrong mode,
 * `conn` is not this target's tunnel any more, calls are queued waiting for
 * a tunnel, or the timer could not be armed at all). `conn` may be NULL for
 * callers that only know the target and mean "whatever its tunnel is now".
 *
 * Callable from any context: it touches only target-owned state under
 * target->lock, and arming a NULL-context (default context) triton timer is
 * already done this way by l2tp_switch_target_schedule_retry() above and by
 * l2tp_switch_open_connect_budget_locked() further down.
 *
 * Deliberately permissive about "is the target really idle": callers arm
 * where a tunnel has just become callless, and the two authoritative
 * re-checks happen when the timer fires -- target->active on the default
 * context, then conn->sess_count in conn's own context, where it cannot go
 * stale under us. An arm too many costs one no-op timer tick; a missing one
 * would strand a session-less tunnel up indefinitely, which is the exact
 * failure this whole feature exists to avoid. */
static int l2tp_switch_target_arm_idle_linger(struct l2tp_switch_target_t *target,
					      struct l2tp_conn_t *conn)
{
	uint64_t now;
	int res;

	if (!target || target->mode != L2TP_SWITCH_MODE_ON_DEMAND)
		return -1;

	pthread_mutex_lock(&target->lock);

	/* Same identity guard as l2tp_tunnel_free()'s own switch_target hook:
	 * a tunnel that is no longer this target's (an attempt abandoned by
	 * the connect timeout, say) has nothing to do with the target's idle
	 * state and must not be kept alive by its linger. */
	if (!target->tunnel || (conn && target->tunnel != conn))
		goto err;
	if (target->tunnel->state != STATE_ESTB)
		goto err; /* still negotiating or already going away -- the
			   * connect path's business, not the linger's */
	/* An open connect budget means calls are queued waiting for this
	 * target to produce a usable tunnel: it is about to be busy, not
	 * idle, and arming a teardown against the very tunnel they are about
	 * to be placed on would be backwards. */
	if (target->connect_budget_open)
		goto err;

	now = l2tp_switch_monotonic_ms();
	target->idle_timer.expire = l2tp_switch_target_idle_timer;
	target->idle_timer.period = l2tp_switch_conf_idle_linger_ms();

	/* The timer can still be armed from an earlier linger that was
	 * cancelled by a call reusing the tunnel (cancelling only zeroes
	 * idle_deadline -- see the field's own comment) or that fired while
	 * the target was busy. Push it out to a full linger from now rather
	 * than stacking a second registration on top of it, or inheriting
	 * whatever was left of the previous window. Mirrors
	 * l2tp_switch_open_connect_budget_locked() exactly. */
	if (target->idle_timer.tpd)
		res = triton_timer_mod(&target->idle_timer, 0);
	else
		res = triton_timer_add(NULL, &target->idle_timer, 0);

	if (res < 0) {
		log_error("l2tp-switch: target \"%s\": failed to arm idle"
			  " linger\n", target->name);
		goto err;
	}

	/* Read before arming, so the deadline the callback compares against
	 * is never later than the timer's own expiry -- otherwise a genuine
	 * expiry would look like a stale dispatch and cost a whole extra
	 * period. */
	target->idle_deadline = now + l2tp_switch_conf_idle_linger_ms();

	pthread_mutex_unlock(&target->lock);

	return 0;

err:
	pthread_mutex_unlock(&target->lock);

	return -1;
}

static void l2tp_tunnel_free(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	switch (conn->state) {
	case STATE_INIT:
	case STATE_WAIT_SCCRP:
	case STATE_WAIT_SCCCN:
		l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_finishing);
		break;
	case STATE_ESTB:
		l2tp_stat_move(&l2tp_stat.conn_active, &l2tp_stat.conn_finishing);
		break;
	case STATE_FIN:
	case STATE_FIN_WAIT:
		break;
	case STATE_CLOSE:
		/* Tunnel already removed. Will be freed once its reference
		 * counter drops to 0.
		 */
		return;
	default:
		log_tunnel(log_error, conn,
			   "impossible to delete tunnel: invalid state %i\n",
			   conn->state);
		return;
	}

	log_tunnel(log_info2, conn, "deleting tunnel\n");

	conn->state = STATE_CLOSE;

	if (conn->switch_target) {
		struct l2tp_switch_target_t *target = conn->switch_target;

		pthread_mutex_lock(&target->lock);
		/* Only if this is still *the* tunnel for the target: an
		 * on-demand target can briefly have a newer connect attempt
		 * in flight while this one is being torn down (the connect
		 * timeout and the reconnect cadence can both come due at
		 * once), and clearing the pointer unconditionally would show
		 * a live tunnel as down and strand it. */
		if (target->tunnel == conn)
			target->tunnel = NULL;
		pthread_mutex_unlock(&target->lock);

		if (l2tp_switch_target_should_retry(target))
			l2tp_switch_target_schedule_retry(target);
	}

	pthread_mutex_lock(&l2tp_lock);
	l2tp_conn[conn->tid] = NULL;
	pthread_mutex_unlock(&l2tp_lock);

	if (conn->hnd.tpd)
		triton_md_unregister_handler(&conn->hnd, 0);
	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->rtimeout_timer.tpd)
		triton_timer_del(&conn->rtimeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	while (!list_empty(&conn->rtms_queue)) {
		pack = list_first_entry(&conn->rtms_queue, typeof(*pack),
					entry);
		list_del(&pack->entry);
		l2tp_packet_free(pack);
	}
	l2tp_tunnel_clear_sendqueue(conn);

	if (conn->recv_queue)
		l2tp_tunnel_clear_recvqueue(conn);

	if (conn->sessions)
		l2tp_tunnel_free_sessions(conn);

	pthread_mutex_lock(&conn->ctx_lock);
	if (conn->ctx.tpd)
		triton_context_unregister(&conn->ctx);
	pthread_mutex_unlock(&conn->ctx_lock);

	/* Drop the reference the tunnel holds to itself */
	tunnel_put(conn);
}

static void l2tp_session_disconnect(struct l2tp_sess_t *sess,
				    uint16_t res, uint16_t err)
{
	/* Session is closing, unsent messages are now useless */
	l2tp_session_clear_sendqueue(sess);

	if (l2tp_send_CDN(sess, res, err) < 0)
		log_session(log_error, sess,
			    "impossible to notify peer of session disconnection:"
			    " sending CDN failed, deleting session anyway\n");

	l2tp_session_free(sess);
}

static void l2tp_session_disconnect_push(struct l2tp_sess_t *sess,
					 uint16_t res, uint16_t err)
{
	if (l2tp_send_CDN(sess, res, err) < 0)
		log_session(log_error, sess,
			    "impossible to notify peer of session disconnection,"
			    " sending CDN failed, deleting session anyway\n");
	else if (l2tp_tunnel_push_sendqueue(sess->paren_conn) < 0)
		log_session(log_error, sess,
			    "impossible to notify peer of session disconnection:"
			    " transmitting messages from send queue failed,"
			    " deleting session anyway\n");

	l2tp_session_free(sess);
}

static void l2tp_session_apses_finished(void *data)
{
	struct l2tp_conn_t *conn = l2tp_tunnel_self();
	struct l2tp_sess_t *sess;
	intptr_t sid = (intptr_t)data;

	sess = l2tp_tunnel_get_session(conn, sid);
	if (sess == NULL)
		return;

	/* Here, the only valid session state is STATE_ESTB. If the session's
	 * state was STATE_CLOSE (which happens if session gets closed before
	 * l2tp_session_apses_finished() gets scheduled), it wouldn't be found
	 * by l2tp_tunnel_get_session().
	 */
	if (sess->state1 == STATE_ESTB) {
		log_session(log_info1, sess,
			    "data channel closed, disconnecting session\n");
		l2tp_session_disconnect_push(sess, 2, 0);
	} else {
		log_session(log_warn, sess,
			    "avoiding disconnection of session with no data channel:"
			    " invalid state %i\n", sess->state1);
	}
}

static void __apses_destroy(void *data)
{
	struct l2tp_sess_t *sess = data;

	pthread_mutex_lock(&sess->apses_lock);
	triton_context_unregister(&sess->apses_ctx);
	pthread_mutex_unlock(&sess->apses_lock);

	log_ppp_info2("session destroyed\n");

	l2tp_stat_dec(&l2tp_stat.data_finishing);

	/* Drop reference to the L2TP session */
	session_put(sess);
}

static void apses_finished(struct ap_session *apses)
{
	struct l2tp_sess_t *sess = container_of(apses->ctrl, typeof(*sess),
						ctrl);
	intptr_t sid = sess->sid;
	int res = 1;

	switch (sess->apses_state) {
	case APSTATE_STARTING:
		l2tp_stat_move(&l2tp_stat.data_starting, &l2tp_stat.data_finishing);
		break;
	case APSTATE_STARTED:
		l2tp_stat_move(&l2tp_stat.data_active, &l2tp_stat.data_finishing);
		break;
	case APSTATE_FINISHING:
		break;
	default:
		log_ppp_error("impossible to delete session:"
			      " invalid state %i\n",
			      sess->apses_state);
		return;
	}

	sess->apses_state = APSTATE_FINISHING;

	pthread_mutex_lock(&sess->paren_conn->ctx_lock);
	if (sess->paren_conn->ctx.tpd)
		res = triton_context_call(&sess->paren_conn->ctx,
					  l2tp_session_apses_finished,
					  (void *)sid);
	pthread_mutex_unlock(&sess->paren_conn->ctx_lock);
	if (res < 0)
		log_ppp_warn("deleting session without notifying L2TP layer:"
			     " call to L2TP control channel context failed\n");

	/* Don't drop the reference to the session now: session_put() may
	 * destroy the L2TP session, but the caller expects it to remain valid
	 * after we return.
	 */
	if (triton_context_call(&sess->apses_ctx, __apses_destroy, sess) < 0)
		log_ppp_error("impossible to delete session:"
			      " scheduling session destruction failed\n");
}

static void apses_stop(void *data)
{
	struct l2tp_sess_t *sess = container_of(triton_context_self(),
						typeof(*sess), apses_ctx);
	intptr_t cause = (intptr_t)data;

	switch (sess->apses_state) {
	case APSTATE_INIT:
	case APSTATE_STARTING:
		l2tp_stat_move(&l2tp_stat.data_starting, &l2tp_stat.data_finishing);
		break;
	case APSTATE_STARTED:
		l2tp_stat_move(&l2tp_stat.data_active, &l2tp_stat.data_finishing);
		break;
	case APSTATE_FINISHING:
		break;
	default:
		log_ppp_error("impossible to delete session:"
			      " invalid state %i\n",
			      sess->apses_state);
		return;
	}

	if (sess->apses_state == APSTATE_STARTING ||
	    sess->apses_state == APSTATE_STARTED) {
		sess->apses_state = APSTATE_FINISHING;
		ap_session_terminate(&sess->ppp.ses, cause, 1);
	} else {
		intptr_t sid = sess->sid;
		int res = 1;

		pthread_mutex_lock(&sess->paren_conn->ctx_lock);
		if (sess->paren_conn->ctx.tpd)
			res = triton_context_call(&sess->paren_conn->ctx,
						  l2tp_session_apses_finished,
						  (void *)sid);
		pthread_mutex_unlock(&sess->paren_conn->ctx_lock);
		if (res < 0)
			log_ppp_warn("deleting session without notifying L2TP layer:"
				     " call to L2TP control channel context failed\n");
	}

	/* Execution of __apses_destroy() may have been scheduled by
	 * ap_session_terminate() (via apses_finished()). We can
	 * nevertheless call __apses_destroy() synchronously here,
	 * so that the data channel gets destroyed without uselessly
	 * waiting for scheduling.
	 */
	__apses_destroy(sess);
}

static void apses_ctx_stop(struct triton_context_t *ctx)
{
	intptr_t cause = TERM_ADMIN_RESET;

	log_ppp_info1("context thread is closing, disconnecting session\n");
	apses_stop((void *)cause);
}

static void apses_started(struct ap_session *apses)
{
	struct l2tp_sess_t *sess = container_of(apses->ctrl, typeof(*sess),
						ctrl);

	if (sess->apses_state != APSTATE_STARTING) {
		log_ppp_error("impossible to activate session:"
			      " invalid state %i\n",
			      sess->apses_state);
		return;
	}

	l2tp_stat_move(&l2tp_stat.data_starting, &l2tp_stat.data_active);
	sess->apses_state = APSTATE_STARTED;

	log_ppp_info1("session started over l2tp session %hu-%hu, %hu-%hu\n",
		      sess->paren_conn->tid, sess->paren_conn->peer_tid,
		      sess->sid, sess->peer_sid);
}

static void apses_start(void *data)
{
	struct ap_session *apses = data;
	struct l2tp_sess_t *sess = container_of(apses->ctrl, typeof(*sess),
						ctrl);

	if (sess->apses_state != APSTATE_INIT) {
		log_ppp_error("impossible to start session:"
			      " invalid state %i\n",
			      sess->apses_state);
		return;
	}

	log_ppp_info2("starting data channel for l2tp(%s)\n",
		      apses->chan_name);

	if (establish_ppp(&sess->ppp) < 0) {
		intptr_t cause = TERM_NAS_ERROR;

		log_ppp_error("session startup failed,"
			      " disconnecting session\n");
		apses_stop((void *)cause);
	} else
		sess->apses_state = APSTATE_STARTING;
}

static void l2tp_session_timeout(struct triton_timer_t *t)
{
	struct l2tp_sess_t *sess = container_of(t, typeof(*sess),
						timeout_timer);

	triton_timer_del(t);
	log_session(log_info1, sess, "session establishment timeout,"
		    " disconnecting session\n");
	l2tp_session_disconnect_push(sess, 10, 0);
}

static struct l2tp_sess_t *l2tp_tunnel_new_session(struct l2tp_conn_t *conn)
{
	struct l2tp_sess_t *sess = NULL;
	struct l2tp_sess_t **sess_search = NULL;
	ssize_t rdlen = 0;
	uint16_t count;

	sess = mempool_alloc(l2tp_sess_pool);
	if (sess == NULL) {
		log_tunnel(log_error, conn,
			   "impossible to allocate new session:"
			   " memory allocation failed\n");
		goto out_err;
	}
	memset(sess, 0, sizeof(*sess));

	for (count = UINT16_MAX; count > 0; --count) {
		rdlen = read(urandom_fd, &sess->sid, sizeof(sess->sid));
		if (rdlen != sizeof(sess->sid)) {
			log_tunnel(log_error, conn,
				   "impossible to allocate new session:"
				   " reading from urandom failed: %s\n",
				   (rdlen < 0) ? strerror(errno) : "short read");
			goto out_err;
		}

		if (sess->sid == 0)
			continue;

		pthread_mutex_lock(&conn->sessions_lock);
		sess_search = tsearch(sess, &conn->sessions, sess_cmp);
		pthread_mutex_unlock(&conn->sessions_lock);
		if (*sess_search != sess)
			continue;

		break;
	}

	if (count == 0) {
		log_tunnel(log_error, conn,
			   "impossible to allocate new session:"
			   " could not find any unused session ID\n");
		goto out_err;
	}

	++conn->sess_count;

	return sess;

out_err:
	if (sess)
		mempool_free(sess);
	return NULL;
}

static struct l2tp_sess_t *l2tp_tunnel_alloc_session(struct l2tp_conn_t *conn)
{
	struct l2tp_sess_t *sess = NULL;

	sess = l2tp_tunnel_new_session(conn);
	if (sess == NULL)
		return NULL;

	sess->paren_conn = conn;
	sess->peer_sid = 0;
	sess->state1 = STATE_INIT;
	sess->lns_mode = conn->lns_mode;
	sess->hide_avps = conn->hide_avps;
	sess->send_seq = (conf_dataseq == L2TP_DATASEQ_PREFER) ||
			 (conf_dataseq == L2TP_DATASEQ_REQUIRE);
	sess->recv_seq = (conf_dataseq == L2TP_DATASEQ_REQUIRE);
	sess->reorder_timeout = conf_reorder_timeout;
	INIT_LIST_HEAD(&sess->send_queue);
	INIT_LIST_HEAD(&sess->switch_pending_entry);

	sess->timeout_timer.expire = l2tp_session_timeout;
	sess->timeout_timer.period = conf_timeout * 1000;

	pthread_mutex_init(&sess->apses_lock, NULL);
	ppp_init(&sess->ppp);

	/* The tunnel holds a reference to the session */
	session_hold(sess);
	/* The session holds a reference to the tunnel and to itself */
	tunnel_hold(conn);
	session_hold(sess);

	l2tp_stat_inc(&l2tp_stat.sess_starting);

	return sess;
}

static void l2tp_conn_close(struct triton_context_t *ctx)
{
	struct l2tp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	log_tunnel(log_info1, conn, "context thread is closing,"
		   " disconnecting tunnel\n");
	l2tp_tunnel_disconnect_push(conn, 0, 0);
}

static int l2tp_tunnel_start(struct l2tp_conn_t *conn,
			     triton_event_func start_func,
			     void *start_param)
{
	if (triton_context_register(&conn->ctx, NULL) < 0) {
		log_error("l2tp: impossible to start new tunnel:"
			  " context registration failed\n");
		goto err;
	}
	triton_md_register_handler(&conn->ctx, &conn->hnd);
	if (triton_md_enable_handler(&conn->hnd, MD_MODE_READ) < 0) {
		log_error("l2tp: impossible to start new tunnel:"
			  " enabling handler failed\n");
		goto err_ctx;
	}
	triton_context_wakeup(&conn->ctx);
	if (triton_timer_add(&conn->ctx, &conn->timeout_timer, 0) < 0) {
		log_error("l2tp: impossible to start new tunnel:"
			  " setting tunnel establishment timer failed\n");
		goto err_ctx_md;
	}
	if (triton_context_call(&conn->ctx, start_func, start_param) < 0) {
		log_error("l2tp: impossible to start new tunnel:"
			  " call to tunnel context failed\n");
		goto err_ctx_md_timer;
	}

	return 0;

err_ctx_md_timer:
	triton_timer_del(&conn->timeout_timer);
err_ctx_md:
	triton_md_unregister_handler(&conn->hnd, 0);
err_ctx:
	triton_context_unregister(&conn->ctx);
err:
	return -1;
}

static struct l2tp_conn_t *l2tp_tunnel_alloc(const struct sockaddr_in *peer,
					     const struct sockaddr_in *host,
					     uint32_t framing_cap,
					     int lns_mode, int port_set,
					     int hide_avps)
{
	struct l2tp_conn_t *conn;
	socklen_t hostaddrlen = sizeof(conn->host_addr);
	uint16_t count;
	ssize_t rdlen;
	int flag;

	conn = mempool_alloc(l2tp_conn_pool);
	if (!conn) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " memory allocation failed\n");
		goto err;
	}

	memset(conn, 0, sizeof(*conn));
	pthread_mutex_init(&conn->ctx_lock, NULL);
	pthread_mutex_init(&conn->sessions_lock, NULL);
	INIT_LIST_HEAD(&conn->send_queue);
	INIT_LIST_HEAD(&conn->rtms_queue);

	conn->hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (conn->hnd.fd < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " socket(PF_INET) failed: %s\n", strerror(errno));
		goto err_conn;
	}

	flag = fcntl(conn->hnd.fd, F_GETFD);
	if (flag < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " fcntl(F_GETFD) failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}
	flag = fcntl(conn->hnd.fd, F_SETFD, flag | FD_CLOEXEC);
	if (flag < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " fcntl(F_SETFD) failed: %s\n",
			  strerror(errno));
		goto err_conn_fd;
	}

	flag = 1;
	if (setsockopt(conn->hnd.fd, SOL_SOCKET, SO_REUSEADDR,
		       &flag, sizeof(flag)) < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " setsockopt(SO_REUSEADDR) failed: %s\n",
			  strerror(errno));
		goto err_conn_fd;
	}
	if (bind(conn->hnd.fd, (struct sockaddr*)host, sizeof(*host))) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " bind() failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}

	memcpy(&conn->peer_addr, peer, sizeof(*peer));
	if (!port_set)
		/* 'peer.sin_port' is set to a default destination port but the
		   source port that will be used by the peer isn't known yet */
		conn->peer_addr.sin_port = 0;
	if (connect(conn->hnd.fd, (struct sockaddr *)&conn->peer_addr,
		    sizeof(conn->peer_addr))) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " connect() failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}
	if (!port_set)
		conn->peer_addr.sin_port = peer->sin_port;

	flag = fcntl(conn->hnd.fd, F_GETFL);
	if (flag < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " fcntl(F_GETFL) failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}
	flag = fcntl(conn->hnd.fd, F_SETFL, flag | O_NONBLOCK);
	if (flag < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " fcntl(F_SETFL) failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}

	if (getsockname(conn->hnd.fd, (struct sockaddr*)&conn->host_addr, &hostaddrlen) < 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " getsockname() failed: %s\n", strerror(errno));
		goto err_conn_fd;
	}
	if (hostaddrlen != sizeof(conn->host_addr)) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " inconsistent address length returned by"
			  " getsockname(): %i bytes instead of %zu\n",
			  hostaddrlen, sizeof(conn->host_addr));
		goto err_conn_fd;
	}

	conn->recv_queue_sz = conf_recv_window;
	conn->recv_queue = _malloc(conn->recv_queue_sz *
				   sizeof(*conn->recv_queue));
	if (conn->recv_queue == NULL) {
		log_error("l2tp: impossible to allocate new tunnel:"
			  " allocating reception queue (%zu bytes) failed\n",
			  conn->recv_queue_sz * sizeof(*conn->recv_queue));
		goto err_conn_fd;
	}
	memset(conn->recv_queue, 0,
	       conn->recv_queue_sz * sizeof(*conn->recv_queue));
	conn->recv_queue_offt = 0;

	for (count = UINT16_MAX; count > 0; --count) {
		rdlen = read(urandom_fd, &conn->tid, sizeof(conn->tid));
		if (rdlen != sizeof(conn->tid)) {
			log_error("l2tp: impossible to allocate new tunnel:"
				  " reading from urandom failed: %s\n",
				  (rdlen < 0) ? strerror(errno) : "short read");
			goto err_conn_fd_queue;
		}

		if (conn->tid == 0)
			continue;

		pthread_mutex_lock(&l2tp_lock);
		if (l2tp_conn[conn->tid]) {
			pthread_mutex_unlock(&l2tp_lock);
			continue;
		}
		l2tp_conn[conn->tid] = conn;
		pthread_mutex_unlock(&l2tp_lock);

		break;
	}

	if (count == 0) {
		log_error("l2tp: impossible to allocate new tunnel:"
			   " could not find any unused tunnel ID\n");
		goto err_conn_fd_queue;
	}

	conn->state = STATE_INIT;
	conn->framing_cap = framing_cap;

	conn->ctx.before_switch = l2tp_ctx_switch;
	conn->ctx.close = l2tp_conn_close;
	conn->hnd.read = l2tp_conn_read;
	conn->timeout_timer.expire = l2tp_tunnel_timeout;
	conn->timeout_timer.period = conf_timeout * 1000;
	conn->rtimeout_timer.expire = l2tp_rtimeout;
	conn->rtimeout_timer.period = conf_rtimeout * 1000;
	conn->hello_timer.expire = l2tp_send_HELLO;
	conn->hello_timer.period = conf_hello_interval * 1000;

	conn->rtimeout = conf_rtimeout * 1000;
	conn->rtimeout_cap = conf_rtimeout_cap * 1000;
	conn->max_retransmit = conf_retransmit;

	conn->sessions = NULL;
	conn->sess_count = 0;
	conn->lns_mode = lns_mode;
	conn->port_set = port_set;
	conn->hide_avps = hide_avps;
	conn->peer_rcv_wnd_sz = DEFAULT_PEER_RECV_WINDOW_SIZE;
	tunnel_hold(conn);

	l2tp_stat_inc(&l2tp_stat.conn_starting);

	return conn;

err_conn_fd_queue:
	_free(conn->recv_queue);
err_conn_fd:
	close(conn->hnd.fd);
err_conn:
	mempool_free(conn);
err:
	return NULL;
}

static void l2tp_switch_target_connect(struct l2tp_switch_target_t *target)
{
	struct sockaddr_in host = {
		.sin_family = AF_INET,
		.sin_addr = { htonl(INADDR_ANY) },
	};
	struct l2tp_conn_t *conn;
	int taken;

	if (ap_shutdown)
		return;

	/* One attempt at a time, always. target->tunnel doubles as that
	 * exclusion: a non-NULL value means an attempt is either still
	 * negotiating or has already succeeded, and starting a second one
	 * would leave whichever tunnel loses the race live but unreferenced,
	 * with nothing to ever reap it -- and with queued calls potentially
	 * being placed on one tunnel from the other's context. */
	pthread_mutex_lock(&target->lock);
	taken = target->tunnel != NULL;
	pthread_mutex_unlock(&target->lock);
	if (taken)
		return;

	conn = l2tp_tunnel_alloc(&target->peer_addr, &host, 3, 0, 0,
				 conf_hide_avps);
	if (conn == NULL) {
		log_error("l2tp-switch: target \"%s\": tunnel allocation"
			  " failed, retrying in %ds\n", target->name,
			  l2tp_switch_conf_reconnect_interval_ms() / 1000);
		goto retry;
	}

	conn->secret = _strdup(target->secret);
	if (conn->secret == NULL) {
		log_error("l2tp-switch: target \"%s\": secret allocation"
			  " failed\n", target->name);
		l2tp_tunnel_free(conn);
		goto retry;
	}
	conn->secret_len = target->secret_len;

	/* Publish before starting, not after: l2tp_tunnel_start() registers
	 * conn's context, wakes it and sends the SCCRQ from it, so a peer
	 * that answers fast enough can drive l2tp_tunnel_connect() -- and
	 * with it the queued-call drain -- before this function would have
	 * got around to storing the pointer. Draining with target->tunnel
	 * still NULL disconnects every queued call on a connect that in fact
	 * succeeded. Re-checked under the lock, so an attempt that won the
	 * slot in the window since the check above is never overwritten. */
	pthread_mutex_lock(&target->lock);
	if (target->tunnel) {
		pthread_mutex_unlock(&target->lock);
		l2tp_tunnel_free(conn); /* conn->switch_target deliberately
					 * still unset: this tunnel never
					 * belonged to the target, so its
					 * teardown must not touch it */
		return;
	}
	conn->switch_target = target;
	target->tunnel = conn;
	pthread_mutex_unlock(&target->lock);

	if (l2tp_tunnel_start(conn, l2tp_send_SCCRQ, &target->peer_addr) < 0) {
		log_error("l2tp-switch: target \"%s\": starting tunnel"
			  " failed, retrying in %ds\n", target->name,
			  l2tp_switch_conf_reconnect_interval_ms() / 1000);
		pthread_mutex_lock(&target->lock);
		if (target->tunnel == conn) /* same identity guard as
					     * l2tp_tunnel_free()'s hook: never
					     * blank out another attempt's
					     * pointer */
			target->tunnel = NULL;
		pthread_mutex_unlock(&target->lock);
		l2tp_tunnel_free(conn);
		goto retry;
	}

	return;

retry:
	if (l2tp_switch_target_should_retry(target))
		l2tp_switch_target_schedule_retry(target);
}

static void l2tp_switch_target_reconnect_timer(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), reconnect_timer);

	pthread_mutex_lock(&target->lock);
	if (target->reconnect_timer.tpd)
		triton_timer_del(t);
	pthread_mutex_unlock(&target->lock);

	/* Re-checked here, not just where the cadence is armed: by the time a
	 * tick comes due, an on-demand target's queued calls may already have
	 * been placed or given up on, and reconnecting a target nothing is
	 * waiting for is exactly what on-demand mode exists to avoid. */
	if (!l2tp_switch_target_should_retry(target))
		return;

	l2tp_switch_target_connect(target);
}

static void l2tp_switch_targets_connect(void)
{
	struct l2tp_switch_target_t *target;

	list_for_each_entry(target, &l2tp_switch_targets, entry) {
		target->reconnect_timer.expire =
			l2tp_switch_target_reconnect_timer;
		target->reconnect_timer.period =
			l2tp_switch_conf_reconnect_interval_ms();
		if (target->mode == L2TP_SWITCH_MODE_PERSISTENT)
			l2tp_switch_target_connect(target);
	}
}

static inline int l2tp_tunnel_update_peerport(struct l2tp_conn_t *conn,
					      uint16_t port_nbo)
{
	in_port_t old_port = conn->peer_addr.sin_port;
	int res;

	conn->peer_addr.sin_port = port_nbo;
	res = connect(conn->hnd.fd, (struct sockaddr*)&conn->peer_addr, sizeof(conn->peer_addr));
	if (res < 0) {
		log_tunnel(log_error, conn,
			   "impossible to update peer port from %hu to %hu:"
			   " connect() failed: %s\n",
			   ntohs(old_port), ntohs(port_nbo), strerror(errno));
		conn->peer_addr.sin_port = old_port;
	}

	return res;
}

static int l2tp_session_start_data_channel(struct l2tp_sess_t *sess)
{
	sess->apses_ctx.before_switch = l2tp_ctx_switch;
	sess->apses_ctx.close = apses_ctx_stop;

	sess->ctrl.ctx = &sess->apses_ctx;
	sess->ctrl.type = CTRL_TYPE_L2TP;
	sess->ctrl.ppp = 1;
	sess->ctrl.name = "l2tp";
	sess->ctrl.ifname = "";
	sess->ctrl.started = apses_started;
	sess->ctrl.finished = apses_finished;
	sess->ctrl.terminate = ppp_terminate;
	sess->ctrl.max_mtu = conf_ppp_max_mtu;
	sess->ctrl.mppe = conf_mppe;

	/* If l2tp calling number avp exists, we use it, otherwise we use lac ip */
	if (sess->calling_num != NULL) {
		sess->ctrl.calling_station_id = _malloc(sess->calling_num_len+1);
		if (sess->ctrl.calling_station_id == NULL) {
			log_session(log_error, sess,
				    "impossible to start data channel:"
				    " allocation of calling station ID failed\n");
			goto err;
		}else {
			strcpy(sess->ctrl.calling_station_id, sess->calling_num);
		}
	} else {
		sess->ctrl.calling_station_id = _malloc(17);
		if (sess->ctrl.calling_station_id == NULL) {
			log_session(log_error, sess,
				"impossible to start data channel:"
				" allocation of calling station ID failed\n");
			goto err;
		} else {
			u_inet_ntoa(sess->paren_conn->peer_addr.sin_addr.s_addr,
				sess->ctrl.calling_station_id);
		}
	}
	/* If l2tp called number avp exists, we use it, otherwise we use my ip */
	if (sess->called_num != NULL) {
		sess->ctrl.called_station_id = _malloc(sess->called_num_len+1);
		if (sess->ctrl.called_station_id == NULL) {
			log_session(log_error, sess,
				    "impossible to start data channel:"
				    " allocation of called station ID failed\n");
			goto err;
		} else {
			strcpy(sess->ctrl.called_station_id, sess->called_num);
		}
	} else {
		sess->ctrl.called_station_id = _malloc(17);
		if (sess->ctrl.called_station_id == NULL) {
			log_session(log_error, sess,
				"impossible to start data channel:"
				" allocation of called station ID failed\n");
			goto err;
		} else {
			u_inet_ntoa(sess->paren_conn->host_addr.sin_addr.s_addr,
				sess->ctrl.called_station_id);
		}
	}

	if (conf_ip_pool) {
		sess->ppp.ses.ipv4_pool_name = _strdup(conf_ip_pool);
		if (sess->ppp.ses.ipv4_pool_name == NULL) {
		err_pool:
			log_session(log_error, sess,
				    "impossible to start data channel:"
				    " allocation of pool name failed\n");
			goto err;
		}
	}
	if (conf_ipv6_pool) {
		sess->ppp.ses.ipv6_pool_name = _strdup(conf_ipv6_pool);
		if (sess->ppp.ses.ipv6_pool_name == NULL)
			goto err_pool;
	}
	if (conf_dpv6_pool) {
		sess->ppp.ses.dpv6_pool_name = _strdup(conf_dpv6_pool);
		if (sess->ppp.ses.dpv6_pool_name == NULL)
			goto err_pool;
	}
	if (conf_ifname)
		sess->ppp.ses.ifname_rename = _strdup(conf_ifname);

	if (conf_session_timeout)
		sess->ppp.ses.session_timeout = conf_session_timeout;

	sess->ppp.ses.ctrl = &sess->ctrl;
	sess->apses_state = APSTATE_INIT;

	/* The data channel holds a reference to the control session */
	session_hold(sess);

	if (triton_context_register(&sess->apses_ctx, &sess->ppp.ses) < 0) {
		log_session(log_error, sess,
			    "impossible to start data channel:"
			    " context registration failed\n");
		goto err_put;
	}

	triton_context_wakeup(&sess->apses_ctx);

	if (triton_context_call(&sess->apses_ctx, apses_start,
				&sess->ppp.ses) < 0) {
		log_session(log_error, sess,
			    "impossible to start data channel:"
			    " call to data channel context failed\n");
		goto err_put_ctx;
	}

	l2tp_stat_inc(&l2tp_stat.data_starting);

	return 0;

err_put_ctx:
	triton_context_unregister(&sess->apses_ctx);
err_put:
	session_put(sess);
err:
	if (sess->ppp.ses.ipv4_pool_name) {
		_free(sess->ppp.ses.ipv4_pool_name);
		sess->ppp.ses.ipv4_pool_name = NULL;
	}
	if (sess->ppp.ses.ipv6_pool_name) {
		_free(sess->ppp.ses.ipv6_pool_name);
		sess->ppp.ses.ipv6_pool_name = NULL;
	}
	if (sess->ppp.ses.dpv6_pool_name) {
		_free(sess->ppp.ses.dpv6_pool_name);
		sess->ppp.ses.dpv6_pool_name = NULL;
	}
	if (sess->ctrl.called_station_id) {
		_free(sess->ctrl.called_station_id);
		sess->ctrl.called_station_id = NULL;
	}
	if (sess->ctrl.calling_station_id) {
		_free(sess->ctrl.calling_station_id);
		sess->ctrl.calling_station_id = NULL;
	}

	return -1;
}

/* Larger than the typical net.core.rmem_max/wmem_max default (208 KiB on
 * most distros) on purpose: switch-mode sessions read and write this
 * socket directly via splice() in userspace (see l2tp_switch_link_read()),
 * unlike a normal session's kernel-to-kernel PPPIOCATTCHAN path, so a
 * short burst has to fit in this buffer or it's lost (read side) or
 * fails outright with ENOMEM (write side, handled as retryable -- see
 * l2tp_switch_link_read()). Sized to comfortably absorb the largest
 * burst confirmed lossless during testing (~100 back-to-back 1400-byte
 * datagrams, ~140 KiB) with real headroom on top, without being so large
 * it hides a genuinely sustained overload for long enough to matter. This
 * only raises how much of a *momentary* burst survives -- it cannot raise
 * a rate ceiling enforced by the network path itself (confirmed via a
 * real two-VM test: throughput scaled with UDP payload size while both
 * hosts' CPUs stayed idle, the signature of a packets-per-second policer
 * outside either host, not a buffering problem -- see
 * docs/l2tp_switching.md's "Operational constraints" for the full
 * diagnostic). */
#define L2TP_SWITCH_SOCKBUF_SIZE (4 * 1024 * 1024)

/* SO_RCVBUFFORCE/SO_SNDBUFFORCE (root/CAP_NET_ADMIN, which accel-ppp already
 * needs for pppol2tp itself) bypass net.core.rmem_max/wmem_max, which
 * otherwise silently clamp a plain SO_RCVBUF/SO_SNDBUF request down to
 * whatever the system default happens to be (208 KiB on most distros) --
 * exactly the ceiling this sizing is meant to raise. Fall back to the
 * plain (clamped) option if FORCE isn't permitted for some reason (e.g.
 * running under reduced capabilities); either way this is a best-effort
 * optimization, not a correctness requirement, so a failure here only
 * logs and never blocks session setup. */
static void l2tp_switch_set_sockbuf(struct l2tp_sess_t *sess, int fd)
{
	int size = L2TP_SWITCH_SOCKBUF_SIZE;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) < 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
		log_session(log_warn, sess,
			    "l2tp-switch: setsockopt(SO_RCVBUF) failed: %s\n",
			    strerror(errno));

	size = L2TP_SWITCH_SOCKBUF_SIZE;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &size, sizeof(size)) < 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) < 0)
		log_session(log_warn, sess,
			    "l2tp-switch: setsockopt(SO_SNDBUF) failed: %s\n",
			    strerror(errno));
}

static int l2tp_session_connect_socket(struct l2tp_sess_t *sess, int start_ppp)
{
	struct sockaddr_pppol2tp pppox_addr;
	struct l2tp_conn_t *conn = sess->paren_conn;
	int lns_mode = sess->lns_mode;
	int flg;
	uint16_t peer_port;
	char addr[17];

	if (sess->timeout_timer.tpd)
		triton_timer_del(&sess->timeout_timer);

	sess->ppp.fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (sess->ppp.fd < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " socket(AF_PPPOX) failed: %s\n", strerror(errno));
		goto out_err;
	}

	flg = fcntl(sess->ppp.fd, F_GETFD);
	if (flg < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " fcntl(F_GETFD) failed: %s\n", strerror(errno));
		goto out_err;
	}
	flg = fcntl(sess->ppp.fd, F_SETFD, flg | FD_CLOEXEC);
	if (flg < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " fcntl(F_SETFD) failed: %s\n", strerror(errno));
		goto out_err;
	}

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = conn->hnd.fd;
	memcpy(&pppox_addr.pppol2tp.addr, &conn->peer_addr,
	       sizeof(conn->peer_addr));
	pppox_addr.pppol2tp.s_tunnel = conn->tid;
	pppox_addr.pppol2tp.d_tunnel = conn->peer_tid;
	pppox_addr.pppol2tp.s_session = sess->sid;
	pppox_addr.pppol2tp.d_session = sess->peer_sid;

	if (connect(sess->ppp.fd,
		    (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " connect() failed: %s\n", strerror(errno));
		goto out_err;
	}

	/* start_ppp==0 sessions (l2tp-switch) read/write this socket
	 * directly via splice() in l2tp_switch_link_read() -- unlike the
	 * normal (start_ppp==1) path, where this fd is handed off to the
	 * kernel's generic PPP channel via PPPIOCATTCHAN and userspace
	 * never touches it again, so it has never needed O_NONBLOCK.
	 * Without this, splice()'s read side blocks forever once the
	 * currently pending datagram(s) are drained (SPLICE_F_NONBLOCK
	 * only avoids blocking on the pipe end, not on a blocking-mode
	 * socket on the other end), permanently consuming one of triton's
	 * worker threads per active switched session and, once thread-count
	 * many sessions are up, starving every other triton context
	 * (including the CLI) -- confirmed on a real VM via gdb thread
	 * dump showing both worker threads stuck inside splice(). */
	if (!start_ppp) {
		flg = fcntl(sess->ppp.fd, F_GETFL);
		if (flg < 0) {
			log_session(log_error, sess,
				    "impossible to connect session:"
				    " fcntl(F_GETFL) failed: %s\n",
				    strerror(errno));
			goto out_err;
		}
		if (fcntl(sess->ppp.fd, F_SETFL, flg | O_NONBLOCK) < 0) {
			log_session(log_error, sess,
				    "impossible to connect session:"
				    " fcntl(F_SETFL) failed: %s\n",
				    strerror(errno));
			goto out_err;
		}

		l2tp_switch_set_sockbuf(sess, sess->ppp.fd);
	}

	if (setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE,
		       &lns_mode, sizeof(lns_mode))) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setsockopt(PPPOL2TP_SO_LNSMODE) failed: %s\n",
			    strerror(errno));
		goto out_err;
	}

	flg = 1;
	if (sess->send_seq &&
	    setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_SENDSEQ,
		       &flg, sizeof(flg))) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setsockopt(PPPOL2TP_SO_SENDSEQ) failed: %s\n",
			    strerror(errno));
		goto out_err;
	}
	if (sess->recv_seq &&
	    setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_RECVSEQ,
		       &flg, sizeof(flg))) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setsockopt(PPPOL2TP_SO_RECVSEQ) failed: %s\n",
			    strerror(errno));
		goto out_err;
	}
	if (sess->reorder_timeout &&
	    setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_REORDERTO,
		       &sess->reorder_timeout, sizeof(sess->reorder_timeout))) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setsockopt(PPPOL2TP_REORDERTO) failed: %s\n",
			    strerror(errno));
		goto out_err;
	}

	u_inet_ntoa(conn->peer_addr.sin_addr.s_addr, addr);
	peer_port = ntohs(conn->peer_addr.sin_port);
	if (_asprintf(&sess->ppp.ses.chan_name,
		      "%s:%hu session %hu-%hu, %hu-%hu",
		      addr, peer_port,
		      sess->paren_conn->tid, sess->paren_conn->peer_tid,
		      sess->sid, sess->peer_sid) < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " setting session's channel name failed\n");
		goto out_err;
	}

	triton_event_fire(EV_CTRL_STARTED, &sess->ppp.ses);
	l2tp_stat_move(&l2tp_stat.sess_starting, &l2tp_stat.sess_active);
	sess->state1 = STATE_ESTB;

	if (start_ppp && l2tp_session_start_data_channel(sess) < 0) {
		log_session(log_error, sess, "impossible to connect session:"
			    " starting data channel failed\n");
		goto out_err;
	}

	return 0;

out_err:
	if (sess->ppp.ses.chan_name) {
		_free(sess->ppp.ses.chan_name);
		sess->ppp.ses.chan_name = NULL;
	}
	if (sess->ppp.fd >= 0) {
		close(sess->ppp.fd);
		sess->ppp.fd = -1;
	}
	return -1;
}

static int l2tp_session_connect(struct l2tp_sess_t *sess)
{
	return l2tp_session_connect_socket(sess, 1);
}

/* Hands every call that queued up while this target's tunnel was connecting
 * to the tunnel that has just come up.
 *
 * Runs inside conn->ctx (reached from l2tp_recv_SCCRP/l2tp_recv_SCCCN, both
 * message handlers on this tunnel's own context, and from
 * l2tp_switch_abort_stalled_tunnel(), a scheduled call on that same context),
 * so the queued calls can be placed with a *direct* call to
 * l2tp_switch_place_call_on() -- no triton_context_call() hop, and no extra
 * guard for a queued upstream session having died while it waited: that
 * function's own STATE_CLOSE check already handles it, releasing the hold
 * taken when the call was queued.
 *
 * Deliberately does NOT cancel connect_timeout_timer, even though this
 * closes the budget that timer bounds: the timer belongs to the default
 * context, and deleting it from here (a tunnel context) races triton's own
 * dispatch. It is left to fire and retire itself instead -- see
 * l2tp_switch_on_demand_timeout(), which no-ops on a closed budget. */
static void l2tp_switch_drain_pending_calls(struct l2tp_conn_t *conn)
{
	struct l2tp_switch_target_t *target = conn->switch_target;
	LIST_HEAD(drained);
	struct l2tp_sess_t *sess;

	pthread_mutex_lock(&target->lock);
	if (target->tunnel != conn) {
		/* Not (or no longer) this target's tunnel: the queue belongs
		 * to whichever attempt currently owns the target, and placing
		 * its calls here would mean driving that other tunnel from
		 * this one's context. Leave them queued; their own budget
		 * still bounds the wait. */
		pthread_mutex_unlock(&target->lock);
		return;
	}
	target->connect_budget_open = 0;
	list_splice_init(&target->pending_calls, &drained);
	target->pending_count = 0;
	pthread_mutex_unlock(&target->lock);

	while (!list_empty(&drained)) {
		sess = list_first_entry(&drained, typeof(*sess),
					switch_pending_entry);
		list_del(&sess->switch_pending_entry);
		l2tp_switch_place_call_on(sess, conn);
	}

	/* Nothing left to place -- every queued call was given up on by the
	 * connect timeout in the instant before this tunnel finished coming
	 * up. It is a perfectly good tunnel that a later call can reuse, so
	 * it is not an error, but nothing will ever call l2tp_session_free()
	 * on it either: start its idle linger so it closes itself instead of
	 * waiting for the peer to do it. (Calls that *were* placed and then
	 * failed do the same from l2tp_switch_place_call_on()'s own tail.) */
	if (conn->state == STATE_ESTB && conn->sess_count == 0)
		l2tp_switch_target_arm_idle_linger(target, conn);
}

static int l2tp_tunnel_connect(struct l2tp_conn_t *conn)
{
	struct sockaddr_pppol2tp pppox_addr;
	int tunnel_fd;
	int flg;

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = conn->hnd.fd;
	memcpy(&pppox_addr.pppol2tp.addr, &conn->peer_addr,
	       sizeof(conn->peer_addr));
	pppox_addr.pppol2tp.s_tunnel = conn->tid;
	pppox_addr.pppol2tp.d_tunnel = conn->peer_tid;

	tunnel_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (tunnel_fd < 0) {
		log_tunnel(log_error, conn, "impossible to connect tunnel:"
			   " socket(AF_PPPOX) failed: %s\n", strerror(errno));
		goto err;
	}

	flg = fcntl(tunnel_fd, F_GETFD);
	if (flg < 0) {
		log_tunnel(log_error, conn, "impossible to connect tunnel:"
			   " fcntl(F_GETFD) failed: %s\n", strerror(errno));
		goto err_fd;
	}
	flg = fcntl(tunnel_fd, F_SETFD, flg | FD_CLOEXEC);
	if (flg < 0) {
		log_tunnel(log_error, conn, "impossible to connect tunnel:"
			   " fcntl(F_SETFD) failed: %s\n", strerror(errno));
		goto err_fd;
	}

	if (connect(tunnel_fd,
		    (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		log_tunnel(log_error, conn, "impossible to connect tunnel:"
			   " connect() failed: %s\n", strerror(errno));
		goto err_fd;
	}

	if (conf_hello_interval)
		if (triton_timer_add(&conn->ctx, &conn->hello_timer, 0) < 0) {
			log_tunnel(log_error, conn,
				   "impossible to connect tunnel:"
				   " setting HELLO timer failed\n");
			goto err_fd;
		}

	close(tunnel_fd);

	l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_active);
	conn->state = STATE_ESTB;

	if (conn->switch_target)
		l2tp_switch_drain_pending_calls(conn);

	return 0;

err_fd:
	close(tunnel_fd);
err:
	return -1;
}

static void l2tp_rtimeout(struct triton_timer_t *tm)
{
	struct l2tp_conn_t *conn = container_of(tm, typeof(*conn),
						rtimeout_timer);
	struct l2tp_packet_t *pack;

	if (list_empty(&conn->rtms_queue)) {
		log_tunnel(log_warn, conn,
			   "impossible to handle retransmission:"
			   " retransmission queue is empty\n");

		return;
	}

	pack = list_first_entry(&conn->rtms_queue, typeof(*pack), entry);

	if (++conn->retransmit > conn->max_retransmit) {
		log_tunnel(log_warn, conn,
			   "no acknowledgement from peer after %i retransmissions,"
			   " deleting tunnel\n", conn->retransmit - 1);
		goto err;
	}

	log_tunnel(log_info2, conn, "retransmission #%i\n", conn->retransmit);
	if (conf_verbose) {
		log_tunnel(log_info2, conn, "retransmit (timeout) ");
		l2tp_packet_print(pack, log_info2);
	}

	if (__l2tp_tunnel_send(conn, pack) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to handle retransmission:"
			   " sending packet failed, deleting tunnel\n");
		goto err;
	}

	conn->rtimeout_timer.period *= 2;
	if (conn->rtimeout_timer.period > conn->rtimeout_cap)
		conn->rtimeout_timer.period = conn->rtimeout_cap;

	if (triton_timer_mod(&conn->rtimeout_timer, 0) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to handle retransmission:"
			   " updating retransmission timer failed,"
			   " deleting tunnel\n");
		goto err;
	}

	return;

err:
	triton_timer_del(tm);
	l2tp_tunnel_free(conn);
}

static void l2tp_tunnel_timeout(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn),
						timeout_timer);

	triton_timer_del(t);
	log_tunnel(log_info1, conn, "tunnel establishment timeout,"
		   " disconnecting tunnel\n");
	l2tp_tunnel_disconnect_push(conn, 1, 0);
}

static int l2tp_send_ZLB(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	int res;

	log_tunnel(log_debug, conn, "sending ZLB\n");

	pack = l2tp_packet_alloc(2, 0, &conn->peer_addr, 0, NULL, 0);
	if (!pack) {
		log_tunnel(log_error, conn, "impossible to send ZLB:"
			   " packet allocation failed\n");
		return -1;
	}

	/* ZLB messages are special: they take no slot in the control message
	 * sequence number space and never have to be retransmitted. So they're
	 * sent directly by __l2tp_tunnel_send(), thus bypassing the send and
	 * retransmission queues.
	 */
	pack->hdr.tid = htons(conn->peer_tid);
	pack->hdr.Ns = htons(conn->Ns);

	res = __l2tp_tunnel_send(conn, pack);
	if (res < 0)
		log_tunnel(log_error, conn, "impossible to send ZLB:"
			   " sending packet failed\n");

	l2tp_packet_free(pack);

	return res;
}

static void l2tp_send_HELLO(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn), hello_timer);
	struct l2tp_packet_t *pack;

	log_tunnel(log_debug, conn, "sending HELLO\n");

	pack = l2tp_packet_alloc(2, Message_Type_Hello, &conn->peer_addr,
				 conn->hide_avps, conn->secret,
				 conn->secret_len);
	if (!pack) {
		log_tunnel(log_error, conn, "impossible to send HELLO:"
			   " packet allocation failed, deleting tunnel\n");
		goto err;
	}

	l2tp_tunnel_send(conn, pack);

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to send HELLO:"
			   " transmitting messages from send queue failed,"
			   " deleting tunnel\n");
		goto err;
	}

	return;

err:
	l2tp_tunnel_free(conn);
}

static void l2tp_send_SCCRQ(void *peer_addr)
{
	struct l2tp_conn_t *conn = l2tp_tunnel_self();
	struct l2tp_packet_t *pack = NULL;
	uint16_t chall_len;
	int err;

	log_tunnel(log_info2, conn, "sending SCCRQ\n");

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Request,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (pack == NULL) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " packet allocation failed\n");
		goto err;
	}

	if (l2tp_packet_add_int16(pack, Protocol_Version,
				  L2TP_V2_PROTOCOL_VERSION, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_string(pack, Host_Name, conf_host_name, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Capabilities,
				  conn->framing_cap, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID,
				  conn->tid, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_string(pack, Vendor_Name, "accel-ppp", 0) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}
	if (l2tp_packet_add_int16(pack, Recv_Window_Size, conn->recv_queue_sz,
				  1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " adding data to packet failed\n");
		goto pack_err;
	}

	if (u_randbuf(&chall_len, sizeof(chall_len), &err) < 0) {
		if (err)
			log_tunnel(log_error, conn, "impossible to send SCCRQ:"
				   " reading from urandom failed: %s\n",
				   strerror(err));
		else
			log_tunnel(log_error, conn, "impossible to send SCCRQ:"
				   " end of file reached while reading"
				   " from urandom\n");
		goto pack_err;
	}
	chall_len = (chall_len & 0x007F) + MD5_DIGEST_LENGTH;
	if (l2tp_tunnel_genchall(chall_len, conn, pack) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " Challenge generation failed\n");
		goto pack_err;
	}

	l2tp_tunnel_send(conn, pack);

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRQ:"
			   " transmitting messages from send queue failed\n");
		goto err;
	}

	conn->state = STATE_WAIT_SCCRP;

	return;

pack_err:
	l2tp_packet_free(pack);
err:
	l2tp_tunnel_free(conn);
}

static void l2tp_send_SCCRP(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	uint16_t chall_len;
	int err;

	log_tunnel(log_info2, conn, "sending SCCRP\n");

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Reply,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (!pack) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " packet allocation failed\n");
		goto out;
	}

	if (l2tp_packet_add_int16(pack, Protocol_Version,
				  L2TP_V2_PROTOCOL_VERSION, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_string(pack, Host_Name, conf_host_name, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Capabilities,
				  conn->framing_cap, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack,
				  Assigned_Tunnel_ID, conn->tid, 1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_string(pack, Vendor_Name, "accel-ppp", 0) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int16(pack, Recv_Window_Size, conn->recv_queue_sz,
				  1) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " adding data to packet failed\n");
		goto out_err;
	}

	if (l2tp_tunnel_genchallresp(Message_Type_Start_Ctrl_Conn_Reply,
				     conn, pack) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " Challenge Response generation failed\n");
		goto out_err;
	}

	if (u_randbuf(&chall_len, sizeof(chall_len), &err) < 0) {
		if (err)
			log_tunnel(log_error, conn, "impossible to send SCCRP:"
				   " reading from urandom failed: %s\n",
				   strerror(err));
		else
			log_tunnel(log_error, conn, "impossible to send SCCRP:"
				   " end of file reached while reading"
				   " from urandom\n");
		goto out_err;
	}
	chall_len = (chall_len & 0x007F) + MD5_DIGEST_LENGTH;
	if (l2tp_tunnel_genchall(chall_len, conn, pack) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " Challenge generation failed\n");
		goto out_err;
	}

	l2tp_tunnel_send(conn, pack);

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCRP:"
			   " transmitting messages from send queue failed\n");
		goto out;
	}

	conn->state = STATE_WAIT_SCCCN;

	return;

out_err:
	l2tp_packet_free(pack);
out:
	l2tp_tunnel_free(conn);
}

static int l2tp_send_SCCCN(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack = NULL;

	log_tunnel(log_info2, conn, "sending SCCCN\n");

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Connected,
				 &conn->peer_addr, conn->hide_avps,
				 conn->secret, conn->secret_len);
	if (pack == NULL) {
		log_tunnel(log_error, conn, "impossible to send SCCCN:"
			   " packet allocation failed\n");
		goto err;
	}

	if (l2tp_tunnel_genchallresp(Message_Type_Start_Ctrl_Conn_Connected,
				     conn, pack) < 0) {
		log_tunnel(log_error, conn, "impossible to send SCCCN:"
			   " Challenge Response generation failed\n");
		goto pack_err;
	}
	l2tp_tunnel_storechall(conn, NULL);

	l2tp_tunnel_send(conn, pack);

	return 0;

pack_err:
	l2tp_packet_free(pack);
err:
	return -1;
}

static int l2tp_send_ICRQ(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	log_session(log_info2, sess, "sending ICRQ\n");

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Request,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == NULL) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Call_Serial_Number, 0, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (sess->calling_num &&
	    l2tp_packet_add_string(pack, Calling_Number, sess->calling_num,
				   1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (sess->called_num &&
	    l2tp_packet_add_string(pack, Called_Number, sess->called_num,
				   1) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	if (l2tp_session_try_send(sess, pack) < 0) {
		log_session(log_error, sess, "impossible to send ICRQ:"
			    " too many outstanding packets in send queue\n");
		goto out_err;
	}

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_ICRP(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	log_session(log_info2, sess, "sending ICRP\n");

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Reply,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (!pack) {
		log_session(log_error, sess, "impossible to send ICRP:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICRP:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_ICCN(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	log_session(log_info2, sess, "sending ICCN\n");

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int32(pack, TX_Speed, 1000, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Type, 3, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (sess->send_seq &&
	    l2tp_packet_add_octets(pack, Sequencing_Required, NULL, 0, 1) < 0) {
		log_session(log_error, sess, "impossible to send ICCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	if (sess->switch_avps) {
		int i;

		for (i = 0; i < sess->switch_avps->count; i++) {
			struct l2tp_switch_avp_t *a = &sess->switch_avps->avp[i];

			if (l2tp_packet_add_octets(pack, a->id, a->val, a->len,
						   a->M) < 0) {
				log_session(log_error, sess,
					    "impossible to send ICCN:"
					    " re-injecting proxy AVP %d"
					    " failed\n", a->id);
				goto out_err;
			}
		}
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_OCRQ(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	log_session(log_info2, sess, "sending OCRQ\n");

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Request,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (!pack) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Call_Serial_Number, 0, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Minimum_BPS, 100, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Maximum_BPS, 100000, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Bearer_Type, 3, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Type, 3, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_string(pack, Called_Number, "", 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	if (l2tp_session_try_send(sess, pack) < 0) {
		log_session(log_error, sess, "impossible to send OCRQ:"
			    " too many outstanding packets in send queue\n");
		goto out_err;
	}

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_OCRP(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack = NULL;

	log_session(log_info2, sess, "sending OCRP\n");

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Reply,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == NULL) {
		log_session(log_error, sess, "impossible to send OCRP:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCRP:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_OCCN(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack = NULL;

	log_session(log_info2, sess, "sending OCCN\n");

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Connected,
				 &sess->paren_conn->peer_addr, sess->hide_avps,
				 sess->paren_conn->secret,
				 sess->paren_conn->secret_len);
	if (pack == NULL) {
		log_session(log_error, sess, "impossible to send OCCN:"
			    " packet allocation failed\n");
		return -1;
	}

	if (l2tp_packet_add_int32(pack, TX_Speed, 1000, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (l2tp_packet_add_int32(pack, Framing_Type, 3, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}
	if (sess->send_seq &&
	    l2tp_packet_add_octets(pack, Sequencing_Required, NULL, 0, 1) < 0) {
		log_session(log_error, sess, "impossible to send OCCN:"
			    " adding data to packet failed\n");
		goto out_err;
	}

	l2tp_session_send(sess, pack);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static void l2tp_tunnel_finwait_timeout(struct triton_timer_t *tm)
{
	struct l2tp_conn_t *conn = container_of(tm, typeof(*conn),
						timeout_timer);

	triton_timer_del(tm);
	log_tunnel(log_info2, conn, "tunnel disconnection timeout\n");
	l2tp_tunnel_free(conn);
}

static void l2tp_tunnel_finwait(struct l2tp_conn_t *conn)
{
	switch (conn->state) {
	case STATE_WAIT_SCCRP:
	case STATE_WAIT_SCCCN:
		l2tp_stat_move(&l2tp_stat.conn_starting, &l2tp_stat.conn_finishing);
		break;
	case STATE_ESTB:
		l2tp_stat_move(&l2tp_stat.conn_active, &l2tp_stat.conn_finishing);
		break;
	case STATE_FIN:
		break;
	case STATE_FIN_WAIT:
	case STATE_CLOSE:
		return;
	default:
		log_tunnel(log_error, conn,
			   "impossible to disconnect tunnel:"
			   " invalid state %i\n",
			   conn->state);
		return;
	}

	conn->state = STATE_FIN_WAIT;

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	/* Too late to send outstanding messages */
	l2tp_tunnel_clear_sendqueue(conn);

	if (conn->sessions)
		l2tp_tunnel_free_sessions(conn);

	/* l2tp_recv_StopCCN() is this function's only caller: we get here
	 * exclusively after receiving the peer's own StopCCN, never after
	 * sending ours (that path -- l2tp_tunnel_disconnect() -- relies on
	 * the ordinary reliable-delivery retransmit queue instead, and never
	 * reaches STATE_FIN_WAIT). By this point our ack was already sent by
	 * the generic receive path, and the send queue was just cleared
	 * above, so there is nothing left of ours to protect with a
	 * worst-case retransmission cycle -- one base rtimeout of slack is
	 * enough to let that ack actually leave the wire. For an l2tp-switch
	 * target's persistent tunnel (l2tp.c's l2tp_switch_target_connect()),
	 * this directly bounds how long the target stays unusable after a
	 * peer-initiated teardown (e.g. a downstream LNS's own idle-tunnel
	 * timeout firing on a session-less tunnel): previously up to
	 * max_retransmit exponential-backoff retries' worth of wait (tens of
	 * seconds at the defaults) on top of the reconnect_timer cadence.
	 */
	conn->timeout_timer.period = conn->rtimeout;
	conn->timeout_timer.expire = l2tp_tunnel_finwait_timeout;

	if (triton_timer_add(&conn->ctx, &conn->timeout_timer, 0) < 0) {
		log_tunnel(log_warn, conn,
			   "impossible to start the disconnection timer,"
			   " disconnecting immediately\n");

		/* FIN-WAIT state occurs upon reception of a StopCCN message
		 * which has to be acknowledged. This is normally handled by
		 * the caller, but here l2tp_tunnel_free() will close the L2TP
		 * socket. So we have to manually send the acknowledgement
		 * first.
		 */
		l2tp_send_ZLB(conn);
		l2tp_tunnel_free(conn);
	}
}

static int l2tp_recv_SCCRQ(const struct l2tp_serv_t *serv,
			   const struct l2tp_packet_t *pack,
			   const struct in_pktinfo *pkt_info)
{
	const struct l2tp_attr_t *attr;
	const struct l2tp_attr_t *protocol_version = NULL;
	const struct l2tp_attr_t *assigned_tid = NULL;
	const struct l2tp_attr_t *assigned_cid = NULL;
	const struct l2tp_attr_t *framing_cap = NULL;
	const struct l2tp_attr_t *router_id = NULL;
	const struct l2tp_attr_t *recv_window_size = NULL;
	const struct l2tp_attr_t *challenge = NULL;
	struct l2tp_conn_t *conn = NULL;
	struct sockaddr_in host_addr = { 0 };
	uint16_t tid;
	char src_addr[17];

	u_inet_ntoa(pack->addr.sin_addr.s_addr, src_addr);

	if (ap_shutdown) {
		log_warn("l2tp: shutdown in progress,"
			 " discarding SCCRQ from %s\n", src_addr);
		return 0;
	}

	if (conf_max_starting && ap_session_stat_starting() >= conf_max_starting)
		return 0;

	if (conf_max_sessions && ap_session_stat_active() + ap_session_stat_starting() >= conf_max_sessions)
		return 0;

	if (triton_module_loaded("connlimit")
	    && connlimit_check(cl_key_from_ipv4(pack->addr.sin_addr.s_addr))) {
		log_warn("l2tp: connection limits reached,"
			 " discarding SCCRQ from %s\n", src_addr);
		return 0;
	}

	log_info2("l2tp: handling SCCRQ from %s\n", src_addr);

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
			case Random_Vector:
				break;
			case Protocol_Version:
				protocol_version = attr;
				break;
			case Framing_Capabilities:
				framing_cap = attr;
				break;
			case Assigned_Tunnel_ID:
				assigned_tid = attr;
				break;
			case Recv_Window_Size:
				recv_window_size = attr;
				break;
			case Challenge:
				challenge = attr;
				break;
			case Assigned_Connection_ID:
				assigned_cid = attr;
				break;
			case Router_ID:
				router_id = attr;
				break;
			case Message_Digest:
				log_error("l2tp: impossible to handle SCCRQ from %s:"
					  " Message Digest is not supported\n",
					  src_addr);
				return -1;
		}
	}

	if (assigned_tid) {
		if (!protocol_version) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " no Protocol Version present in message\n",
				  src_addr);
			return -1;
		}
		if (protocol_version->val.uint16 != L2TP_V2_PROTOCOL_VERSION) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " unknown Protocol Version %hhu.%hhu\n",
				  src_addr, protocol_version->val.uint16 >> 8,
				  protocol_version->val.uint16 & 0x00FF);
			return -1;
		}
		if (!framing_cap) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " no Framing Capabilities present in message\n",
				  src_addr);
			return -1;
		}

		host_addr.sin_family = AF_INET;
		host_addr.sin_addr = pkt_info->ipi_addr;
		if (conf_ephemeral_ports)
			host_addr.sin_port = 0;
		else
			host_addr.sin_port = serv->addr.sin_port;

		conn = l2tp_tunnel_alloc(&pack->addr, &host_addr,
					 framing_cap->val.uint32, 1, 1,
					 conf_hide_avps);
		if (conn == NULL) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " tunnel allocation failed\n", src_addr);
			return -1;
		}
		tid = conn->tid;

		if (recv_window_size) {
			conn->peer_rcv_wnd_sz = recv_window_size->val.uint16;
			if (conn->peer_rcv_wnd_sz == 0 ||
			    conn->peer_rcv_wnd_sz > RECV_WINDOW_SIZE_MAX) {
				log_error("l2tp: impossible to handle SCCRQ from %s:"
					  " invalid Receive Window Size %hu\n",
					  src_addr, conn->peer_rcv_wnd_sz);
				l2tp_tunnel_free(conn);
				return -1;
			}
		}

		if (conf_secret) {
			conn->secret = _strdup(conf_secret);
			if (conn->secret == NULL) {
				log_error("l2tp: impossible to handle SCCRQ from %s:"
					  " secret allocation failed\n",
					  src_addr);
				l2tp_tunnel_free(conn);
				return -1;
			}
			conn->secret_len = strlen(conn->secret);
		}

		if (l2tp_tunnel_storechall(conn, challenge) < 0) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " storing challenge failed\n", src_addr);
			l2tp_tunnel_free(conn);
			return -1;
		}

		conn->peer_tid = assigned_tid->val.uint16;
		conn->port_set = 1;
		conn->Nr = 1;

		if (l2tp_tunnel_start(conn, (triton_event_func)l2tp_send_SCCRP, conn) < 0) {
			log_error("l2tp: impossible to handle SCCRQ from %s:"
				  " starting tunnel failed\n", src_addr);
			l2tp_tunnel_free(conn);
			return -1;
		}
		log_info1("l2tp: new tunnel %hu-%hu created following"
			  " reception of SCCRQ from %s:%hu\n", tid,
			  assigned_tid->val.uint16, src_addr,
			  ntohs(pack->addr.sin_port));
	} else if (assigned_cid || router_id) {
		log_error("l2tp: impossible to handle SCCRQ from %s:"
			  " no support for L2TPv3 attributes\n", src_addr);
		return -1;
	} else {
		log_error("l2tp: impossible to handle SCCRQ from %s:"
			  " no Assigned-Tunnel-ID or Assigned-Connection-ID present in message\n",
			  src_addr);
		return -1;
	}

	return 0;
}

static int l2tp_recv_SCCRP(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *protocol_version = NULL;
	const struct l2tp_attr_t *assigned_tid = NULL;
	const struct l2tp_attr_t *framing_cap = NULL;
	const struct l2tp_attr_t *recv_window_size = NULL;
	const struct l2tp_attr_t *challenge = NULL;
	const struct l2tp_attr_t *challenge_resp = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;
	char host_addr[17];

	if (conn->state != STATE_WAIT_SCCRP) {
		log_tunnel(log_warn, conn, "discarding unexpected SCCRP\n");
		return 0;
	}

	log_tunnel(log_info2, conn, "handling SCCRP\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
		case Host_Name:
		case Bearer_Capabilities:
		case Firmware_Revision:
		case Vendor_Name:
			break;
		case Protocol_Version:
			protocol_version = attr;
			break;
		case Framing_Capabilities:
			framing_cap = attr;
			break;
		case Assigned_Tunnel_ID:
			assigned_tid = attr;
			break;
		case Recv_Window_Size:
			recv_window_size = attr;
			break;
		case Challenge:
			challenge = attr;
			break;
		case Challenge_Response:
			challenge_resp = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_tunnel(log_warn, conn,
					   "discarding unknown attribute type"
					   " %i in SCCRP\n", attr->attr->id);
			break;
		}
	}

	if (assigned_tid == NULL) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " no Assigned Tunnel ID present in message,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}

	/* Set peer_tid as soon as possible so that StopCCCN
	   will be sent to the right tunnel in case of error */
	log_tunnel(log_info2, conn, "peer-tid set to %hu by SCCRP\n",
		   assigned_tid->val.uint16);
	conn->peer_tid = assigned_tid->val.uint16;

	if (unknown_attr) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " unknown mandatory attribute type %i,"
			   " disconnecting tunnel\n",
			   unknown_attr->attr->id);
		l2tp_tunnel_disconnect(conn, 2, 8);
		return -1;
	}
	if (framing_cap == NULL) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " no Framing Capabilities present in message,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (protocol_version == NULL) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " no Protocol Version present in message,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (protocol_version->val.uint16 != L2TP_V2_PROTOCOL_VERSION) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " unknown Protocol Version %hhu.%hhu,"
			   " disconnecting tunnel\n",
			   protocol_version->val.uint16 >> 8,
			   protocol_version->val.uint16 & 0x00FF);
		l2tp_tunnel_disconnect(conn, 5, 0);
		return -1;
	}
	if (recv_window_size) {
		conn->peer_rcv_wnd_sz = recv_window_size->val.uint16;
		if (conn->peer_rcv_wnd_sz == 0 ||
		    conn->peer_rcv_wnd_sz > RECV_WINDOW_SIZE_MAX) {
			log_error("impossible to handle SCCRP:"
				  " invalid Receive Window Size %hu\n",
				  conn->peer_rcv_wnd_sz);
			conn->peer_rcv_wnd_sz = DEFAULT_PEER_RECV_WINDOW_SIZE;
			l2tp_tunnel_disconnect(conn, 2, 3);
			return -1;
		}
	}

	if (l2tp_tunnel_checkchallresp(Message_Type_Start_Ctrl_Conn_Reply,
				       conn, challenge_resp) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " checking Challenge Response failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 4, 0);
		return -1;
	}
	if (l2tp_tunnel_storechall(conn, challenge) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " storing Challenge failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 4);
		return -1;
	}

	if (l2tp_send_SCCCN(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " sending SCCCN failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (l2tp_tunnel_connect(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCRP:"
			   " connecting tunnel failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}

	u_inet_ntoa(conn->host_addr.sin_addr.s_addr, host_addr);
	log_tunnel(log_info1, conn, "established at %s:%hu\n",
		   host_addr, ntohs(conn->host_addr.sin_port));

	return 0;
}

static int l2tp_recv_SCCCN(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *attr = NULL;
	const struct l2tp_attr_t *challenge_resp = NULL;
	char host_addr[17];

	if (conn->state != STATE_WAIT_SCCCN) {
		log_tunnel(log_warn, conn, "discarding unexpected SCCCN\n");
		return 0;
	}

	log_tunnel(log_info2, conn, "handling SCCCN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Host_Name:
		case Vendor_Name:
		case Bearer_Capabilities:
		case Recv_Window_Size:
		case Protocol_Version:
		case Framing_Capabilities:
		case Assigned_Tunnel_ID:
		case Random_Vector:
			break;
		case Challenge_Response:
			challenge_resp = attr;
			break;
		default:
			if (attr->M) {
				log_tunnel(log_error, conn,
					   "impossible to handle SCCCN:"
					   " unknown mandatory attribute type %i,"
					   " disconnecting tunnel\n",
					   attr->attr->id);
				l2tp_tunnel_disconnect(conn, 2, 8);
				return -1;
			}
		}
	}

	if (l2tp_tunnel_checkchallresp(Message_Type_Start_Ctrl_Conn_Connected,
				       conn, challenge_resp) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCCN:"
			   " checking Challenge Response failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 4, 0);
		return -1;
	}
	l2tp_tunnel_storechall(conn, NULL);

	if (l2tp_tunnel_connect(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to handle SCCCN:"
			   " connecting tunnel failed,"
			   " disconnecting tunnel\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}

	u_inet_ntoa(conn->host_addr.sin_addr.s_addr, host_addr);
	log_tunnel(log_info1, conn, "established at %s:%hu\n",
		   host_addr, ntohs(conn->host_addr.sin_port));

	return 0;
}

static int rescode_get_data(const struct l2tp_attr_t *result_attr,
			    uint16_t *res, uint16_t *err, char **err_msg)
{
	struct l2tp_avp_result_code *resavp = NULL;
	int msglen;

	if (result_attr->length != 2 && result_attr->length < sizeof(*resavp))
		return -1;

	if (result_attr->length == 2) {
		/* No Error Code */
		*res = ntohs(*(const uint16_t *)result_attr->val.octets);
		return 1;
	}

	resavp = (struct l2tp_avp_result_code *)result_attr->val.octets;
	*res = ntohs(resavp->result_code);
	*err = ntohs(resavp->error_code);
	msglen = result_attr->length - sizeof(*resavp);
	if (msglen <= 0)
		return 2;

	*err_msg = _malloc(msglen + 1);
	if (*err_msg) {
		memcpy(*err_msg, resavp->error_msg, msglen);
		(*err_msg)[msglen] = '\0';
	}

	return 3;
}

static int l2tp_recv_StopCCN(struct l2tp_conn_t *conn,
			     const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_tid = NULL;
	const struct l2tp_attr_t *result_code = NULL;
	const struct l2tp_attr_t *attr = NULL;
	char *err_msg = NULL;
	uint16_t res = 0;
	uint16_t err = 0;

	if (conn->state == STATE_CLOSE || conn->state == STATE_FIN_WAIT) {
		log_tunnel(log_warn, conn, "discarding unexpected StopCCN\n");

		return 0;
	}

	log_tunnel(log_info2, conn, "handling StopCCN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case Assigned_Tunnel_ID:
			assigned_tid = attr;
			break;
		case Result_Code:
			result_code = attr;
			break;
		default:
			if (attr->M) {
				log_tunnel(log_warn, conn,
					   "discarding unknown attribute type"
					   " %i in StopCCN\n", attr->attr->id);
			}
			break;
		}
	}

	if (assigned_tid) {
		if (conn->peer_tid == 0) {
			log_tunnel(log_info2, conn,
				   "peer-tid set to %hu by StopCCN\n",
				   assigned_tid->val.uint16);
			conn->peer_tid = assigned_tid->val.uint16;
		} else if (conn->peer_tid != assigned_tid->val.uint16) {
			log_tunnel(log_warn, conn,
				   "discarding invalid Assigned Tunnel ID %hu"
				   " in StopCCN\n", assigned_tid->val.uint16);
		}
	} else {
		log_tunnel(log_warn, conn,
			   "no Assigned Tunnel ID present in StopCCN\n");
	}

	if (result_code) {
		if (rescode_get_data(result_code, &res, &err, &err_msg) < 0) {
			log_tunnel(log_warn, conn,
				   "invalid Result Code in StopCCN\n");
		}
	} else {
		log_tunnel(log_warn, conn,
			   "no Result Code present in StopCCN\n");
	}

	log_tunnel(log_info1, conn, "StopCCN received from peer (result: %hu,"
		   " error: %hu%s%s%s), disconnecting tunnel\n",
		   res, err, err_msg ? ", message: \"" : "",
		   err_msg ? err_msg : "", err_msg ? "\"" : "");

	if (err_msg)
		_free(err_msg);

	l2tp_tunnel_finwait(conn);

	return -1;
}

static int l2tp_recv_HELLO(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	if (conn->state != STATE_ESTB) {
		log_tunnel(log_warn, conn, "discarding unexpected HELLO\n");

		return 0;
	}

	log_tunnel(log_debug, conn, "handling HELLO\n");

	if (conn->hello_timer.tpd)
		triton_timer_mod(&conn->hello_timer, 0);

	return 0;
}

static int l2tp_session_incall_reply(struct l2tp_sess_t *sess)
{
	if (triton_timer_add(&sess->paren_conn->ctx,
			     &sess->timeout_timer, 0) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to incoming call:"
			    " setting establishment timer failed\n");
		goto err;
	}

	if (l2tp_send_ICRP(sess) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to incoming call:"
			    " sending ICRP failed\n");
		goto err_timer;
	}

	sess->state1 = STATE_WAIT_ICCN;

	return 0;

err_timer:
	triton_timer_del(&sess->timeout_timer);
err:
	return -1;
}

static int l2tp_recv_ICRQ(struct l2tp_conn_t *conn,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *attr;
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	struct l2tp_sess_t *sess = NULL;
	uint16_t peer_sid = 0;
	uint16_t sid = 0;
	uint16_t res = 0;
	uint16_t err = 0;
	uint8_t	calling[L2TP_AVP_LEN_MASK] = {0};
	uint8_t	called[L2TP_AVP_LEN_MASK] = {0};
	int n = 0;
	int m = 0;

	if (conn->state != STATE_ESTB && conn->lns_mode) {
		log_tunnel(log_warn, conn, "discarding unexpected ICRQ\n");
		return 0;
	}

	if (ap_shutdown) {
		log_tunnel(log_warn, conn, "shutdown in progress,"
			   " discarding ICRQ\n");
		return 0;
	}

	if (conf_max_starting && ap_session_stat_starting() >= conf_max_starting)
		return 0;

	if (conf_max_sessions && ap_session_stat_active() + ap_session_stat_starting() >= conf_max_sessions)
		return 0;

	if (triton_module_loaded("connlimit")
	    && connlimit_check(cl_key_from_ipv4(conn->peer_addr.sin_addr.s_addr))) {
		log_tunnel(log_warn, conn, "connection limits reached,"
			   " discarding ICRQ\n");
		return 0;
	}

	log_tunnel(log_info2, conn, "handling ICRQ\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
			case Assigned_Session_ID:
				assigned_sid = attr;
				break;
			case Message_Type:
			case Random_Vector:
			case Call_Serial_Number:
			case Bearer_Type:
			case Calling_Number:
			/* Save Calling-Number L2TP attribute locally */
				if (attr->attr->id == Calling_Number) {
					n = attr->length;
					memcpy(calling,attr->val.octets,n);
				}
			case Called_Number:
			/* Save Called-Number L2TP attribute locally */
				if (attr->attr->id == Called_Number) {
					m = attr->length;
					memcpy(called,attr->val.octets,m);
				}
			case Sub_Address:
			case Physical_Channel_ID:
				break;
			default:
				if (attr->M)
					unknown_attr = attr;
				else
					log_tunnel(log_warn, conn,
						   "discarding unknown attribute type"
						   " %i in ICRQ\n", attr->attr->id);
				break;
		}
	}

	if (!assigned_sid) {
		log_tunnel(log_error, conn, "impossible to handle ICRQ:"
			   " no Assigned Session ID present in message,"
			   " disconnecting session\n");
		res = 2;
		err = 6;
		goto out_reject;
	}

	peer_sid = assigned_sid->val.uint16;

	sess = l2tp_tunnel_alloc_session(conn);
	if (sess == NULL) {
		log_tunnel(log_error, conn, "impossible to handle ICRQ:"
			   " session allocation failed,"
			   " disconnecting session\n");
		res = 2;
		err = 4;
		goto out_reject;
	}

	sess->peer_sid = peer_sid;
	sid = sess->sid;

	/* Generic AVP-based routing (l2tp_switch_match(), l2tp_switch_conf.c):
	 * each configured match= rule names its own AVP, so this offers
	 * every AVP actually present in the ICRQ and lets the rule table
	 * decide whether any of them means something. Safe to pass
	 * attr->val.octets unconditionally regardless of this AVP's real
	 * dictionary type (int16/int32 AVPs included): l2tp_switch_match()
	 * only ever dereferences val/len after first confirming this exact
	 * attr pointer matches a configured rule's own attr, and no rule can
	 * exist for a non-string-typed AVP in the first place (enforced at
	 * config-load time by resolve_match_attr() in l2tp_switch_conf.c) --
	 * so the union member is never actually read as a pointer unless it
	 * is genuinely a string. Same reasoning applies at every other call
	 * site below and in l2tp_recv_ICCN. */
	list_for_each_entry(attr, &pack->attrs, entry) {
		sess->switch_target = l2tp_switch_match(attr->attr,
							attr->val.octets,
							attr->length);
		if (sess->switch_target) {
			l2tp_stat_inc(&l2tp_stat.switch_matched);
			log_tunnel(log_info1, conn,
				   "call matches l2tp-switch"
				   " target \"%s\"\n",
				   sess->switch_target->name);
			break;
		}
	}

	/* Allocate memory for Calling-Number if exists, and put it to l2tp_sess_t structure */
	if (n > 0) {
		sess->calling_num = _malloc(n+1);
		if (sess->calling_num == NULL) {
			log_tunnel(log_warn, conn, "can't allocate memory for Calling Number attribute. Will use LAC IP instead\n");
		}else{
			memcpy(sess->calling_num, calling, n);
			sess->calling_num[n] = '\0';
			sess->calling_num_len = n;
		}
	}

	/* Allocate memory for Called-Number if exists, and put it to l2tp_sess_t structure */
	if (m > 1) {
		sess->called_num = _malloc(m+1);
		if (sess->called_num == NULL) {
			log_tunnel(log_warn, conn, "can't allocate memory for Called Number attribute. Will use my IP instead\n");
		} else {
			memcpy(sess->called_num, called, m);
			sess->called_num[m] = '\0';
			sess->called_num_len = m;
		}
	}

	if (unknown_attr) {
		log_tunnel(log_error, conn, "impossible to handle ICRQ:"
			   " unknown mandatory attribute type %i,"
			   " disconnecting session\n",
			   unknown_attr->attr->id);
		res = 2;
		err = 8;
		goto out_reject;
	}

	if (l2tp_session_incall_reply(sess) < 0) {
		log_tunnel(log_error, conn, "impossible to handle ICRQ:"
			   " starting session failed,"
			   " disconnecting session\n");
		res = 2;
		err = 4;
		goto out_reject;
	}

	log_tunnel(log_info1, conn, "new session %hu-%hu with calling num %s len %d, called num %s len %d created following"
		   " reception of ICRQ\n", sid, peer_sid, sess->calling_num, sess->calling_num_len, sess->called_num, sess->called_num_len);

	return 0;

out_reject:
	if (l2tp_tunnel_send_CDN(sid, peer_sid, res, err) < 0)
		log_tunnel(log_warn, conn,
			   "impossible to reject ICRQ:"
			   " sending CDN failed\n");
	if (sess)
		l2tp_session_free(sess);

	return -1;
}

struct l2tp_switch_link_t {
	struct triton_md_handler_t hnd;
	struct l2tp_sess_t *src; /* read from src->ppp.fd */
	struct l2tp_sess_t *dst; /* write to dst->ppp.fd */
	int pipe_rd, pipe_wr;
	uint64_t bytes; /* this link's own lifetime, dies with the call --
			  * see target->rx_bytes/tx_bytes for the
			  * persistent, per-target totals this feeds into */

	/* Set once at creation (below), read-only for this link's
	 * whole lifetime -- which of the two directions this link carries,
	 * and which target's traffic it counts against. */
	struct l2tp_switch_target_t *target;
	int from_upstream; /* 1: src is the upstream (upstream-facing) leg, this
			     * link's bytes are "upstream rx" / "target tx";
			     * 0: src is the downstream (target-facing) leg,
			     * this link's bytes are "target rx" / "upstream tx" */

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
};

#define L2TP_SWITCH_SPLICE_LEN (1 << 16)
#define L2TP_SWITCH_EAGAIN_POLL_MS 100
#define L2TP_SWITCH_EAGAIN_MAX_WAITS 50 /* 5s of a full destination send path */

static void l2tp_switch_link_fail(struct l2tp_switch_link_t *link);
static void l2tp_switch_link_peer_gone(struct l2tp_switch_link_t *link);

/* Mirrors accel-pppd/ppp/ppp_lcp.h's struct lcp_hdr_t/CONFACK/PPP_LCP:
 * that header also pulls in triton.h/ppp.h/ppp_fsm.h, coupling to the
 * generic PPP layer-chain framework this feature deliberately never
 * touches (no struct ppp_t involvement anywhere in this file), so this is
 * a deliberate mirror rather than an #include. */
struct l2tp_switch_lcp_hdr {
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

#define L2TP_SWITCH_PPP_LCP 0xc021
#define L2TP_SWITCH_PPP_PAP 0xc023
#define L2TP_SWITCH_PPP_CHAP 0xc223
#define L2TP_SWITCH_LCP_CONFREQ 1
#define L2TP_SWITCH_LCP_TERMREQ 5
#define L2TP_SWITCH_LCP_PROTREJ 8
#define L2TP_SWITCH_LCP_OPT_AUTH 3 /* Authentication-Protocol */

/* Finds the Authentication-Protocol option (RFC 1661 6.x, type 3) in an LCP
 * Configure-Request or Configure-Ack held in `buf` (the peek copy: possibly
 * only the first bytes of the frame). Returns 1 and sets *proto (PPP protocol
 * number, e.g. 0xc023 PAP, 0xc223 CHAP) and *algo (CHAP algorithm byte, else
 * 0) if found. Returns 0 if not, with *truncated set when the frame was longer
 * than the bytes held, i.e. the option may simply not have been seen. */
static int l2tp_switch_lcp_find_auth(const uint8_t *buf, size_t len,
				     uint16_t *proto, uint8_t *algo,
				     int *truncated)
{
	const struct l2tp_switch_lcp_hdr *lcp = (const struct l2tp_switch_lcp_hdr *)buf;
	size_t end = sizeof(lcp->proto) + ntohs(lcp->len);
	size_t o = sizeof(*lcp);

	*truncated = end > len;
	if (*truncated)
		end = len;

	while (o + 2 <= end) {
		size_t olen = buf[o + 1];

		if (olen < 2 || o + olen > end)
			break;
		if (buf[o] == L2TP_SWITCH_LCP_OPT_AUTH && olen >= 4) {
			*proto = (buf[o + 2] << 8) | buf[o + 3];
			*algo = olen > 4 ? buf[o + 4] : 0;
			return 1;
		}
		o += olen;
	}

	return 0;
}

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

/* Bounded: up to ~1s total (20 * up to 50ms), matching the kind of
 * transient network-stack memory pressure a real burst causes -- not meant
 * to ride out a sustained overload indefinitely, just to not treat one bad
 * moment as fatal. */
#define L2TP_SWITCH_ENOMEM_MAX_RETRIES 20

static void l2tp_switch_link_count_bytes(struct l2tp_switch_link_t *link, ssize_t n)
{
	__atomic_add_fetch(&link->bytes, n, __ATOMIC_RELAXED);
	if (link->from_upstream) {
		__atomic_add_fetch(&l2tp_stat.switch_lns_rx_bytes,
				   (uint64_t)n, __ATOMIC_RELAXED);
		__atomic_add_fetch(&link->target->tx_bytes,
				   (uint64_t)n, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&link->target->rx_bytes,
				   (uint64_t)n, __ATOMIC_RELAXED);
		__atomic_add_fetch(&l2tp_stat.switch_lns_tx_bytes,
				   (uint64_t)n, __ATOMIC_RELAXED);
	}
}

/* downstream LCP-auth logging: peek at what just landed in link->pipe_rd --
 * tee(2) duplicates, it does not consume, so the real splice(out) that
 * follows sees pipe_rd exactly as if this were not here. Must run before
 * that splice drains pipe_rd. Only the downstream-fed direction is ever
 * worth inspecting -- see l2tp_switch_link_log_lcp_auth(). */
static void l2tp_switch_link_peek(struct l2tp_switch_link_t *link, ssize_t n)
{
	uint8_t peek[64]; /* enough for an LCP Configure-Request's common
			     options -- see l2tp_switch_link_log_lcp_auth() */
	ssize_t teed, got;

	/* LCP frames this logs (Configure-Request with options,
	 * Protocol-Reject, Terminate-Request) are well under this; ordinary
	 * data traffic on this direction -- the high-volume subscriber
	 * download path -- is well over it. Skips the tee()/read() pair on
	 * every data frame for the call's whole lifetime, unconditionally --
	 * there is no "done peeking" signal any more the way the removed
	 * watcher had once PAP resolved. */
	if (link->from_upstream || n > 128)
		return;

	teed = tee(link->pipe_rd, link->peek_pipe_wr, sizeof(peek),
		   SPLICE_F_NONBLOCK);
	if (teed > 0) {
		got = read(link->peek_pipe_rd, peek, sizeof(peek));
		if (got > 0)
			l2tp_switch_link_log_lcp_auth(link, peek, (size_t)got);
	}
}

/* Waits up to `timeout_ms` for the destination leg's socket to become
 * writable. Returns poll()'s result. */
static int l2tp_switch_link_wait_writable(int fd, int timeout_ms)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLOUT,
	};

	return poll(&pfd, 1, timeout_ms);
}

/* Splices `n` bytes from link->pipe_rd out to the destination leg. Returns 0
 * on success, -1 after failing the link -- the caller must not touch `link`
 * again in that case, l2tp_switch_link_fail() may have freed it. */
static int l2tp_switch_link_write_out(struct l2tp_switch_link_t *link, ssize_t n)
{
	int enomem_retries = 0;
	int eagain_waits = 0;

	while (n > 0) {
		/* The destination leg tears down on the OTHER tunnel's context
		 * and sets its fd to -1 (l2tp_switch_link_free()) without
		 * synchronizing with this one: read it once per lap, and treat
		 * "gone" as the peer closing rather than as a splice failure. */
		int dst_fd = __atomic_load_n(&link->dst->ppp.fd, __ATOMIC_RELAXED);
		ssize_t w;

		if (dst_fd < 0)
			goto peer_gone;

		w = splice(link->pipe_rd, NULL, dst_fd, NULL, n, SPLICE_F_MOVE);

		if (w >= 0) {
			enomem_retries = 0;
			n -= w;
			continue;
		}

		if (errno == EINTR)
			continue;

		if (errno == EAGAIN) {
			/* link->dst->ppp.fd is O_NONBLOCK (see
			 * l2tp_session_connect_socket()); wait for it to
			 * become writable rather than treating a momentarily
			 * full send path as a hard failure. Bounded: this runs
			 * on the source tunnel's own context, so an
			 * indefinitely full destination would stall every
			 * other session and the control channel (HELLOs, acks)
			 * of that tunnel with it. */
			int pres = l2tp_switch_link_wait_writable(dst_fd,
						L2TP_SWITCH_EAGAIN_POLL_MS);

			if (pres < 0 && errno != EINTR) {
				log_session(log_error, link->src,
					    "l2tp-switch: poll(out) failed: %s\n",
					    strerror(errno));
				goto fail;
			}
			if (pres == 0 &&
			    ++eagain_waits >= L2TP_SWITCH_EAGAIN_MAX_WAITS) {
				log_session(log_error, link->src,
					    "l2tp-switch: destination not"
					    " writable for %ims, dropping call\n",
					    L2TP_SWITCH_EAGAIN_POLL_MS *
					    L2TP_SWITCH_EAGAIN_MAX_WAITS);
				goto fail;
			}
			continue;
		}

		if ((errno == ENOMEM || errno == ENOBUFS) &&
		    enomem_retries < L2TP_SWITCH_ENOMEM_MAX_RETRIES) {
			/* Transient kernel/network-stack memory pressure under
			 * a burst -- confirmed on a real VM (splice(out)
			 * failing with ENOMEM under a large instantaneous
			 * burst, disconnecting an otherwise-healthy call).
			 * Unlike EAGAIN, POLLOUT readiness doesn't necessarily
			 * mean this has cleared, so back off on a short
			 * timeout instead of waiting indefinitely for an event
			 * that may already be (mis)reported as ready. */
			enomem_retries++;
			l2tp_switch_link_wait_writable(dst_fd, 50);
			continue;
		}

		if (errno == EBADF &&
		    (__atomic_load_n(&link->dst->ppp.fd, __ATOMIC_RELAXED) < 0 ||
		     link->dst->state1 == STATE_CLOSE))
			goto peer_gone; /* closed between the read above and now */

		log_session(log_error, link->src,
			    "l2tp-switch: splice(out) failed: %s\n",
			    strerror(errno));
		goto fail;
	}

	return 0;

peer_gone:
	l2tp_switch_link_peer_gone(link);
	return -1;

fail:
	l2tp_switch_link_fail(link);
	return -1;
}

static int l2tp_switch_link_read(struct triton_md_handler_t *h)
{
	struct l2tp_switch_link_t *link = container_of(h, typeof(*link), hnd);
	ssize_t n;

	while (1) {
		n = splice(link->src->ppp.fd, NULL, link->pipe_wr, NULL,
			  L2TP_SWITCH_SPLICE_LEN,
			  SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (n < 0) {
			if (errno == EAGAIN)
				return 0;
			if (errno == EINTR)
				continue;
			log_session(log_error, link->src,
				    "l2tp-switch: splice(in) failed: %s\n",
				    strerror(errno));
			l2tp_switch_link_fail(link);
			return 0;
		}
		if (n == 0)
			return 0;

		l2tp_switch_link_count_bytes(link, n);
		l2tp_switch_link_peek(link, n);

		if (l2tp_switch_link_write_out(link, n) < 0)
			return 0; /* link is gone */
	}
}

static void l2tp_switch_link_free(struct l2tp_switch_link_t *link)
{
	/* Detach from the owning session first, under the pair lock: the
	 * `l2tp switch show` walk reads src->switch_link (and the link's byte
	 * counter) on the CLI thread while holding that same lock, so once
	 * this returns no reader can still be looking at `link`. */
	pthread_mutex_lock(&l2tp_switch_pair_lock);
	link->src->switch_link = NULL;
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	/* Every pair has exactly one from_upstream link and one that isn't,
	 * and -- across every teardown path (the l2tp_session_free() hook,
	 * l2tp_switch_teardown_peer(), l2tp_switch_link_fail()) -- both
	 * always get freed exactly once each, in whichever order that
	 * teardown happens to take. Decrementing target->active here,
	 * gated on from_upstream, therefore fires exactly once per pair
	 * regardless of which of the two links is freed first or through
	 * which path -- unlike gating on "is this the first link freed",
	 * which the splice-failure path (l2tp_switch_link_fail frees its
	 * own link *before* disconnecting, so the l2tp_session_free hook
	 * never sees it non-NULL) would get wrong. */
	if (link->from_upstream &&
	    __atomic_sub_fetch(&link->target->active, 1,
			       __ATOMIC_RELAXED) == 0) {
		/* Last call on this target just ended: start the idle linger
		 * (a no-op unless the target is on-demand with an established
		 * tunnel). NULL tunnel: this runs in one of the *call's* two
		 * session contexts, neither of which is necessarily the
		 * target's tunnel context, so the target's own current tunnel
		 * pointer -- read under its lock -- is the only sound answer
		 * to "which tunnel just went idle". The same linger is armed
		 * again from l2tp_session_free() once the downstream leg
		 * actually leaves that tunnel; arming here too means a
		 * pairing that never got as far as its own session still
		 * starts the clock. */
		l2tp_switch_target_arm_idle_linger(link->target, NULL);
	}

	if (link->hnd.tpd) {
		triton_md_unregister_handler(&link->hnd, 1 /* close fd */);
		/* triton_md_unregister_handler() closes and resets
		 * link->hnd.fd, but that is a separate int from
		 * link->src->ppp.fd (same value, different storage) -- left
		 * alone, __session_destroy() finds a stale fd number still
		 * >= 0 and close()s it a second time, potentially closing
		 * an unrelated fd some other thread opened in the meantime. */
		__atomic_store_n(&link->src->ppp.fd, -1, __ATOMIC_RELAXED);
	}
	close(link->pipe_rd);
	close(link->pipe_wr);
	close(link->peek_pipe_rd);
	close(link->peek_pipe_wr);
	_free(link);
}

/* Runs in whichever session's own context is passed as `data`. This is
 * the "forced" half of teardown: sess's own l2tp_session_free() hook
 * calls this, via triton_context_call(), only when it finds its
 * peer is *not* already closing on its own. It mirrors exactly what the
 * peer's *own* l2tp_session_free() hook would have done had the peer
 * been the one to go through l2tp_session_free() first -- clearing the
 * peer's own outgoing pointer and releasing the hold that pointer
 * justified -- which is what stops this from ping-ponging back and
 * forth: by the time l2tp_session_disconnect() below reaches the peer's
 * own l2tp_session_free() hook, that hook finds no pointer left to chase.
 */
static void l2tp_switch_teardown_peer(void *data)
{
	struct l2tp_sess_t *peer = data;
	struct l2tp_switch_unpaired u = l2tp_switch_unpair(peer, 0);

	if (u.link)
		l2tp_switch_link_free(u.link);
	if (u.peer)
		session_put(u.peer); /* the hold justified by the pointer just cleared */
	l2tp_switch_avps_free(u.avps); /* no longer needed once the call is going */

	if (peer->state1 != STATE_CLOSE)
		/* _push(), not the plain disconnect: this runs as a scheduled
		 * context call, never through l2tp_conn_read()'s own receive
		 * loop, so nothing else would ever flush the CDN out of the
		 * tunnel's send queue -- exactly the problem
		 * l2tp_switch_place_call_on() already documents for its ICRQ.
		 * Against an accel-ppp downstream it goes unnoticed, since
		 * that peer answers the end of a call by tearing the whole
		 * tunnel down within milliseconds, and its StopCCN flushes
		 * the queue on the way in. Against a peer that simply keeps
		 * the tunnel -- which, with this task's idle linger, is now
		 * the case the switch is written for -- the CDN sat unsent
		 * until the linger closed the tunnel 20s later and
		 * l2tp_tunnel_disconnect() discarded it, leaving the peer
		 * holding a call that ended long ago. */
		l2tp_session_disconnect_push(peer, 2, 6);

	session_put(peer); /* the temporary hold taken to survive the
			     * context switch into here -- see the caller */
}

/* Tears down `link` and disconnects its source session. Shared by
 * l2tp_switch_link_fail() (a real splice failure, logged as an error) and
 * l2tp_switch_link_peer_gone() (the other leg is already going away). */
static void l2tp_switch_link_teardown(struct l2tp_switch_link_t *link)
{
	struct l2tp_sess_t *src = link->src;

	l2tp_switch_link_free(link); /* src->switch_link = NULL happens inside */
	if (src->state1 != STATE_CLOSE)
		/* _push(), not the plain disconnect: this callback runs in
		 * src's own context (which is what makes touching src's send
		 * queue legal here at all), but it is reached from the splice
		 * handler, never through l2tp_conn_read()'s receive-processing
		 * loop -- the one place that flushes the send queue on its own
		 * afterwards. Without the push the CDN just sits in the queue
		 * until l2tp_tunnel_free()'s l2tp_tunnel_clear_sendqueue()
		 * discards it unsent. Same fix, same reason, as
		 * l2tp_switch_teardown_peer() above.
		 *
		 * Reaches l2tp_session_free(src)'s teardown hook synchronously,
		 * which is what actually tears down the peer (see that hook
		 * for the other half of this). */
		l2tp_session_disconnect_push(src, 2, 6);
}

static void l2tp_switch_link_fail(struct l2tp_switch_link_t *link)
{
	log_session(log_error, link->src, "l2tp-switch: splice failed,"
		    " disconnecting session\n");
	l2tp_switch_link_teardown(link);
}

/* The destination leg is already closing (its socket is gone, or it is
 * STATE_CLOSE): the call is ending anyway, so this is not an error -- but the
 * source leg still has to be brought down with it. */
static void l2tp_switch_link_peer_gone(struct l2tp_switch_link_t *link)
{
	log_session(log_info2, link->src, "l2tp-switch: the other leg of this"
		    " call is already closing, disconnecting session\n");
	l2tp_switch_link_teardown(link);
}

static int l2tp_switch_link_create(struct l2tp_sess_t *src,
				   struct l2tp_sess_t *dst,
				   struct l2tp_switch_target_t *target,
				   int from_upstream)
{
	struct l2tp_switch_link_t *link;
	int pfd[2], peek_pfd[2];

	if (pipe2(pfd, O_CLOEXEC | O_NONBLOCK) < 0)
		return -1;

	/* peek target for l2tp_switch_link_log_lcp_auth()'s downstream LCP-auth
	 * logging -- created once here, alongside the real splice pipe, and
	 * reused for the link's whole lifetime rather than per-read: a pipe
	 * pair per read call would be wasteful. The peek itself is skipped
	 * for any frame over 128 bytes (see l2tp_switch_link_peek()), so
	 * steady-state data traffic never actually pays for it despite the
	 * pipe existing for the link's whole life. */
	if (pipe2(peek_pfd, O_CLOEXEC | O_NONBLOCK) < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	link = _malloc(sizeof(*link));
	if (!link) {
		close(pfd[0]);
		close(pfd[1]);
		close(peek_pfd[0]);
		close(peek_pfd[1]);
		return -1;
	}
	memset(link, 0, sizeof(*link));
	link->pipe_rd = pfd[0];
	link->pipe_wr = pfd[1];
	link->peek_pipe_rd = peek_pfd[0];
	link->peek_pipe_wr = peek_pfd[1];
	link->src = src;
	link->dst = dst;
	link->target = target;
	link->from_upstream = from_upstream;
	link->downstream_sess = from_upstream ? dst : src;
	/* No session_hold() here: src and dst are already kept alive for the
	 * whole pairing's lifetime by the two holds l2tp_switch_place_call()
	 * took once -- see the note above this function. */

	/* Symmetric with l2tp_switch_link_free()'s decrement, gated the same
	 * way -- see the comment there for why this must live in
	 * create/free themselves rather than being incremented once after
	 * both links succeed: if the *second* link's creation fails, the
	 * first is torn down via this same l2tp_switch_link_free(), which
	 * must find a matching increment to undo or target->active
	 * underflows (it's unsigned). Incrementing here means every
	 * l2tp_switch_link_free() call has exactly one create() call to
	 * balance against, on every path, including partial failure. */
	if (from_upstream)
		__atomic_add_fetch(&target->active, 1, __ATOMIC_RELAXED);

	link->hnd.fd = src->ppp.fd;
	link->hnd.read = l2tp_switch_link_read;

	triton_md_register_handler(&src->paren_conn->ctx, &link->hnd);
	if (triton_md_enable_handler(&link->hnd, MD_MODE_READ) < 0) {
		if (from_upstream)
			__atomic_sub_fetch(&target->active, 1, __ATOMIC_RELAXED);
		triton_md_unregister_handler(&link->hnd, 0);
		close(pfd[0]);
		close(pfd[1]);
		close(peek_pfd[0]);
		close(peek_pfd[1]);
		_free(link);
		return -1;
	}

	pthread_mutex_lock(&l2tp_switch_pair_lock);
	src->switch_link = link;
	pthread_mutex_unlock(&l2tp_switch_pair_lock);
	return 0;
}

static unsigned int l2tp_switch_active_total(void)
{
	struct l2tp_switch_target_t *t;
	unsigned int total = 0;

	list_for_each_entry(t, &l2tp_switch_targets, entry)
		total += __atomic_load_n(&t->active, __ATOMIC_RELAXED);

	return total;
}

struct l2tp_switch_finish_ctx {
	struct l2tp_sess_t *upstream;
	struct l2tp_sess_t *downstream;
};

/* Second half of bringing a switched call's splice up, on the DOWNSTREAM
 * leg's own tunnel context: creates the downstream->upstream link, which
 * belongs to the downstream leg and is torn down by its l2tp_session_free()/
 * l2tp_switch_teardown_peer() on this same context. Creating it here,
 * instead of from the upstream context as an earlier version did, ensures a
 * concurrent teardown of this leg cannot miss a half-published link and leak
 * it.
 *
 * Consumes the two temporary holds l2tp_switch_finish_upstream() carried
 * over in `ctx`, on every path. */
static void l2tp_switch_finish_downstream(void *data)
{
	struct l2tp_switch_finish_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_sess_t *downstream = ctx->downstream;

	_free(ctx);

	/* Either leg may have closed while this call was in flight; the leg
	 * that did already cascaded the teardown to the other one (which also
	 * frees the upstream link created by the first half), so all that is
	 * left to do is release the holds. downstream->state1 is this
	 * context's own field; upstream's is only a hint -- a teardown that
	 * lands right after this check still finds the links we create below
	 * through the normal hooks. */
	if (upstream->state1 == STATE_CLOSE || downstream->state1 == STATE_CLOSE)
		goto out;

	if (l2tp_switch_link_create(downstream, upstream,
				    upstream->switch_target, 0) < 0) {
		log_session(log_error, downstream,
			    "l2tp-switch: creating downstream->upstream"
			    " splice link failed\n");
		goto err;
	}
	goto out;

err:
	/* Disconnecting downstream reaches its l2tp_session_free() hook, which
	 * cascades to upstream (and frees the upstream link). _push(), not the
	 * plain disconnect: this is a scheduled context call, so nothing else
	 * would flush the CDN. */
	l2tp_session_disconnect_push(downstream, 2, 6);
out:
	session_put(downstream); /* temporary hold taken at the call site */
	session_put(upstream);   /* temporary hold taken at the call site */
}

/* First half, on the UPSTREAM leg's context (scheduled from the downstream
 * leg's ICRP handling): creates the upstream->downstream link (upstream's
 * own kernel socket is already connected -- see l2tp_recv_ICCN()), then
 * hands over to l2tp_switch_finish_downstream() for the downstream leg's
 * own half. The two temporary holds travel with `ctx`. */
static void l2tp_switch_finish_upstream(void *data)
{
	struct l2tp_switch_finish_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_sess_t *downstream = ctx->downstream;
	int res = -1;

	/* Either leg can already be STATE_CLOSE by the time this scheduled
	 * cross-context call actually runs (e.g. a StopCCN tears one side
	 * down while this call is still in flight). The dying leg's own
	 * l2tp_session_free() already cascaded a teardown to the survivor, so
	 * doing nothing here beyond releasing this call's two temporary holds
	 * is correct -- connecting a socket or creating a link against an
	 * already-STATE_CLOSE session would leak a stray kernel socket that
	 * nothing will ever clean up (its l2tp_session_free() already ran and
	 * is a no-op on any later call). Both sessions are carried explicitly
	 * via ctx rather than re-derived from upstream->switch_downstream,
	 * which that cascade may already have cleared. */
	if (upstream->state1 == STATE_CLOSE || downstream->state1 == STATE_CLOSE)
		goto put_holds;

	/* upstream's kernel socket is already connected -- l2tp_recv_ICCN()
	 * does it as soon as the call is recognized as switched, specifically
	 * so the kernel starts holding the real peer's data frames instead of
	 * dropping them while the downstream handshake below is still in
	 * flight. See its own comment for why. */

	if (l2tp_switch_link_create(upstream, downstream,
				    upstream->switch_target, 1) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: creating upstream->downstream"
			    " splice link failed\n");
		goto err;
	}

	/* target->active was incremented inside that l2tp_switch_link_create()
	 * call (gated on from_upstream); l2tp_switch_link_free() undoes it --
	 * see the comments there. */

	/* ctx_lock + ctx.tpd: the holds keep the downstream session (and so its
	 * l2tp_conn_t) alive across the hop, but not its tunnel's context
	 * registered -- same guard as every other cross-tunnel call here. */
	pthread_mutex_lock(&downstream->paren_conn->ctx_lock);
	if (downstream->paren_conn->ctx.tpd)
		res = triton_context_call(&downstream->paren_conn->ctx,
					  l2tp_switch_finish_downstream, ctx);
	pthread_mutex_unlock(&downstream->paren_conn->ctx_lock);
	if (res < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: downstream context gone before the"
			    " splice could be finished\n");
		goto err;
	}

	return; /* the holds and ctx now belong to l2tp_switch_finish_downstream() */

err:
	/* upstream->switch_downstream is still set (nothing before this point
	 * clears it) -- disconnecting upstream reaches l2tp_session_free()'s
	 * teardown hook, which releases the hold that pointer justifies, frees
	 * the upstream link if it was created, and tears down downstream via
	 * l2tp_switch_teardown_peer(). _push(), not the plain disconnect: this
	 * runs as a scheduled context call, so nothing else would flush the
	 * CDN to the upstream peer (same reason as
	 * l2tp_switch_teardown_peer()). */
	l2tp_session_disconnect_push(upstream, 2, 6);
put_holds:
	_free(ctx);
	session_put(downstream); /* temporary hold taken at the call site */
	session_put(upstream);   /* temporary hold taken at the call site */
}

static int l2tp_recv_ICRP(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_ICRP) {
		log_session(log_warn, sess, "discarding unexpected ICRP\n");
		return 0;
	}

	log_session(log_info2, sess, "handling ICRP\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					     " %i in ICRP\n", attr->attr->id);
			break;
		}
	}

	if (assigned_sid == NULL) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " no Assigned Session ID present in message,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	/* Set peer_sid as soon as possible so that CDN
	   will be sent to the right tunnel in case of error */
	log_session(log_info2, sess, "peer-sid set to %hu by ICRP\n",
		    assigned_sid->val.uint16);
	sess->peer_sid = assigned_sid->val.uint16;

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	if (l2tp_send_ICCN(sess) < 0) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " sending ICCN failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	if (sess->switch_upstream) {
		struct l2tp_sess_t *upstream = sess->switch_upstream;

		if (l2tp_session_connect_socket(sess, 0) < 0) {
			log_session(log_error, sess,
				    "l2tp-switch: connecting downstream"
				    " kernel socket failed\n");
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}

		l2tp_stat_inc(&l2tp_stat.switch_downstream_connected);

		/* Both sessions must survive until l2tp_switch_finish_upstream()
		 * actually runs, since triton_context_call() only schedules it
		 * -- both need a temporary hold, released inside that function
		 * on every path. Both pointers are carried explicitly via a
		 * small heap-allocated ctx rather than re-derived from
		 * downstream->switch_upstream at call time, since that pointer
		 * can be concurrently cleared by the teardown hook if
		 * either leg dies before this scheduled call runs -- see the
		 * comment in l2tp_switch_finish_upstream() itself. */
		struct l2tp_switch_finish_ctx *ctx = _malloc(sizeof(*ctx));

		if (!ctx) {
			log_session(log_error, sess,
				    "l2tp-switch: allocating finish-upstream"
				    " context failed\n");
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}
		ctx->upstream = upstream;
		ctx->downstream = sess;

		session_hold(upstream);
		session_hold(sess);
		/* ctx_lock + ctx.tpd: the holds above keep both sessions (and
		 * so upstream's l2tp_conn_t) alive across the hop, but not
		 * upstream's tunnel *context* registered --
		 * l2tp_tunnel_free() NULLs ctx.tpd long before the last
		 * reference drops, and triton_context_call() dereferences it
		 * without a NULL check. Same guard l2tp_session_apses_*()
		 * already uses for this exact cross-tunnel hop; "context
		 * gone" simply joins the scheduling-failure branch below. */
		int res = -1;

		pthread_mutex_lock(&upstream->paren_conn->ctx_lock);
		if (upstream->paren_conn->ctx.tpd)
			res = triton_context_call(&upstream->paren_conn->ctx,
						  l2tp_switch_finish_upstream,
						  ctx);
		pthread_mutex_unlock(&upstream->paren_conn->ctx_lock);

		if (res < 0) {
			_free(ctx);
			session_put(sess);
			session_put(upstream);
			l2tp_session_disconnect(sess, 2, 6);
			return -1;
		}

		return 0;
	}

	if (l2tp_session_connect(sess) < 0) {
		log_session(log_error, sess, "impossible to handle ICRP:"
			    " connecting session failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	return 0;
}

static int l2tp_switch_capture_avp(struct l2tp_sess_t *sess,
				   const struct l2tp_attr_t *attr)
{
	struct l2tp_switch_avp_t *slot;

	if (!sess->switch_avps) {
		sess->switch_avps = _malloc(sizeof(*sess->switch_avps));
		if (!sess->switch_avps)
			return -1;
		memset(sess->switch_avps, 0, sizeof(*sess->switch_avps));
	}

	if (sess->switch_avps->count >=
	    (int)(sizeof(sess->switch_avps->avp) /
		  sizeof(sess->switch_avps->avp[0])))
		return -1; /* more of these AVPs than RFC 2661 defines */

	slot = &sess->switch_avps->avp[sess->switch_avps->count];
	slot->id = attr->attr->id;
	slot->M = attr->M;

	/* attr->val is a union: which member is actually populated depends
	 * on attr->attr->type (set by packet.c's parser from the dictionary
	 * entry for this AVP id), not on how this function is called. Every
	 * AVP this function is ever invoked for is octets, string, or int16
	 * (Init/Last-*-LCP and Proxy-Authen-Challenge/Response are octets;
	 * Proxy-Authen-Name is string; Proxy-Authen-Type/ID are int16) --
	 * reading attr->val.octets unconditionally works for the first two
	 * (both are just a pointer into real byte data, string vs uint8_t*
	 * makes no difference for memcpy purposes) but for int16 it
	 * reinterprets a small integer VALUE stored directly in the union as
	 * if it were a pointer and crashes dereferencing it -- confirmed by
	 * reproducing this exact segfault against a real accel-pppd on a VM
	 * (Proxy-Authen-Type, sent whenever --proxy-username is used).
	 * Serialize to the same on-the-wire byte representation
	 * l2tp_packet_add_int16() itself would produce, so re-injecting via
	 * l2tp_packet_add_octets() later round-trips correctly --
	 * the wire format for an int16 AVP is just its 2 network-order
	 * bytes, indistinguishable from an octets AVP of length 2 to
	 * whichever end decodes it. */
	switch (attr->attr->type) {
	case ATTR_TYPE_INT16: {
		uint16_t val = htons(attr->val.uint16);

		slot->len = sizeof(val);
		slot->val = _malloc(slot->len);
		if (!slot->val)
			return -1;
		memcpy(slot->val, &val, slot->len);
		break;
	}
	case ATTR_TYPE_OCTETS:
	case ATTR_TYPE_STRING:
	default:
		slot->len = attr->length;
		slot->val = _malloc(slot->len ? slot->len : 1);
		if (!slot->val)
			return -1;
		memcpy(slot->val, attr->val.octets, slot->len);
		break;
	}

	sess->switch_avps->count++;

	/* Name/Challenge/Response are credential material (RFC 2661 4.4.5) --
	 * only that an AVP of this id was captured is logged, never its
	 * value. Type is the one exception: its value (0-5, which auth
	 * mechanism) isn't sensitive, and is exactly what settles whether the
	 * upstream even attempted proxy auth in the first place -- otherwise
	 * only answerable from a raw capture of the upstream leg, which a
	 * downstream partner reporting a problem usually cannot provide (they
	 * can only capture their own leg, not ours). */
	log_session(log_debug, sess,
		    "l2tp-switch: captured proxy AVP %s (id=%d, len=%d)"
		    " from upstream ICCN\n",
		    attr->attr->name, attr->attr->id, slot->len);
	if (attr->attr->id == Proxy_Authen_Type)
		log_session(log_debug, sess,
			    "l2tp-switch: upstream ICCN proxy authen type = %d\n",
			    attr->val.uint16);

	return 0;
}

static void l2tp_switch_disconnect_upstream(void *data)
{
	struct l2tp_sess_t *upstream = data;

	if (upstream->state1 != STATE_CLOSE)
		/* _push(), not the plain disconnect: this only ever runs as a
		 * scheduled context call (from l2tp_switch_place_call_on()'s
		 * err_no_pairing path and from the on-demand connect
		 * timeout), never through l2tp_conn_read()'s own receive
		 * loop, so nothing else would flush the CDN out of the
		 * tunnel's send queue before l2tp_tunnel_free() discards it.
		 * Same fix, same reason, as l2tp_switch_teardown_peer(). */
		l2tp_session_disconnect_push(upstream, 2, 6);

	session_put(upstream); /* the temporary hold taken in
				 * l2tp_switch_place_downstream_call() below */
}

/* Disposes of a tunnel whose on-demand connect budget was spent while it was
 * still mid-negotiation: tears it down if it really did stall, or takes the
 * target's connect slot back if it turns out to have established after all.
 *
 * Runs in the tunnel's own context (crossed into by
 * l2tp_switch_on_demand_timeout() below), which is the only context allowed to
 * touch its timers and send queue -- and the only one where conn->state cannot
 * go stale between the test and what is done about it. The timeout's own read
 * of conn->state, from the default context, is necessarily a guess; this is
 * where that guess is re-checked authoritatively. */
static void l2tp_switch_abort_stalled_tunnel(void *data)
{
	struct l2tp_conn_t *conn = data;
	struct l2tp_switch_target_t *target = conn->switch_target;
	int reclaimed;

	if (conn->state != STATE_ESTB) {
		if (conn->state != STATE_CLOSE)
			/* Result 2: general error, matching this file's
			 * existing convention for aborting a tunnel that
			 * failed to establish.
			 *
			 * _push(), not the plain disconnect: this runs as a
			 * scheduled context call from
			 * l2tp_switch_on_demand_timeout(), never through
			 * l2tp_conn_read()'s receive loop, so nothing else
			 * would flush the StopCCN out of the send queue before
			 * l2tp_tunnel_free()'s l2tp_tunnel_clear_sendqueue()
			 * discards it. Same fix, same reason, as
			 * l2tp_switch_teardown_peer(). */
			l2tp_tunnel_disconnect_push(conn, 2, 0);
		goto out;
	}

	/* It established between the timeout's state check and this call being
	 * dispatched -- which is not an exotic window at all: triton's
	 * ctx_thread() runs a context's pending md handlers *before* its
	 * pending context calls, so a peer SCCRP landing any time between that
	 * check and this call getting its turn is processed first. The tunnel
	 * then reached STATE_ESTB, and l2tp_tunnel_connect()'s drain ran and
	 * did nothing, its `target->tunnel == conn` identity guard having
	 * already been falsified by the timeout releasing the slot.
	 *
	 * So this is the only place left that can keep such a tunnel from
	 * becoming an orphan: established, with conn->switch_target still set,
	 * but reachable from nothing -- no call can find it (target->tunnel is
	 * NULL) and no idle linger can be armed for it (arming demands
	 * target->tunnel == conn), leaving it up against a live peer until the
	 * daemon exits or the peer itself hangs up. */
	pthread_mutex_lock(&target->lock);
	/* Same "one tunnel at a time" rule, and the same locked test, that
	 * l2tp_switch_target_connect() publishes an attempt under: take the
	 * slot back only if it is still free. A newer attempt that claimed it
	 * in the meantime owns the target now, and its own calls are queued
	 * against it. */
	reclaimed = !target->tunnel || target->tunnel == conn;
	if (reclaimed)
		target->tunnel = conn;
	pthread_mutex_unlock(&target->lock);

	if (reclaimed) {
		log_tunnel(log_info1, conn, "l2tp-switch: target \"%s\":"
			   " tunnel established just as its connect budget"
			   " expired, keeping it\n", target->name);
		/* Everything a normally-drained connect does, and for the same
		 * reasons -- place whatever is queued now (a call that arrived
		 * after the timeout gave up on the old queue would otherwise
		 * wait out its own budget behind a tunnel that is already
		 * usable), close that budget, and arm the idle linger if
		 * nothing was placed, so a tunnel nobody ends up using still
		 * closes itself.
		 *
		 * Safe to call directly: it must run in conn's own context,
		 * which is exactly where we are, and no call can slip past it
		 * -- l2tp_switch_place_downstream_call() decides between its
		 * fast path and queueing in a single hold of target->lock, so
		 * after the re-claim above every new call takes the fast path
		 * instead of queueing. */
		l2tp_switch_drain_pending_calls(conn);
	} else {
		log_tunnel(log_info1, conn, "l2tp-switch: target \"%s\":"
			   " tunnel established too late, a newer attempt"
			   " already owns the target -- closing it\n",
			   target->name);
		/* Result 1, "general request to clear the control connection"
		 * (RFC 2661 5.4): nothing is wrong with this tunnel, it simply
		 * has no owner any more. Leaving it up would leak exactly the
		 * orphan described above. Same _push() reason as every other
		 * disconnect reached by a scheduled context call. */
		l2tp_tunnel_disconnect_push(conn, 1, 0);
	}

out:
	tunnel_put(conn); /* the hold taken in
			   * l2tp_switch_on_demand_timeout() below */
}

/* An on-demand target's connect took longer than the budget a waiting call
 * is willing to give it. Fail the queued calls rather than hold them
 * indefinitely, and abandon the connect attempt they were waiting on.
 *
 * Runs on the default context (the timer was armed with a NULL context), not
 * on any tunnel's own context -- hence every piece of per-tunnel/per-session
 * work below is handed to the owning context via triton_context_call().
 *
 * This callback can run when it has nothing to do: triton re-checks a timer's
 * registration only *before* dispatching it (triton.c's pending-timer loop
 * drops its own lock, then tests t->ud), so a dispatch already in flight
 * still reaches us after the budget it was armed for was closed by the drain
 * -- possibly after a newer call has since reopened a budget with a later
 * deadline. Since triton hands a timer callback nothing that identifies which
 * arming it came from (the timer is a single embedded field, identical across
 * budgets), the budget flag and its deadline are what distinguish the two. */
static void l2tp_switch_on_demand_timeout(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), connect_timeout_timer);
	LIST_HEAD(drained);
	struct l2tp_sess_t *sess;
	struct l2tp_conn_t *stalled = NULL;

	pthread_mutex_lock(&target->lock);

	if (!target->connect_budget_open) {
		/* The connect succeeded and drained the queue itself before
		 * this timer got a chance to fire. Retire the timer here, on
		 * the context that owns it. */
		if (target->connect_timeout_timer.tpd)
			triton_timer_del(&target->connect_timeout_timer);
		pthread_mutex_unlock(&target->lock);
		return;
	}

	if (l2tp_switch_monotonic_ms() < target->connect_deadline) {
		/* A newer budget pushed the deadline out from under a
		 * dispatch that was already on its way. Leave the timer
		 * armed -- it is the newer budget's timer now, and it will
		 * come due again at the right time. */
		pthread_mutex_unlock(&target->lock);
		return;
	}

	if (target->connect_timeout_timer.tpd)
		triton_timer_del(&target->connect_timeout_timer);
	/* Nothing is waiting on this target any more, so the reconnect
	 * cadence has no one left to serve: cancel it here rather than let a
	 * tick that was armed by one of the failed attempts fire later and
	 * start a connect for calls that have already been given up on.
	 * Same context as this callback (both timers are armed with a NULL
	 * context), so this deletion is not a cross-context one. */
	if (target->reconnect_timer.tpd)
		triton_timer_del(&target->reconnect_timer);
	target->connect_budget_open = 0;
	list_splice_init(&target->pending_calls, &drained);
	target->pending_count = 0;
	if (target->tunnel && target->tunnel->state != STATE_ESTB) {
		stalled = target->tunnel; /* still mid-negotiation past budget */
		tunnel_hold(stalled); /* keeps it alive until the abort call
				       * below runs in its own context */
		/* Release the target's connect slot in the same locked step
		 * that abandons the attempt. target->tunnel doubles as
		 * l2tp_switch_target_connect()'s "one attempt at a time"
		 * exclusion, and the abort below only *starts* this tunnel's
		 * death -- StopCCN, retransmits, FIN_WAIT -- which can take
		 * tens of seconds to reach l2tp_tunnel_free() and clear the
		 * pointer there. Leaving it set for that whole window makes
		 * every call arriving in it queue behind a connect that can
		 * never be started, burn its full budget and get CDN'd, no
		 * matter how reachable the target actually is.
		 *
		 * conn->switch_target stays set: the abandoned tunnel still
		 * belongs to this target for accounting and for
		 * l2tp_tunnel_free()'s own hook, whose `target->tunnel ==
		 * conn` identity guard is exactly what keeps that later
		 * teardown from blanking out a newer attempt's pointer.
		 *
		 * Releasing the slot here means the tunnel is unreachable from
		 * the target from now on -- no later call can find it, and no
		 * idle linger can be armed for it. That is deliberate for a
		 * tunnel that really is stalled, but the state read just above
		 * is read from the wrong context to be final: it can already
		 * be establishing. l2tp_switch_abort_stalled_tunnel() re-tests
		 * it where it is authoritative and takes this slot back if so,
		 * which is what keeps a tunnel that beat the deadline by a
		 * hair from being stranded up with nothing referencing it. */
		target->tunnel = NULL;
	}
	pthread_mutex_unlock(&target->lock);

	if (list_empty(&drained) && !stalled)
		return;

	log_error("l2tp-switch: target \"%s\": on-demand connect timed out,"
		  " disconnecting queued call(s)\n", target->name);

	while (!list_empty(&drained)) {
		int res = -1;

		sess = list_first_entry(&drained, typeof(*sess),
					switch_pending_entry);
		list_del(&sess->switch_pending_entry);
		/* Cross into this call's own upstream tunnel context -- mirrors
		 * l2tp_switch_place_call()'s existing err_no_pairing path
		 * exactly, reusing the same hold taken when this session was
		 * queued.
		 *
		 * ctx_lock + ctx.tpd, the same guard l2tp_session_apses_*()
		 * already uses for this exact cross-context hop: the session
		 * hold keeps the l2tp_conn_t's *memory* alive, but not its
		 * triton context registered -- l2tp_tunnel_free() unregisters
		 * it (NULLing ctx.tpd) long before the last reference goes
		 * away, and triton_context_call() dereferences ud->tpd with no
		 * NULL check of its own. */
		pthread_mutex_lock(&sess->paren_conn->ctx_lock);
		if (sess->paren_conn->ctx.tpd)
			res = triton_context_call(&sess->paren_conn->ctx,
						  l2tp_switch_disconnect_upstream,
						  sess);
		pthread_mutex_unlock(&sess->paren_conn->ctx_lock);
		if (res < 0)
			session_put(sess);
	}

	if (stalled) {
		int res = -1;

		/* Same guard, this time on the tunnel's own ctx_lock: our
		 * tunnel_hold() above pins the struct, not the context
		 * registration. */
		pthread_mutex_lock(&stalled->ctx_lock);
		if (stalled->ctx.tpd)
			res = triton_context_call(&stalled->ctx,
						  l2tp_switch_abort_stalled_tunnel,
						  stalled);
		pthread_mutex_unlock(&stalled->ctx_lock);
		if (res < 0)
			tunnel_put(stalled);
	}
}

/* Closes an on-demand target's tunnel whose idle linger has run out. Runs in
 * the tunnel's own context (crossed into by l2tp_switch_target_idle_timer()
 * below), the only context allowed to touch its send queue and timers. */
static void l2tp_switch_close_idle_tunnel(void *data)
{
	struct l2tp_conn_t *conn = data;

	/* The authoritative "is it still idle" test, and the reason it lives
	 * here rather than in the timer callback: conn->sess_count is owned
	 * by this context, so unlike anything read from the default context
	 * it cannot go stale between the test and the disconnect. A call
	 * placed in the window between the timer firing and this call running
	 * is exactly what the linger exists to let happen. */
	if (conn->state != STATE_ESTB || conn->sess_count)
		goto out;

	log_tunnel(log_info1, conn, "l2tp-switch: target \"%s\" idle for %ds,"
		   " closing on-demand tunnel\n",
		   conn->switch_target ? conn->switch_target->name : "?",
		   l2tp_switch_conf_idle_linger_ms() / 1000);

	/* Result 1, "general request to clear the control connection"
	 * (RFC 2661 5.4): a voluntary administrative close, not an error --
	 * the same code l2tp_session_free() sends when an ordinary tunnel
	 * loses its last session, which is the disconnect this linger
	 * postponed. _push(), not the plain disconnect: reached by a
	 * scheduled context call rather than through l2tp_conn_read()'s
	 * receive loop, nothing else would flush the StopCCN out of the send
	 * queue (same reason l2tp_switch_place_call_on() pushes its ICRQ).
	 *
	 * l2tp_tunnel_free()'s own switch_target hook then leaves the target
	 * cold: l2tp_switch_target_should_retry() finds an on-demand target
	 * with no pending calls and schedules no reconnect. */
	l2tp_tunnel_disconnect_push(conn, 1, 0);

out:
	tunnel_put(conn); /* the hold taken in
			   * l2tp_switch_target_idle_timer() below */
}

/* An on-demand target's tunnel has now been callless for a full linger
 * window. Hand it to its own context to be closed.
 *
 * Runs on the default context (the timer is armed with a NULL context),
 * which is also the context that owns the timer -- so this is the one place
 * allowed to delete it. Cancelling a linger from anywhere else therefore
 * only zeroes idle_deadline (see l2tp_switch_place_downstream_call()'s fast
 * path) and leaves the retirement to this callback; deleting a triton timer
 * from a foreign context races triton's own dispatch, which drops its lock
 * before dereferencing the timer it is about to call.
 *
 * Like l2tp_switch_on_demand_timeout(), this can therefore run with nothing
 * to do, and for a window that no longer exists: idle_deadline is what tells
 * a genuine expiry from a dispatch left over from an earlier, shorter
 * linger. */
static void l2tp_switch_target_idle_timer(struct triton_timer_t *t)
{
	struct l2tp_switch_target_t *target =
		container_of(t, typeof(*target), idle_timer);
	struct l2tp_conn_t *conn = NULL;
	int res = -1;

	pthread_mutex_lock(&target->lock);

	if (target->idle_deadline &&
	    l2tp_switch_monotonic_ms() < target->idle_deadline) {
		/* A later call's linger pushed the deadline out from under a
		 * dispatch that was already on its way. Leave the timer
		 * armed: it is that window's timer now, and it comes due
		 * again at the right time. */
		pthread_mutex_unlock(&target->lock);
		return;
	}

	if (target->idle_timer.tpd)
		triton_timer_del(&target->idle_timer);

	/* A cancelled linger (idle_deadline == 0) retires the timer above and
	 * stops here. Otherwise the target's own call count is the cheap
	 * first re-check -- conn->sess_count, checked in conn's context, is
	 * the authoritative one. */
	if (target->idle_deadline && target->tunnel &&
	    __atomic_load_n(&target->active, __ATOMIC_RELAXED) == 0) {
		conn = target->tunnel;
		tunnel_hold(conn); /* keeps it alive until the close call
				    * below runs in its own context */
	}
	target->idle_deadline = 0;

	pthread_mutex_unlock(&target->lock);

	if (!conn)
		return;

	/* ctx_lock + ctx.tpd: the tunnel_hold() above keeps conn's memory
	 * alive across this hop, but l2tp_tunnel_free() can have unregistered
	 * its context in the meantime -- and triton_context_call() would then
	 * spin_lock(NULL). Same guard the apses paths already use. The
	 * re-arm below stays outside this lock: it takes target->lock, and
	 * l2tp_tunnel_free() takes target->lock and conn->ctx_lock in that
	 * order (never nested), which is the order kept here too. */
	pthread_mutex_lock(&conn->ctx_lock);
	if (conn->ctx.tpd)
		res = triton_context_call(&conn->ctx,
					  l2tp_switch_close_idle_tunnel, conn);
	pthread_mutex_unlock(&conn->ctx_lock);

	if (res < 0) {
		/* The close never got scheduled, and this callback has
		 * already retired the timer and consumed the window it fired
		 * for -- leaving the tunnel session-less with nothing left to
		 * ever close it. Start the window again rather than strand
		 * it. (Reachable when conn's context is already gone or
		 * shutting down, in which case the re-arm is refused too --
		 * l2tp_switch_target_arm_idle_linger()'s identity/state
		 * guards reject a tunnel that is no longer the target's or no
		 * longer STATE_ESTB -- and the tunnel is going away on its
		 * own anyway.) */
		l2tp_switch_target_arm_idle_linger(target, conn);
		tunnel_put(conn);
	}
}

/* Places upstream's downstream leg on `conn`. Two callers, both of which
 * hand over one session hold on upstream that this function releases on
 * every path:
 *
 *   - l2tp_switch_place_downstream_call()'s fast path, indirectly: it
 *     schedules the l2tp_switch_place_call() trampoline below into conn's
 *     context, since it runs in the *upstream* session's context;
 *   - l2tp_switch_drain_pending_calls(), directly -- it is already running
 *     in conn's own context when a queued-up connect completes.
 *
 * The tunnel to use is an argument rather than re-read from
 * upstream->switch_target->tunnel, which is not necessarily the same tunnel
 * any more by the time this runs: using it would mean mutating one tunnel's
 * session tree and send queue from another tunnel's context. */
static void l2tp_switch_place_call_on(struct l2tp_sess_t *upstream,
				      struct l2tp_conn_t *conn)
{
	/* Captured up front: every failure path below releases the caller's
	 * hold on upstream, after which upstream may already be gone. */
	struct l2tp_switch_target_t *target = upstream->switch_target;
	struct l2tp_sess_t *downstream;
	int res;

	/* This function runs in conn's context (the downstream target's
	 * tunnel) -- NOT in upstream->paren_conn->ctx. Touching upstream's own
	 * state (timers, send queue -- exactly what l2tp_session_disconnect()
	 * does) from here would violate this codebase's per-tunnel-context
	 * threading model, so every path that needs to disconnect upstream
	 * crosses into its own context first via triton_context_call()
	 * rather than calling l2tp_session_disconnect(upstream, ...) here
	 * directly. */

	/* upstream can already be STATE_CLOSE by the time this scheduled
	 * cross-context call actually runs -- e.g. the upstream LAC peer sends ICCN
	 * then immediately StopCCN, and the StopCCN is processed on
	 * upstream's own tunnel context (tearing upstream down completely,
	 * via l2tp_session_free()'s normal STATE_CLOSE-guarded path) before
	 * this call is scheduled to run. l2tp_session_free() is a no-op on
	 * an already-STATE_CLOSE session (its own switch statement returns
	 * immediately), so pairing downstream to a dead upstream here would
	 * mean nothing ever calls l2tp_session_free(upstream) again --
	 * the teardown hook would never fire, downstream's own
	 * session_hold(upstream) would never be released, and the pairing
	 * would leak forever (confirmed on a real VM: active stuck at 1
	 * indefinitely). session_put() directly (no context cross needed --
	 * l2tp_switch_finish_upstream() already does the same for its own
	 * trailing releases) releases the hold taken by the caller without
	 * pairing or placing any downstream call for a call that no longer
	 * exists. */
	if (upstream->state1 == STATE_CLOSE) {
		session_put(upstream);
		goto out_idle;
	}

	/* conn was usable when this call was handed over, but it can have been
	 * torn down since -- the scheduled path in particular crosses contexts
	 * to get here. */
	if (conn->state != STATE_ESTB) {
		log_session(log_error, upstream,
			    "l2tp-switch: target tunnel not available,"
			    " disconnecting upstream call\n");
		goto err_no_pairing;
	}

	downstream = l2tp_tunnel_alloc_session(conn);
	if (!downstream) {
		log_session(log_error, upstream,
			    "l2tp-switch: downstream session allocation"
			    " failed\n");
		goto err_no_pairing;
	}

	if (upstream->calling_num) {
		downstream->calling_num = _malloc(upstream->calling_num_len + 1);
		if (downstream->calling_num) {
			memcpy(downstream->calling_num, upstream->calling_num,
			      upstream->calling_num_len + 1);
			downstream->calling_num_len = upstream->calling_num_len;
		}
	}
	if (upstream->called_num) {
		downstream->called_num = _malloc(upstream->called_num_len + 1);
		if (downstream->called_num) {
			memcpy(downstream->called_num, upstream->called_num,
			      upstream->called_num_len + 1);
			downstream->called_num_len = upstream->called_num_len;
		}
	}

	/* Mirror the upstream leg's sequencing request onto the downstream
	 * leg (spec §11: sequencing must match across legs, not fall back to
	 * independent per-tunnel defaults). l2tp_send_ICCN already sends a
	 * Sequencing_Required AVP whenever sess->send_seq is set -- no other
	 * change is needed for the downstream leg to advertise the same
	 * requirement the upstream LAC made of the upstream leg. */
	downstream->send_seq = upstream->send_seq;
	downstream->recv_seq = upstream->recv_seq;

	/* Pair the two legs. The "is upstream still alive" check has to be
	 * atomic with the cross-links: upstream's own l2tp_session_free() runs
	 * on ITS context, clears/frees these very fields under the same lock
	 * (l2tp_switch_unpair()) and marks it STATE_CLOSE in that critical
	 * section. Without this, a teardown landing between the early
	 * STATE_CLOSE check above and these stores would free switch_avps
	 * under the move below, or leave the freshly-placed downstream call
	 * paired to a dead upstream with nothing ever tearing it down. */
	pthread_mutex_lock(&l2tp_switch_pair_lock);
	if (upstream->state1 == STATE_CLOSE) {
		pthread_mutex_unlock(&l2tp_switch_pair_lock);
		l2tp_session_free(downstream); /* not paired yet: plain free */
		session_put(upstream);
		goto out_idle;
	}
	downstream->switch_upstream = upstream;
	downstream->switch_avps = upstream->switch_avps;
	upstream->switch_avps = NULL; /* ownership moves to the downstream leg */
	upstream->switch_downstream = downstream;
	session_hold(downstream);
	session_hold(upstream);
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	if (l2tp_session_place_call(downstream) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: placing downstream call failed\n");
		/* downstream->switch_upstream == upstream was just set above,
		 * so l2tp_session_free()'s teardown hook finds it and, via
		 * l2tp_switch_teardown_peer(), correctly crosses into
		 * upstream's own context to tear it down too -- nothing more
		 * to do for upstream on this path. */
		l2tp_session_free(downstream);
		goto err_pairing_done;
	}

	/* l2tp_session_place_call() only enqueues the ICRQ (l2tp_tunnel_send()
	 * appends to conn->send_queue and returns) -- it never transmits.
	 * Every other path that ends up here goes through l2tp_conn_read()'s
	 * own receive-processing loop, which unconditionally flushes the
	 * queue afterward; this function is reached via triton_context_call()
	 * instead (scheduled from a different tunnel's context), which never
	 * passes through that loop. l2tp_tunnel_create_session() -- the
	 * existing CLI-triggered path this whole cross-context pattern is
	 * modeled on -- calls this explicitly for exactly the same reason;
	 * omitting it here left the ICRQ sitting in the queue, silently
	 * undelivered, until some *unrelated* event on this tunnel (e.g. the
	 * next HELLO) happened to flush it -- confirmed on a real VM: a
	 * ~40s+ stall between "sending ICRQ" and the packet actually
	 * reaching the wire, tracked down via the log's own send-queue
	 * accounting ("N message(s) sent from send queue") once it was
	 * clear the wire packet was simply late rather than never matching /
	 * misrouted. */
	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_session(log_error, upstream,
			    "l2tp-switch: transmitting downstream ICRQ"
			    " failed\n");
		l2tp_session_free(downstream);
		goto err_pairing_done;
	}

	l2tp_stat_inc(&l2tp_stat.switch_placed);
	session_put(upstream); /* the temporary hold taken in
				 * l2tp_switch_place_downstream_call() below --
				 * the two pairing holds taken just above stay
				 * intact for the life of the active pairing */
	return;

err_no_pairing:
	/* No downstream leg exists yet -- upstream has no peer, so there is
	 * nothing for a teardown hook to cascade to. Cross into upstream's own
	 * context to disconnect it directly.
	 *
	 * ctx_lock + ctx.tpd: our hold on upstream keeps its l2tp_conn_t's
	 * memory alive, but not that tunnel's triton context registered --
	 * l2tp_tunnel_free() NULLs ctx.tpd well before the last reference
	 * goes, and triton_context_call() dereferences it unchecked. Same
	 * guard l2tp_session_apses_*() already uses for this exact hop. */
	res = -1;
	pthread_mutex_lock(&upstream->paren_conn->ctx_lock);
	if (upstream->paren_conn->ctx.tpd)
		res = triton_context_call(&upstream->paren_conn->ctx,
					  l2tp_switch_disconnect_upstream,
					  upstream);
	pthread_mutex_unlock(&upstream->paren_conn->ctx_lock);
	if (res < 0)
		session_put(upstream); /* couldn't even schedule it; still
					 * release our own hold */
	goto out_idle;

err_pairing_done:
	/* The teardown hook triggered by l2tp_session_free(downstream) above
	 * already scheduled upstream's teardown in its own context; just
	 * release the call-site's own temporary hold on upstream. */
	session_put(upstream);
	/* fall through */

out_idle:
	/* This call left conn without one. If it was the reason conn was kept
	 * alive at all -- the fast path zeroed the target's linger window the
	 * moment it decided to reuse this tunnel, and a call that then fails
	 * before creating a session never reaches l2tp_session_free() to
	 * restart it -- conn would sit here session-less forever. Restart the
	 * linger instead, so a tunnel nothing managed to use still closes
	 * itself. Guarded on conn's own session count, which this context
	 * owns: other calls' sessions on the same tunnel keep it out of this
	 * entirely. */
	if (conn->state == STATE_ESTB && conn->sess_count == 0)
		l2tp_switch_target_arm_idle_linger(target, conn);
}

/* What a scheduled (cross-context) call placement carries, since
 * triton_context_call() passes a single pointer and the tunnel to place the
 * call on has to travel with the session rather than be looked up again on
 * the far side. Mirrors l2tp_switch_finish_ctx's existing use of the same
 * pattern for l2tp_switch_finish_upstream(). */
struct l2tp_switch_place_ctx {
	struct l2tp_sess_t *upstream;
	struct l2tp_conn_t *conn;
};

static void l2tp_switch_place_call(void *data)
{
	struct l2tp_switch_place_ctx *ctx = data;
	struct l2tp_sess_t *upstream = ctx->upstream;
	struct l2tp_conn_t *conn = ctx->conn;

	_free(ctx);
	l2tp_switch_place_call_on(upstream, conn);
	tunnel_put(conn); /* the hold taken when this call was scheduled, which
			   * is what kept conn alive across the context hop */
}

/* Opens a connect budget for this target: arms the timer that bounds how long
 * queued calls may wait, and records the deadline it was armed for. Caller
 * holds target->lock. Returns -1 if the budget could not be armed, in which
 * case no budget is opened -- queueing a call behind an unbounded wait would
 * be worse than failing it now. */
static int l2tp_switch_open_connect_budget_locked(struct l2tp_switch_target_t *target)
{
	uint64_t now = l2tp_switch_monotonic_ms();
	int res;

	target->connect_timeout_timer.expire = l2tp_switch_on_demand_timeout;
	target->connect_timeout_timer.period =
		l2tp_switch_conf_connect_timeout_ms();

	/* The timer can still be armed from a previous budget that was closed
	 * by the drain rather than cancelled (see
	 * l2tp_switch_drain_pending_calls() for why it doesn't cancel). Push
	 * it out to a full budget from now instead of adding a second
	 * registration over the top of it -- and instead of inheriting its
	 * near-expired deadline, which would give this call a budget of
	 * whatever happened to be left. */
	if (target->connect_timeout_timer.tpd)
		res = triton_timer_mod(&target->connect_timeout_timer, 0);
	else
		res = triton_timer_add(NULL, &target->connect_timeout_timer, 0);

	if (res < 0) {
		log_error("l2tp-switch: target \"%s\": failed to arm on-demand"
			  " connect timeout\n", target->name);
		return -1;
	}

	/* Read before arming, so the timer's own expiry is never earlier than
	 * the deadline the callback compares against. */
	target->connect_deadline = now + l2tp_switch_conf_connect_timeout_ms();
	target->connect_budget_open = 1;

	return 0;
}

/* Queues this call behind an on-demand target's in-flight connect, opening a
 * connect budget if this is the call that woke the target up.
 *
 * Caller holds target->lock and keeps holding it (queueing and the
 * budget/timer bookkeeping have to be one atomic step: a tunnel that comes up
 * in between would drain a queue this call isn't in yet, leaving it stuck
 * until the budget expires). *need_connect is set when the caller must kick
 * off the actual connect, which it does after dropping the lock.
 *
 * Returns -1 (and queues nothing) if the target already has more calls
 * waiting than it is allowed to accumulate, or if the budget bounding that
 * wait could not be armed. */
static int l2tp_switch_enqueue_call_locked(struct l2tp_sess_t *upstream,
					   struct l2tp_switch_target_t *target,
					   int *need_connect)
{
	*need_connect = 0;

	if (target->pending_count >= L2TP_SWITCH_PENDING_MAX) {
		log_session(log_error, upstream, "l2tp-switch: target \"%s\""
			    " pending-call queue full, disconnecting"
			    " upstream call\n", target->name);
		return -1;
	}

	/* Before queueing anything, so a failure here needs no rollback. */
	if (!target->connect_budget_open) {
		if (l2tp_switch_open_connect_budget_locked(target) < 0)
			return -1;
		*need_connect = 1;
	}

	session_hold(upstream); /* released by whoever dequeues this call:
				 * l2tp_switch_place_call_on() via the drain,
				 * or l2tp_switch_disconnect_upstream() via the
				 * connect timeout */
	list_add_tail(&upstream->switch_pending_entry, &target->pending_calls);
	target->pending_count++;

	return 0;
}

/* Fast path of l2tp_switch_place_downstream_call(): hands the placement over
 * to the target tunnel's own context. Consumes the tunnel_hold() the caller
 * took on `conn`, on every path. Returns 0 if the hand-over was scheduled,
 * -1 if not (the caller then disconnects the upstream call). */
static int l2tp_switch_place_via_tunnel(struct l2tp_sess_t *upstream,
					struct l2tp_switch_target_t *target,
					struct l2tp_conn_t *conn)
{
	struct l2tp_switch_place_ctx *place;
	int res = -1;

	/* Placing the downstream call touches conn's own tunnel context, which
	 * is not upstream's context -- cross via triton_context_call, same as
	 * l2tp_create_session_exec() already does for the CLI path. */
	place = _malloc(sizeof(*place));
	if (!place) {
		log_session(log_error, upstream, "l2tp-switch: placing"
			    " downstream call failed: out of memory\n");
		goto fail;
	}
	place->upstream = upstream;
	place->conn = conn;

	session_hold(upstream);
	/* ctx_lock + ctx.tpd, the same guard the apses paths already use for
	 * their cross-context hops: the tunnel_hold() pins conn's memory, but
	 * l2tp_tunnel_free() can have unregistered its context since the
	 * target->lock check in the caller, and triton_context_call() would
	 * then spin_lock(NULL). "Context gone" is just another way to reach
	 * the failure cleanup below. */
	pthread_mutex_lock(&conn->ctx_lock);
	if (conn->ctx.tpd)
		res = triton_context_call(&conn->ctx, l2tp_switch_place_call,
					  place);
	pthread_mutex_unlock(&conn->ctx_lock);
	if (res < 0) {
		session_put(upstream);
		_free(place);
		goto fail;
	}

	return 0;

fail:
	/* This call is not going to use the tunnel after all, and the linger
	 * the caller cancelled is the only thing that would ever have closed
	 * it: cancelling is a promise to use the tunnel, and a broken promise
	 * has to put the window back. */
	l2tp_switch_target_arm_idle_linger(target, conn);
	tunnel_put(conn);
	return -1;
}

static int l2tp_switch_place_downstream_call(struct l2tp_sess_t *upstream)
{
	struct l2tp_switch_target_t *target = upstream->switch_target;
	struct l2tp_conn_t *conn;
	int need_connect;
	int queued;

	pthread_mutex_lock(&target->lock);
	conn = target->tunnel;
	if (conn && conn->state == STATE_ESTB) {
		/* Fast path: tunnel already usable (persistent mode always
		 * takes this path when it's going to succeed at all; on-demand
		 * takes it once its own idle/lingering tunnel is reused).
		 * Cancel any linger-teardown armed for it before this call
		 * starts using it again -- by closing the window, not by
		 * deleting the timer: this runs in the *upstream* session's
		 * context, and idle_timer belongs to the default context,
		 * where l2tp_switch_target_idle_timer() retires it on its next
		 * tick. (Same rule connect_timeout_timer already follows; see
		 * l2tp_switch_drain_pending_calls().) */
		target->idle_deadline = 0;
		tunnel_hold(conn); /* taken while the lock still guarantees conn
				    * is alive: it has to outlive the hop into
				    * its own context below */
		pthread_mutex_unlock(&target->lock);

		return l2tp_switch_place_via_tunnel(upstream, target, conn);
	}

	if (target->mode == L2TP_SWITCH_MODE_PERSISTENT) {
		/* Unchanged from before this feature: a persistent target's
		 * tunnel is expected to already be up. */
		pthread_mutex_unlock(&target->lock);
		return -1;
	}

	/* on-demand, no usable tunnel right now: queue and make sure a
	 * connect attempt is in flight. */
	queued = l2tp_switch_enqueue_call_locked(upstream, target, &need_connect);
	pthread_mutex_unlock(&target->lock);

	if (queued < 0)
		return -1; /* both of its failure branches log their own
			    * reason; l2tp_recv_ICCN() logs the disconnect
			    * that follows from this return */

	if (need_connect)
		l2tp_switch_target_connect(target); /* safe from any context --
			same precedent as the existing CLI "l2tp create tunnel"
			path, which already calls this indirectly from a
			CLI-thread context */

	return 0;
}

static int l2tp_recv_ICCN(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_ICCN) {
		log_session(log_warn, sess, "discarding unexpected ICCN\n");
		return 0;
	}

	log_session(log_info2, sess, "handling ICCN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		/* Same generic match attempt as l2tp_recv_ICRQ, run here too:
		 * some AVPs worth routing on (Proxy-Authen-Name, carrying
		 * the upstream LAC's proxied username/realm) only ever appear in ICCN, not
		 * ICRQ -- see l2tp_switch_match()'s own doc comment for why
		 * offering every AVP's raw value is safe regardless of this
		 * AVP's real type. Runs before the switch below so that, if
		 * this same AVP is the one that matches (Proxy-Authen-Name
		 * itself, most commonly), sess->switch_target is already set
		 * by the time that case is reached and the existing capture
		 * logic there correctly captures it for forwarding. */
		if (!sess->switch_target) {
			sess->switch_target = l2tp_switch_match(attr->attr,
								attr->val.octets,
								attr->length);
			if (sess->switch_target) {
				l2tp_stat_inc(&l2tp_stat.switch_matched);
				log_session(log_info1, sess,
					    "call matches l2tp-switch"
					    " target \"%s\"\n",
					    sess->switch_target->name);
			}
		}

		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
		case TX_Speed:
		case Framing_Type:
			break;
		case Init_Recv_LCP:
		case Last_Sent_LCP:
		case Last_Recv_LCP:
		case Proxy_Authen_Type:
		case Proxy_Authen_Name:
		case Proxy_Authen_Challenge:
		case Proxy_Authen_ID:
		case Proxy_Authen_Response:
			/* These are the only AVPs actually worth re-injecting
			 * into the downstream leg's own ICCN -- unlike
			 * Message_Type/TX_Speed/Framing_Type above (whose
			 * dictionary types are int16/int32, not octets;
			 * l2tp_switch_capture_avp() unconditionally reads
			 * attr->val.octets, which for those types
			 * reinterprets a small integer as a pointer and
			 * crashes on the memcpy -- confirmed by reproducing
			 * this exact segfault on a real VM before narrowing
			 * the case grouping to just these AVPs).
			 *
			 * Deliberately NOT gated on sess->switch_target: the
			 * match attempt above only sets it once the AVP it
			 * actually matches on is reached, which for an
			 * ICCN-time match (Proxy-Authen-Name, most commonly)
			 * can be *after* Proxy-Authen-Type -- Type is
			 * attribute id 29, numerically (and so positionally,
			 * on every encoder checked against this) ahead of
			 * Name/Challenge/ID/Response. Gating capture on
			 * switch_target already being set silently dropped
			 * Type alone whenever the match rule matched a later
			 * AVP in the same ICCN, while Name/Response (visited
			 * after the match fired) were captured fine --
			 * confirmed against a partner's own capture of the
			 * switch's outbound ICCN. Capturing unconditionally
			 * costs nothing for a call that turns out not to be
			 * switched: l2tp_session_free() already frees
			 * sess->switch_avps regardless of switch_target (see
			 * l2tp_switch_unpair()). */
			if (l2tp_switch_capture_avp(sess, attr) < 0) {
				log_session(log_error, sess,
					    "impossible to handle ICCN:"
					    " capturing proxy AVP failed\n");
				l2tp_session_disconnect(sess, 2, 6);
				return -1;
			}
			break;
		case Private_Group_ID:
		case RX_Speed:
			break;
		case Sequencing_Required:
			if (conf_dataseq != L2TP_DATASEQ_DENY)
				sess->send_seq = 1;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					     " %i in ICCN\n", attr->attr->id);
			break;
		}
	}

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle ICCN:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	if (sess->switch_target) {
		/* Connect the upstream leg's own kernel socket right now,
		 * rather than waiting for the downstream leg's handshake to
		 * finish (the old l2tp_switch_finish_upstream() timing) --
		 * matching exactly when the non-switch path below already
		 * does it for an ordinary call. Once connect() registers this
		 * session with the kernel's L2TP subsystem, any data frame
		 * the real upstream peer sends is held in this socket's own
		 * (already forced to L2TP_SWITCH_SOCKBUF_SIZE) receive
		 * buffer until something reads it -- exactly the same
		 * absorb-a-burst mechanism l2tp_switch_set_sockbuf() already
		 * relies on elsewhere. Before this, the kernel has no session
		 * registered for this ID at all and silently drops the
		 * frame; on an on-demand target with no already-warm tunnel,
		 * the downstream handshake this triggers below can easily
		 * take longer than the real peer waits before sending its
		 * first live PPP frame. */
		if (l2tp_session_connect_socket(sess, 0) < 0) {
			log_session(log_error, sess,
				    "impossible to switch call:"
				    " connecting upstream kernel socket"
				    " failed, disconnecting session\n");
			l2tp_session_disconnect(sess, 2, 6);

			return -1;
		}

		if (l2tp_switch_place_downstream_call(sess) < 0) {
			log_session(log_error, sess,
				    "impossible to switch call:"
				    " placing downstream call failed,"
				    " disconnecting session\n");
			l2tp_session_disconnect(sess, 2, 6);

			return -1;
		}

		return 0;
	}

	if (l2tp_session_connect(sess)) {
		log_session(log_error, sess, "impossible to handle ICCN:"
			    " connecting session failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	return 0;
}

static int l2tp_session_outcall_reply(struct l2tp_sess_t *sess)
{
	if (triton_timer_add(&sess->paren_conn->ctx,
			     &sess->timeout_timer, 0) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to outgoing call:"
			    " setting establishment timer failed\n");
		goto err;
	}

	if (l2tp_send_OCRP(sess) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to outgoing call:"
			    " sending OCRP failed\n");
		goto err_timer;
	}
	if (l2tp_send_OCCN(sess) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to outgoing call:"
			    " sending OCCN failed\n");
		goto err_timer;
	}

	if (l2tp_session_connect(sess) < 0) {
		log_session(log_error, sess,
			    "impossible to reply to outgoing call:"
			    " connecting session failed\n");
		goto err_timer;
	}

	return 0;

err_timer:
	triton_timer_del(&sess->timeout_timer);
err:
	return -1;
}

static int l2tp_recv_OCRQ(struct l2tp_conn_t *conn,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;
	struct l2tp_sess_t *sess = NULL;
	uint16_t peer_sid = 0;
	uint16_t sid = 0;
	uint16_t res;
	uint16_t err;

	if (conn->state != STATE_ESTB && !conn->lns_mode) {
		log_tunnel(log_warn, conn, "discarding unexpected OCRQ\n");
		return 0;
	}

	if (ap_shutdown) {
		log_tunnel(log_warn, conn, "shutdown in progress,"
			   " discarding OCRQ\n");
		return 0;
	}

	if (conf_max_starting && ap_session_stat_starting() >= conf_max_starting)
		return 0;

	if (conf_max_sessions && ap_session_stat_active() + ap_session_stat_starting() >= conf_max_sessions)
		return 0;

	if (triton_module_loaded("connlimit")
	    && connlimit_check(cl_key_from_ipv4(conn->peer_addr.sin_addr.s_addr))) {
		log_tunnel(log_warn, conn, "connection limits reached,"
			   " discarding OCRQ\n");
		return 0;
	}

	log_tunnel(log_info2, conn, "handling OCRQ\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
		case Call_Serial_Number:
		case Minimum_BPS:
		case Maximum_BPS:
		case Bearer_Type:
		case Framing_Type:
		case Called_Number:
		case Sub_Address:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else {
				log_tunnel(log_warn, conn,
					   "discarding unknown attribute type"
					   " %i in OCRQ\n", attr->attr->id);
			}
			break;
		}
	}

	if (assigned_sid == NULL) {
		log_tunnel(log_error, conn, "impossible to handle OCRQ:"
			   " no Assigned Session ID present in message,"
			   " disconnecting session\n");
		res = 2;
		err = 6;
		goto out_cancel;
	}

	peer_sid = assigned_sid->val.uint16;

	sess = l2tp_tunnel_alloc_session(conn);
	if (sess == NULL) {
		log_tunnel(log_error, conn, "impossible to handle OCRQ:"
			   " session allocation failed,"
			   " disconnecting session\n");
		res = 2;
		err = 4;
		goto out_cancel;
	}

	sess->peer_sid = peer_sid;
	sid = sess->sid;

	if (unknown_attr) {
		log_tunnel(log_error, conn, "impossible to handle OCRQ:"
			   " unknown mandatory attribute type %i,"
			   " disconnecting session\n",
			   unknown_attr->attr->id);
		res = 2;
		err = 8;
		goto out_cancel;
	}

	if (l2tp_session_outcall_reply(sess) < 0) {
		log_tunnel(log_error, conn, "impossible to handle OCRQ:"
			   " starting session failed,"
			   " disconnecting session\n");
		res = 2;
		err = 4;
		goto out_cancel;
	}

	log_tunnel(log_info1, conn, "new session %hu-%hu created following"
		   " reception of OCRQ\n", sid, peer_sid);

	return 0;

out_cancel:
	if (l2tp_tunnel_send_CDN(sid, peer_sid, res, err) < 0)
		log_tunnel(log_warn, conn,
			   "impossible to reject OCRQ:"
			   " sending CDN failed\n");
	if (sess)
		l2tp_session_free(sess);

	return -1;
}

static int l2tp_recv_OCRP(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_OCRP) {
		log_session(log_warn, sess, "discarding unexpected OCRP\n");
		return 0;
	}

	log_session(log_info2, sess, "handling OCRP\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					    " %i in OCRP\n", attr->attr->id);
			break;
		}
	}

	if (assigned_sid == NULL) {
		log_session(log_error, sess, "impossible to handle OCRP:"
			    " no Assigned Session ID present in message,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	/* Set peer_sid as soon as possible so that CDN
	   will be sent to the right tunnel in case of error */
	log_session(log_info2, sess, "peer-sid set to %hu by OCRP\n",
		    assigned_sid->val.uint16);
	sess->peer_sid = assigned_sid->val.uint16;

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle OCRP:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	sess->state1 = STATE_WAIT_OCCN;

	return 0;
}

static int l2tp_recv_OCCN(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *unknown_attr = NULL;
	const struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_OCCN) {
		log_session(log_warn, sess, "discarding unexpected OCCN\n");
		return 0;
	}

	log_session(log_info2, sess, "handling OCCN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Random_Vector:
		case TX_Speed:
		case Framing_Type:
			break;
		case Sequencing_Required:
			if (conf_dataseq != L2TP_DATASEQ_DENY)
				sess->send_seq = 1;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					     " %i in OCCN\n", attr->attr->id);
			break;
		}
	}

	if (unknown_attr) {
		log_session(log_error, sess, "impossible to handle OCCN:"
			    " unknown mandatory attribute type %i,"
			    " disconnecting session\n",
			    unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);

		return -1;
	}

	if (l2tp_session_connect(sess) < 0) {
		log_session(log_error, sess, "impossible to handle OCCN:"
			    " connecting session failed,"
			    " disconnecting session\n");
		l2tp_session_disconnect(sess, 2, 6);

		return -1;
	}

	return 0;
}

static int l2tp_recv_CDN(struct l2tp_sess_t *sess,
			 const struct l2tp_packet_t *pack)
{
	const struct l2tp_attr_t *assigned_sid = NULL;
	const struct l2tp_attr_t *result_code = NULL;
	const struct l2tp_attr_t *attr = NULL;
	char *err_msg = NULL;
	uint16_t res = 0;
	uint16_t err = 0;

	if (sess->state1 == STATE_CLOSE) {
		log_session(log_warn, sess, "discarding unexpected CDN\n");

		return 0;
	}

	log_session(log_info2, sess, "handling CDN\n");

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
		case Random_Vector:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		case Result_Code:
			result_code = attr;
			break;
		default:
			if (attr->M) {
				log_session(log_warn, sess,
					    "discarding unknown attribute type"
					    " %i in CDN\n", attr->attr->id);
			}
			break;
		}
	}

	if (assigned_sid) {
		if (sess->peer_sid == 0) {
			log_session(log_info2, sess,
				    "peer-sid set to %hu by CDN\n",
				    assigned_sid->val.uint16);
			sess->peer_sid = assigned_sid->val.uint16;
		} else if (sess->peer_sid != assigned_sid->val.uint16) {
			log_session(log_warn, sess,
				    "discarding invalid Assigned Session ID"
				    " %hu in CDN\n", assigned_sid->val.uint16);
		}
	} else {
		log_session(log_warn, sess,
			    "no Assigned Session ID present in CDN\n");
	}

	if (result_code) {
		if (rescode_get_data(result_code, &res, &err, &err_msg) < 0) {
			log_session(log_warn, sess,
				    "invalid Result Code in CDN\n");
		}
	} else {
		log_session(log_warn, sess,
			    "no Result Code present in CDN\n");
	}

	log_session(log_info1, sess, "CDN received from peer (result: %hu,"
		    " error: %hu%s%s%s), disconnecting session\n",
		    res, err, err_msg ? ", message: \"" : "",
		    err_msg ? err_msg : "", err_msg ? "\"" : "");

	if (err_msg)
		_free(err_msg);

	/* Too late to send outstanding messages */
	l2tp_session_clear_sendqueue(sess);

	l2tp_session_free(sess);

	return 0;
}

static int l2tp_tunnel_recv_CDN(struct l2tp_conn_t *conn,
				const struct l2tp_packet_t *pack)
{
	if (conn->state != STATE_ESTB) {
		log_tunnel(log_warn, conn, "discarding unexpected CDN\n");

		return 0;
	}

	log_tunnel(log_warn, conn, "discarding CDN with no Session ID:"
		   " disconnecting sessions using Assigned Session ID is currently not supported\n");

	return 0;
}

static int l2tp_recv_WEN(struct l2tp_sess_t *sess,
			 const struct l2tp_packet_t *pack)
{
	if (sess->state1 != STATE_ESTB || !sess->paren_conn->lns_mode) {
		log_session(log_warn, sess, "discarding unexpected WEN\n");

		return 0;
	}

	log_session(log_info2, sess, "handling WEN\n");

	return 0;
}

static int l2tp_recv_SLI(struct l2tp_sess_t *sess,
			 const struct l2tp_packet_t *pack)
{
	if (sess->state1 != STATE_ESTB || sess->paren_conn->lns_mode) {
		log_session(log_warn, sess, "discarding unexpected SLI\n");

		return 0;
	}

	log_session(log_info2, sess, "handling SLI\n");

	return 0;
}

static int l2tp_session_place_call(struct l2tp_sess_t *sess)
{
	int res;

	if (triton_timer_add(&sess->paren_conn->ctx,
			     &sess->timeout_timer, 0) < 0) {
		log_session(log_error, sess,
			    "impossible to place %s call:"
			    " setting establishment timer failed\n",
			    sess->lns_mode ? "outgoing" : "incoming");
		goto err;
	}

	if (sess->lns_mode)
		res = l2tp_send_OCRQ(sess);
	else
		res = l2tp_send_ICRQ(sess);

	if (res < 0) {
		log_session(log_error, sess,
			    "impossible to place %s call:"
			    " sending %cCRQ failed\n",
			    sess->lns_mode ? "outgoing" : "incoming",
			    sess->lns_mode ? 'O' : 'I');
		goto err_timer;
	}

	sess->state1 = sess->lns_mode ? STATE_WAIT_OCRP : STATE_WAIT_ICRP;

	return 0;

err_timer:
	triton_timer_del(&sess->timeout_timer);
err:
	return -1;
}

static void l2tp_tunnel_create_session(void *data)
{
	struct l2tp_conn_t *conn = data;
	struct l2tp_sess_t *sess = NULL;
	uint16_t sid;

	if (conn->state != STATE_ESTB) {
		log_tunnel(log_error, conn, "impossible to create session:"
			   " tunnel is not connected\n");
		return;
	}

	sess = l2tp_tunnel_alloc_session(conn);
	if (sess == NULL) {
		log_tunnel(log_error, conn, "impossible to create session:"
			   " session allocation failed\n");
		return;
	}
	sid = sess->sid;

	if (l2tp_session_place_call(sess) < 0) {
		log_tunnel(log_error, conn, "impossible to create session:"
			   " starting session failed\n");
		l2tp_session_free(sess);

		return;
	}

	if (l2tp_tunnel_push_sendqueue(conn) < 0) {
		log_tunnel(log_error, conn, "impossible to create session:"
			   " transmitting messages from send queue failed\n");
		l2tp_session_free(sess);

		return;
	}

	log_tunnel(log_info1, conn, "new session %hu created following"
		   " request from command line interface\n", sid);
}

static void l2tp_session_recv(struct l2tp_sess_t *sess,
			      const struct l2tp_packet_t *pack,
			      uint16_t msg_type, int mandatory)
{
	switch (msg_type) {
	case Message_Type_Start_Ctrl_Conn_Request:
	case Message_Type_Start_Ctrl_Conn_Reply:
	case Message_Type_Start_Ctrl_Conn_Connected:
	case Message_Type_Stop_Ctrl_Conn_Notify:
	case Message_Type_Hello:
	case Message_Type_Outgoing_Call_Request:
	case Message_Type_Incoming_Call_Request:
		log_session(log_warn, sess,
			    "discarding tunnel specific message type %hu\n",
			    msg_type);
		break;
	case Message_Type_Outgoing_Call_Reply:
		l2tp_recv_OCRP(sess, pack);
		break;
	case Message_Type_Outgoing_Call_Connected:
		l2tp_recv_OCCN(sess, pack);
		break;
	case Message_Type_Incoming_Call_Reply:
		l2tp_recv_ICRP(sess, pack);
		break;
	case Message_Type_Incoming_Call_Connected:
		l2tp_recv_ICCN(sess, pack);
		break;
	case Message_Type_Call_Disconnect_Notify:
		l2tp_recv_CDN(sess, pack);
		break;
	case Message_Type_WAN_Error_Notify:
		l2tp_recv_WEN(sess, pack);
		break;
	case Message_Type_Set_Link_Info:
		l2tp_recv_SLI(sess, pack);
		break;
	default:
		if (mandatory) {
			log_session(log_error, sess,
				    "impossible to handle unknown mandatory message type %hu,"
				    " disconnecting session\n", msg_type);
			l2tp_session_disconnect(sess, 2, 8);
		} else {
			log_session(log_warn, sess,
				    "discarding unknown message type %hu\n",
				    msg_type);
		}
		break;
	}
}

static void l2tp_tunnel_recv(struct l2tp_conn_t *conn,
			     const struct l2tp_packet_t *pack,
			     uint16_t msg_type, int mandatory)
{
	switch (msg_type) {
	case Message_Type_Start_Ctrl_Conn_Request:
		log_tunnel(log_warn, conn, "discarding unexpected SCCRQ\n");
		break;
	case Message_Type_Start_Ctrl_Conn_Reply:
		l2tp_recv_SCCRP(conn, pack);
		break;
	case Message_Type_Start_Ctrl_Conn_Connected:
		l2tp_recv_SCCCN(conn, pack);
		break;
	case Message_Type_Stop_Ctrl_Conn_Notify:
		l2tp_recv_StopCCN(conn, pack);
		break;
	case Message_Type_Hello:
		l2tp_recv_HELLO(conn, pack);
		break;
	case Message_Type_Outgoing_Call_Request:
		l2tp_recv_OCRQ(conn, pack);
		break;
	case Message_Type_Incoming_Call_Request:
		l2tp_recv_ICRQ(conn, pack);
		break;
	case Message_Type_Call_Disconnect_Notify:
		l2tp_tunnel_recv_CDN(conn, pack);
		break;
	case Message_Type_Outgoing_Call_Reply:
	case Message_Type_Outgoing_Call_Connected:
	case Message_Type_Incoming_Call_Reply:
	case Message_Type_Incoming_Call_Connected:
	case Message_Type_WAN_Error_Notify:
	case Message_Type_Set_Link_Info:
		log_tunnel(log_warn, conn,
			   "discarding session specific message type %hu\n",
			   msg_type);
		break;
	default:
		if (mandatory) {
			log_tunnel(log_error, conn,
				   "impossible to handle unknown mandatory message type %hu,"
				   " disconnecting tunnel\n", msg_type);
			l2tp_tunnel_disconnect(conn, 2, 8);
		} else {
			log_tunnel(log_warn, conn,
				   "discarding unknown message type %hu\n",
				   msg_type);
		}
		break;
	}
}

static int l2tp_tunnel_store_msg(struct l2tp_conn_t *conn,
				 struct l2tp_packet_t *pack,
				 int *need_ack)
{
	uint16_t pack_Ns = ntohs(pack->hdr.Ns);
	uint16_t pack_Nr = ntohs(pack->hdr.Nr);
	uint16_t indx;

	/* Drop packets which acknowledge more packets than have actually
	 * been sent.
	 */
	if (nsnr_cmp(conn->Ns, pack_Nr) < 0) {
		log_tunnel(log_warn, conn,
			   "discarding message acknowledging unsent packets"
			   " (packet Ns/Nr: %hu/%hu, tunnel Ns/Nr: %hu/%hu)\n",
			   pack_Ns, pack_Nr, conn->Ns, conn->Nr);

		return -1;
	}

	/* Update peer Nr only when new packets are acknowledged */
	if (nsnr_cmp(pack_Nr, conn->peer_Nr) > 0)
		conn->peer_Nr = pack_Nr;

	if (l2tp_packet_is_ZLB(pack)) {
		log_tunnel(log_debug, conn, "handling ZLB\n");
		if (conf_verbose) {
			log_tunnel(log_debug, conn, "recv ");
			l2tp_packet_print(pack, log_debug);
		}

		return -1;
	}

	/* From now on, acknowledgement has to be sent in any case:
	 * -If the received packet is a duplicated message, the ack will
	 *  let the peer know we received its message (in case our
	 *  previous ack was lost).
	 *
	 * -If the received packet is an out of order message (whether or not
	 *  it fits in our reception window), the ack will explicitly tell the
	 *  peer which message number we're missing.
	 */
	*need_ack = 1;

	/* Drop duplicate messages */
	if (nsnr_cmp(pack_Ns, conn->Nr) < 0) {
		log_tunnel(log_info2, conn, "handling duplicate message"
			   " (packet Ns/Nr: %hu/%hu, tunnel Ns/Nr: %hu/%hu)\n",
			   pack_Ns, pack_Nr, conn->Ns, conn->Nr);

		return -1;
	}

	/* Drop out of order messages which don't fit in our reception queue.
	 * This means that the peer doesn't respect our receive window, so use
	 * log_warn.
	 */
	indx = pack_Ns - conn->Nr;
	if (indx >= conn->recv_queue_sz) {
		log_tunnel(log_warn, conn, "discarding out of order message"
			   " (packet Ns/Nr: %hu/%hu, tunnel Ns/Nr: %hu/%hu,"
			   " tunnel reception window size: %hu bytes)\n",
			   pack_Ns, pack_Nr, conn->Ns, conn->Nr,
			   conn->recv_queue_sz);

		return -1;
	}

	/* Drop duplicate out of order messages */
	indx = (indx + conn->recv_queue_offt) % conn->recv_queue_sz;
	if (conn->recv_queue[indx]) {
		log_tunnel(log_info2, conn,
			   "discarding duplicate out of order message"
			   " (packet Ns/Nr: %hu/%hu, tunnel Ns/Nr: %hu/%hu)\n",
			   pack_Ns, pack_Nr, conn->Ns, conn->Nr);

		return -1;
	}

	conn->recv_queue[indx] = pack;

	return 0;
}

static int l2tp_tunnel_reply(struct l2tp_conn_t *conn, int need_ack)
{
	const struct l2tp_attr_t *msg_attr = NULL;
	struct l2tp_packet_t *pack;
	struct l2tp_sess_t *sess;
	uint16_t msg_sid;
	uint16_t msg_type;
	uint16_t id = conn->recv_queue_offt;
	unsigned int pkt_count = 0;
	int res;

	/* Loop over reception queue, break as as soon as there is no more
	 * message to process or if tunnel gets closed.
	 */
	do {
		if (conn->recv_queue[id] == NULL || conn->state == STATE_CLOSE)
			break;

		pack = conn->recv_queue[id];
		conn->recv_queue[id] = NULL;
		++conn->Nr;
		++pkt_count;
		id = (id + 1) % conn->recv_queue_sz;

		/* We may receive packets even while disconnecting (e.g.
		 * packets sent by peer before we disconnect, but received
		 * later on, or peer retransmissions due to our acknowledgement
		 * getting lost).
		 * We don't have to process these messages, but we still
		 * dequeue them all to send proper acknowledgement (to avoid
		 * useless retransmissions from peer). Log with log_info2 since
		 * there's nothing wrong with receiving messages at this stage.
		 */
		if (conn->state == STATE_FIN ||
		    conn->state == STATE_FIN_WAIT) {
			log_tunnel(log_info2, conn,
				   "discarding message received while disconnecting\n");
			l2tp_packet_free(pack);
			continue;
		}

		/* ZLB aren't stored in the reception queue, so we're sure that
		 * pack->attrs isn't an empty list.
		 */
		msg_attr = list_first_entry(&pack->attrs, typeof(*msg_attr),
					    entry);
		if (msg_attr->attr->id != Message_Type) {
			log_tunnel(log_warn, conn,
				   "discarding message with invalid first attribute type %hu\n",
				   msg_attr->attr->id);
			l2tp_packet_free(pack);
			continue;
		}
		msg_type = msg_attr->val.uint16;

		if (conf_verbose) {
			if (msg_type == Message_Type_Hello) {
				log_tunnel(log_debug, conn, "recv ");
				l2tp_packet_print(pack, log_debug);
			} else {
				log_tunnel(log_info2, conn, "recv ");
				l2tp_packet_print(pack, log_info2);
			}
		}

		msg_sid = ntohs(pack->hdr.sid);
		if (msg_sid) {
			sess = l2tp_tunnel_get_session(conn, msg_sid);
			if (sess == NULL) {
				log_tunnel(log_warn, conn,
					   "discarding message with invalid Session ID %hu\n",
					   msg_sid);
				l2tp_packet_free(pack);
				continue;
			}
			l2tp_session_recv(sess, pack, msg_type, msg_attr->M);
		} else {
			l2tp_tunnel_recv(conn, pack, msg_type, msg_attr->M);
		}

		l2tp_packet_free(pack);
	} while (id != conn->recv_queue_offt);

	conn->recv_queue_offt = (conn->recv_queue_offt + pkt_count) % conn->recv_queue_sz;

	log_tunnel(log_debug, conn,
		   "%u message%s processed from reception queue\n",
		   pkt_count, pkt_count > 1 ? "s" : "");

	res = l2tp_tunnel_push_sendqueue(conn);
	if (res == 0 && need_ack)
		res = l2tp_send_ZLB(conn);

	return res;
}

static int l2tp_conn_read(struct triton_md_handler_t *h)
{
	struct l2tp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct l2tp_packet_t *pack;
	unsigned int pkt_count = 0;
	int need_ack = 0;
	int res;

	/* Hold the tunnel. This allows any function we call to free the
	 * tunnel while still keeping the tunnel valid until we return.
	 */
	tunnel_hold(conn);

	while (1) {
		res = l2tp_recv(h->fd, &pack, NULL,
				conn->secret, conn->secret_len);
		if (res) {
			if (res == -2) {
				log_tunnel(log_info1, conn,
					   "peer is unreachable,"
					   " disconnecting tunnel\n");
				goto err_tunfree;
			}

			break;
		}

		if (!pack)
			continue;

		if (conn->port_set == 0) {
			/* Get peer's first reply source port and use it as
			   destination port for further outgoing messages */
			log_tunnel(log_info2, conn,
				   "setting peer port to %hu\n",
				   ntohs(pack->addr.sin_port));
			res = l2tp_tunnel_update_peerport(conn,
							  pack->addr.sin_port);
			if (res < 0) {
				log_tunnel(log_error, conn,
					   "peer port update failed,"
					   " disconnecting tunnel\n");
				l2tp_packet_free(pack);
				goto err_tunfree;
			}
			conn->port_set = 1;
		}

		if (ntohs(pack->hdr.tid) != conn->tid && (pack->hdr.tid || !conf_dir300_quirk)) {
			log_tunnel(log_warn, conn,
				   "discarding message with invalid tid %hu\n",
				   ntohs(pack->hdr.tid));
			l2tp_packet_free(pack);
			continue;
		}

		if (l2tp_tunnel_store_msg(conn, pack, &need_ack) < 0) {
			l2tp_packet_free(pack);
			continue;
		}

		++pkt_count;
	}

	log_tunnel(log_debug, conn, "%u message%s added to reception queue\n",
		   pkt_count, pkt_count > 1 ? "s" : "");

	/* Drop acknowledged packets from retransmission queue */
	if (l2tp_tunnel_clean_rtmsqueue(conn) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to handle incoming message:"
			   " cleaning retransmission queue failed,"
			   " deleting tunnel\n");
		goto err_tunfree;
	}

	if (l2tp_tunnel_reply(conn, need_ack) < 0) {
		log_tunnel(log_error, conn,
			   "impossible to reply to incoming messages:"
			   " message transmission failed,"
			   " deleting tunnel\n");
		goto err_tunfree;
	}

	if (conn->state == STATE_FIN && list_empty(&conn->send_queue) &&
	    list_empty(&conn->rtms_queue)) {
		log_tunnel(log_info2, conn,
			   "tunnel disconnection acknowledged by peer,"
			   " deleting tunnel\n");
		goto err_tunfree;
	}

	/* Use conn->state to detect tunnel deletion */
	if (conn->state == STATE_CLOSE)
		goto err;

	tunnel_put(conn);

	return 0;

err_tunfree:
	l2tp_tunnel_free(conn);
err:
	tunnel_put(conn);

	return -1;
}

static int l2tp_udp_read(struct triton_md_handler_t *h)
{
	struct l2tp_serv_t *serv = container_of(h, typeof(*serv), hnd);
	struct l2tp_packet_t *pack;
	const struct l2tp_attr_t *msg_type = NULL;
	struct in_pktinfo pkt_info;
	char src_addr[17];

	while (1) {
		if (l2tp_recv(h->fd, &pack, &pkt_info,
			      conf_secret, conf_secret_len) < 0)
			break;

		if (!pack)
			continue;

		u_inet_ntoa(pack->addr.sin_addr.s_addr, src_addr);

		if (iprange_client_check(pack->addr.sin_addr.s_addr)) {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " IP address is out of client-ip-range\n",
				 src_addr);
			goto skip;
		}

		if (pack->hdr.tid) {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " invalid tid %hu\n",
				 src_addr, ntohs(pack->hdr.tid));
			goto skip;
		}

		if (list_empty(&pack->attrs)) {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " message is empty\n", src_addr);
			goto skip;
		}

		msg_type = list_entry(pack->attrs.next, typeof(*msg_type), entry);
		if (msg_type->attr->id != Message_Type) {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " invalid first attribute type %i\n",
				 src_addr, msg_type->attr->id);
			goto skip;
		}

		if (conf_verbose) {
			log_info2("l2tp: recv ");
			l2tp_packet_print(pack, log_info2);
		}
		if (msg_type->val.uint16 == Message_Type_Start_Ctrl_Conn_Request)
			l2tp_recv_SCCRQ(serv, pack, &pkt_info);
		else {
			log_warn("l2tp: discarding unexpected message from %s:"
				 " invalid Message Type %i\n",
				 src_addr, msg_type->val.uint16);
		}
skip:
		l2tp_packet_free(pack);
	}

	return 0;
}

static void l2tp_udp_close(struct triton_context_t *ctx)
{
	struct l2tp_serv_t *serv = container_of(ctx, typeof(*serv), ctx);
	triton_md_unregister_handler(&serv->hnd, 1);
	triton_context_unregister(&serv->ctx);
}

static struct l2tp_serv_t udp_serv =
{
	.hnd.read = l2tp_udp_read,
	.ctx.close = l2tp_udp_close,
	.ctx.before_switch = l2tp_ctx_switch,
};

/*static struct l2tp_serv_t ip_serv =
{
	.hnd.read=l2t_ip_read,
	.ctx.close=l2tp_ip_close,
};*/

in_addr_t l2tp_conf_get_bind_addr(void)
{
	const char *opt = conf_get_opt("l2tp", "bind");

	return opt ? inet_addr(opt) : htonl(INADDR_ANY);
}

/* Parsed fresh via conf_get_opt(), like l2tp_conf_get_bind_addr() above --
 * not read from the conf_port global, which start_udp_server() below only
 * populates from "[l2tp] port=" *after* l2tp_switch_conf_load() has already
 * run (l2tp_init() calls them in that order), so conf_port would still be
 * stuck at its L2TP_PORT default at self-loop-validation time otherwise. */
uint16_t l2tp_conf_get_bind_port(void)
{
	const char *opt = conf_get_opt("l2tp", "port");

	return (opt && atoi(opt) > 0) ? atoi(opt) : L2TP_PORT;
}

static int start_udp_server(void)
{
	struct sockaddr_in addr;
	const char *opt;
	int flag;

	udp_serv.hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (udp_serv.hnd.fd < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " socket(PF_INET) failed: %s\n", strerror(errno));
		return -1;
	}

	flag = fcntl(udp_serv.hnd.fd, F_GETFD);
	if (flag < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " fcntl(F_GETFD) failed: %s\n", strerror(errno));
		goto err_fd;
	}
	flag = fcntl(udp_serv.hnd.fd, F_SETFD, flag | FD_CLOEXEC);
	if (flag < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " fcntl(F_SETFD) failed: %s\n", strerror(errno));
		goto err_fd;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	opt = conf_get_opt("l2tp", "bind");
	if (opt)
		addr.sin_addr.s_addr = inet_addr(opt);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

	opt = conf_get_opt("l2tp", "port");
	if (opt && atoi(opt) > 0)
		conf_port = atoi(opt);
	addr.sin_port = htons(conf_port);

	if (setsockopt(udp_serv.hnd.fd, SOL_SOCKET, SO_REUSEADDR,
		       &udp_serv.hnd.fd, sizeof(udp_serv.hnd.fd)) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " setsockopt(SO_REUSEADDR) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}
	if (setsockopt(udp_serv.hnd.fd, SOL_SOCKET, SO_NO_CHECK,
		       &udp_serv.hnd.fd, sizeof(udp_serv.hnd.fd)) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " setsockopt(SO_NO_CHECK) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}

	if (bind(udp_serv.hnd.fd,
		 (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " bind() failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}

	flag = fcntl(udp_serv.hnd.fd, F_GETFL);
	if (flag < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " fcntl(F_GETFL) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}
	flag = fcntl(udp_serv.hnd.fd, F_SETFL, flag | O_NONBLOCK);
	if (flag < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " fcntl(F_SETFL) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}

	flag = 1;
	if (setsockopt(udp_serv.hnd.fd, IPPROTO_IP,
		       IP_PKTINFO, &flag, sizeof(flag)) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " setsockopt(IP_PKTINFO) failed: %s\n",
			  strerror(errno));
		goto err_fd;
	}

	memcpy(&udp_serv.addr, &addr, sizeof(addr));

	if (triton_context_register(&udp_serv.ctx, NULL) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " context registration failed\n");
		goto err_fd;
	}
	triton_md_register_handler(&udp_serv.ctx, &udp_serv.hnd);
	if (triton_md_enable_handler(&udp_serv.hnd, MD_MODE_READ) < 0) {
		log_error("l2tp: impossible to start L2TP server:"
			  " enabling handler failed\n");
		goto err_hnd;
	}
	triton_context_wakeup(&udp_serv.ctx);

	return 0;

err_hnd:
	triton_md_unregister_handler(&udp_serv.hnd, 1);
	triton_context_unregister(&udp_serv.ctx);

	return -1;

err_fd:
	close(udp_serv.hnd.fd);
	udp_serv.hnd.fd = -1;

	return -1;
}

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct l2tp_stat_t stat;

	l2tp_stat_get(&stat);

	cli_send(client, "l2tp:\r\n");
	cli_send(client, "  tunnels:\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat.conn_starting);
	cli_sendv(client, "    active: %u\r\n", stat.conn_active);
	cli_sendv(client, "    finishing: %u\r\n", stat.conn_finishing);

	cli_send(client, "  sessions (control channels):\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat.sess_starting);
	cli_sendv(client, "    active: %u\r\n", stat.sess_active);
	cli_sendv(client, "    finishing: %u\r\n", stat.sess_finishing);

	cli_send(client, "  sessions (data channels):\r\n");
	cli_sendv(client, "    starting: %u\r\n", stat.data_starting);
	cli_sendv(client, "    active: %u\r\n", stat.data_active);
	cli_sendv(client, "    finishing: %u\r\n", stat.data_finishing);

	cli_send(client, "  l2tp-switch:\r\n");
	cli_sendv(client, "    active: %u\r\n", l2tp_switch_active_total());
	cli_sendv(client, "    lns_rx_bytes: %llu\r\n",
		 (unsigned long long)stat.switch_lns_rx_bytes);
	cli_sendv(client, "    lns_tx_bytes: %llu\r\n",
		 (unsigned long long)stat.switch_lns_tx_bytes);

	return CLI_CMD_OK;
}

static int l2tp_create_tunnel_exec(const char *cmd, char * const *fields,
				   int fields_cnt, void *client)
{
	struct l2tp_conn_t *conn = NULL;
	struct sockaddr_in peer = {
		.sin_family = AF_INET,
		.sin_port = htons(L2TP_PORT),
		.sin_addr = { htonl(INADDR_ANY) }
	};
	struct sockaddr_in host = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = { htonl(INADDR_ANY) }
	};
	const char *opt = NULL;
	const char *secret = conf_secret;
	int peer_indx = -1;
	int host_indx = -1;
	int lns_mode = 0;
	int hide_avps = conf_hide_avps;
	uint16_t tid;
	int indx;

	opt = conf_get_opt("l2tp", "bind");
	if (opt)
		if (inet_aton(opt, &host.sin_addr) == 0) {
			host.sin_family = AF_INET;
			host.sin_port = 0;
		}

	for (indx = 3; indx + 1 < fields_cnt; ++indx) {
		if (strcmp("mode", fields[indx]) == 0) {
			++indx;
			if (strcmp("lns", fields[indx]) == 0)
				lns_mode = 1;
			else if (strcmp("lac", fields[indx]) == 0)
				lns_mode = 0;
			else {
				cli_sendv(client, "invalid mode: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
		} else if (strcmp("peer-addr", fields[indx]) == 0) {
			peer_indx = ++indx;
			if (inet_aton(fields[indx], &peer.sin_addr) == 0) {
				cli_sendv(client,
					  "invalid peer address: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
		} else if (strcmp("host-addr", fields[indx]) == 0) {
			host_indx = ++indx;
			if (inet_aton(fields[indx], &host.sin_addr) == 0) {
				cli_sendv(client,
					  "invalid host address: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
		} else if (strcmp("peer-port", fields[indx]) == 0) {
			long port;
			++indx;
			if (u_readlong(&port, fields[indx],
				       0, UINT16_MAX) < 0) {
				cli_sendv(client,
					  "invalid peer port: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
			peer.sin_port = htons(port);
		} else if (strcmp("host-port", fields[indx]) == 0) {
			long port;
			++indx;
			if (u_readlong(&port, fields[indx],
				       0, UINT16_MAX) < 0) {
				cli_sendv(client,
					  "invalid host port: \"%s\"\r\n",
					  fields[indx]);
				return CLI_CMD_INVAL;
			}
			host.sin_port = htons(port);
		} else if (strcmp("hide-avps", fields[indx]) == 0) {
			++indx;
			hide_avps = atoi(fields[indx]) > 0;
		} else if (strcmp("secret", fields[indx]) == 0) {
			++indx;
			secret = fields[indx];
		} else {
			cli_sendv(client, "invalid option: \"%s\"\r\n",
				  fields[indx]);
			return CLI_CMD_SYNTAX;
		}
	}

	if (indx != fields_cnt) {
		cli_send(client, "argument missing for last option\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (peer_indx < 0) {
		cli_send(client, "missing option \"peer-addr\"\r\n");
		return CLI_CMD_SYNTAX;
	}

	conn = l2tp_tunnel_alloc(&peer, &host, 3, lns_mode, 0, hide_avps);
	if (conn == NULL) {
		cli_send(client, "tunnel allocation failed\r\n");
		return CLI_CMD_FAILED;
	}
	tid = conn->tid;

	if (secret) {
		conn->secret = _strdup(secret);
		if (conn->secret == NULL) {
			cli_send(client, "secret allocation failed\r\n");
			l2tp_tunnel_free(conn);
			return CLI_CMD_FAILED;
		}
		conn->secret_len = strlen(conn->secret);
	}

	if (l2tp_tunnel_start(conn, l2tp_send_SCCRQ, &peer) < 0) {
		cli_send(client, "starting tunnel failed\r\n");
		l2tp_tunnel_free(conn);
		return CLI_CMD_FAILED;
	}

	log_info1("l2tp: new tunnel %hu created following request"
		  " from command line interface (peer-addr: %s,"
		  " host-addr: %s, mode: %s)\n", tid, fields[peer_indx],
		  host_indx < 0 ? "default" : fields[host_indx],
		  lns_mode ? "lns" : "lac");

	return CLI_CMD_OK;
}

static int l2tp_create_session_exec(const char *cmd, char * const *fields,
				    int fields_cnt, void *client)
{
	struct l2tp_conn_t *conn = NULL;
	long int tid;
	int res;

	if (fields_cnt != 5) {
		cli_send(client, "invalid number of arguments\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (strcmp("tid", fields[3]) != 0) {
		cli_sendv(client, "invalid option: \"%s\"\r\n", fields[3]);
		return CLI_CMD_SYNTAX;
	}

	if (u_readlong(&tid, fields[4], 1, UINT16_MAX) < 0) {
		cli_sendv(client, "invalid Tunnel ID: \"%s\"\r\n", fields[4]);
		return CLI_CMD_INVAL;
	}

	pthread_mutex_lock(&l2tp_lock);
	conn = l2tp_conn[tid];
	if (conn) {
		if (triton_context_call(&conn->ctx, l2tp_tunnel_create_session,
					conn) < 0)
			res = CLI_CMD_FAILED;
		else
			res = CLI_CMD_OK;
	} else {
		res = CLI_CMD_INVAL;
	}
	pthread_mutex_unlock(&l2tp_lock);

	if (res == CLI_CMD_FAILED)
		cli_send(client, "session creation failed\r\n");
	else if (res == CLI_CMD_INVAL)
		cli_sendv(client, "tunnel %li not found\r\n", tid);

	return res;
}

static void l2tp_create_tunnel_help(char * const *fields, int fields_cnt,
				    void *client)
{
	cli_send(client,
		 "l2tp create tunnel peer-addr <ip_addr> [OPTIONS...]"
		 " - initiate new tunnel to peer\r\n"
		 "\tOPTIONS:\r\n"
		 "\t\tpeer-port <port> - destination port (default 1701)\r\n"
		 "\t\thost-addr <ip_addr> - source address\r\n"
		 "\t\thost-port <port> - source port\r\n"
		 "\t\tsecret <secret> - tunnel secret\r\n"
		 "\t\thide-avps <0|1> - activation of AVP hiding\r\n"
		 "\t\tmode <lac|lns> - tunnel mode\r\n");
}

static void l2tp_create_session_help(char * const *fields, int fields_cnt,
				     void *client)
{
	cli_send(client,
		 "l2tp create session tid <tid>"
		 " - place new call in tunnel <tid>\r\n");
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("l2tp", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_verbose = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "use-ephemeral-ports");
	if (opt && atoi(opt) >= 0)
		conf_ephemeral_ports = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "hide-avps");
	if (opt && atoi(opt) >= 0)
		conf_hide_avps = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "dataseq");
	if (opt) {
		if (strcmp(opt, "deny") == 0)
			conf_dataseq = L2TP_DATASEQ_DENY;
		else if (strcmp(opt, "allow") == 0)
			conf_dataseq = L2TP_DATASEQ_ALLOW;
		else if (strcmp(opt, "prefer") == 0)
			conf_dataseq = L2TP_DATASEQ_PREFER;
		else if (strcmp(opt, "require") == 0)
			conf_dataseq = L2TP_DATASEQ_REQUIRE;
	}

	opt = conf_get_opt("l2tp", "reorder-timeout");
	if (opt && atoi(opt) >= 0)
		conf_reorder_timeout = atoi(opt);

	opt = conf_get_opt("l2tp", "avp_permissive");
	if (opt && atoi(opt) >= 0)
		conf_avp_permissive = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "hello-interval");
	if (opt && atoi(opt) > 0)
		conf_hello_interval = atoi(opt);

	opt = conf_get_opt("l2tp", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("l2tp", "rtimeout");
	if (opt && atoi(opt) > 0)
		conf_rtimeout = atoi(opt);
	else
		conf_rtimeout = DEFAULT_RTIMEOUT;

	opt = conf_get_opt("l2tp", "rtimeout-cap");
	if (opt && atoi(opt) > 0)
		conf_rtimeout_cap = atoi(opt);
	else
		conf_rtimeout_cap = DEFAULT_RTIMEOUT_CAP;
	if (conf_rtimeout_cap < conf_rtimeout) {
		log_warn("l2tp: rtimeout-cap (%i) is smaller than rtimeout (%i),"
			 " resetting rtimeout-cap to %i\n",
			 conf_rtimeout_cap, conf_rtimeout, conf_rtimeout);
		conf_rtimeout_cap = conf_rtimeout;
	}

	opt = conf_get_opt("l2tp", "retransmit");
	if (opt && atoi(opt) > 0)
		conf_retransmit = atoi(opt);
	else
		conf_retransmit = DEFAULT_RETRANSMIT;

	opt = conf_get_opt("l2tp", "recv-window");
	if (opt && atoi(opt) > 0 && atoi(opt) <= RECV_WINDOW_SIZE_MAX)
		conf_recv_window = atoi(opt);
	else
		conf_recv_window = DEFAULT_RECV_WINDOW;

	opt = conf_get_opt("l2tp", "ppp-max-mtu");
	if (opt && atoi(opt) > 0)
		conf_ppp_max_mtu = atoi(opt);
	else
		conf_ppp_max_mtu = DEFAULT_PPP_MAX_MTU;

	opt = conf_get_opt("l2tp", "host-name");
	if (opt)
		conf_host_name = opt;
	else
		conf_host_name = "accel-ppp";

	opt = conf_get_opt("l2tp", "secret");
	if (opt) {
		conf_secret = opt;
		conf_secret_len = strlen(opt);
	} else {
		conf_secret = NULL;
		conf_secret_len = 0;
	}

	opt = conf_get_opt("l2tp", "dir300_quirk");
	if (opt)
		conf_dir300_quirk = atoi(opt);

	conf_mppe = MPPE_UNSET;
	opt = conf_get_opt("l2tp", "mppe");
	if (opt) {
		if (strcmp(opt, "deny") == 0)
			conf_mppe = MPPE_DENY;
		else if (strcmp(opt, "allow") == 0)
			conf_mppe = MPPE_ALLOW;
		else if (strcmp(opt, "prefer") == 0)
			conf_mppe = MPPE_PREFER;
		else if (strcmp(opt, "require") == 0)
			conf_mppe = MPPE_REQUIRE;
	}

	conf_ip_pool = conf_get_opt("l2tp", "ip-pool");
	conf_ipv6_pool = conf_get_opt("l2tp", "ipv6-pool");
	conf_dpv6_pool = conf_get_opt("l2tp", "ipv6-pool-delegate");
	conf_ifname = conf_get_opt("l2tp", "ifname");

	opt = conf_get_opt("l2tp", "session-timeout");
		if (opt)
			conf_session_timeout = atoi(opt);
		else
			conf_session_timeout = 0;

	switch (iprange_check_activation()) {
	case IPRANGE_DISABLED:
		log_warn("l2tp: iprange module disabled, improper IP configuration of PPP interfaces may cause kernel soft lockup\n");
		break;
	case IPRANGE_NO_RANGE:
		log_warn("l2tp: no IP address range defined in section [%s], incoming L2TP connections will be rejected\n",
			 IPRANGE_CONF_SECTION);
		break;
	default:
		/* Makes compiler happy */
		break;
	}
}

/* twalk_r() (which would let the CLI client be passed through as a
 * closure argument instead of this) is a GNU extension not reliably
 * available across the libc versions this project targets -- confirmed
 * the hard way when it built fine against one glibc but failed with
 * "implicit declaration of function 'twalk_r'" on another. Plain twalk()
 * has no closure parameter at all, so the client is stashed in a
 * thread-local instead of a plain global: l2tp_switch_show_exec() runs
 * to completion on a single thread before any concurrent invocation on
 * that same thread could reuse it, but a plain global would still race
 * against a *different* thread running the same CLI command at the same
 * time. */
static __thread FILE *switch_show_out;

static void switch_show_walk(const void *nodep, VISIT which, int depth)
{
	struct l2tp_sess_t *sess = *(struct l2tp_sess_t **)nodep;
	FILE *out = switch_show_out;
	struct l2tp_sess_t *up;
	unsigned long long bytes_in = 0, bytes_out = 0;
	char calling[64];
	uint16_t up_tid, up_peer_tid;

	if (which != postorder && which != leaf)
		return;

	/* Only downstream legs are listed -- one line per call. Everything
	 * about the pairing is read under the pair lock: it is what
	 * l2tp_switch_unpair() and l2tp_switch_link_free() take before they
	 * clear the pointers read here (and before the upstream session, its
	 * calling number or either link can be freed), so nothing dereferenced
	 * below can go away while it is held. sess->switch_link is this
	 * (downstream) leg's own link -- it reads from the downstream socket
	 * and writes to upstream, i.e. the "target rx / upstream tx" direction;
	 * the other direction is the upstream leg's own link. Both are read
	 * purely for display -- see l2tp_switch_target_t for the persistent,
	 * per-target totals these feed into once the call ends. */
	pthread_mutex_lock(&l2tp_switch_pair_lock);
	up = sess->switch_upstream;
	if (!up) {
		pthread_mutex_unlock(&l2tp_switch_pair_lock);
		return;
	}
	snprintf(calling, sizeof(calling), "%s",
		 up->calling_num ? up->calling_num : "?");
	up_tid = up->paren_conn->tid;
	up_peer_tid = up->paren_conn->peer_tid;
	if (sess->switch_link)
		bytes_in = __atomic_load_n(&sess->switch_link->bytes,
					   __ATOMIC_RELAXED);
	if (up->switch_link)
		bytes_out = __atomic_load_n(&up->switch_link->bytes,
					    __ATOMIC_RELAXED);
	pthread_mutex_unlock(&l2tp_switch_pair_lock);

	fprintf(out, "    call: %s tunnel %hu-%hu / %hu-%hu"
		     " bytes_in=%llu bytes_out=%llu\r\n",
		calling, up_tid, up_peer_tid,
		sess->paren_conn->tid, sess->paren_conn->peer_tid,
		bytes_in, bytes_out);
}

/* Sends the per-call lines of `conn` to `client`. Caller holds a tunnel
 * reference on conn.
 *
 * The walk runs right here on the CLI thread, under conn->sessions_lock --
 * which every write to the sessions tree also takes -- rather than hopping
 * onto the tunnel's own context and waiting for it. An earlier version did
 * the hop and blocked the CLI worker until the context answered; with a
 * single triton worker thread (the default on a 1-CPU host) the context
 * could never run while the CLI thread was blocked, the wait always timed
 * out, and the per-call lines were silently omitted. The text is built in
 * memory so the lock is never held across the (possibly slow) client
 * write. */
static void switch_show_calls(struct l2tp_conn_t *conn, void *client)
{
	char *text = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&text, &len);

	if (!f)
		return;

	switch_show_out = f;
	pthread_mutex_lock(&conn->sessions_lock);
	twalk(conn->sessions, switch_show_walk);
	pthread_mutex_unlock(&conn->sessions_lock);
	fclose(f); /* finalizes text/len */

	if (len)
		cli_send(client, text);
	free(text);
}

static int l2tp_switch_show_exec(const char *cmd, char * const *fields,
				 int fields_cnt, void *client)
{
	struct l2tp_switch_target_t *t;

	cli_send(client, "targets:\r\n");
	list_for_each_entry(t, &l2tp_switch_targets, entry) {
		struct l2tp_conn_t *conn;
		const char *status;
		unsigned int active;
		char peer_addr[17];

		/* Snapshot under the target's lock, with a reference: this
		 * runs on the CLI thread, and an on-demand target's tunnel
		 * pointer churns on every connect/abort/timeout cycle -- two
		 * unlocked reads could disagree, and the second could
		 * dereference a tunnel that has since been destroyed. Reused
		 * below for both modes' status word, so there is only ever
		 * this one lock/hold on this pointer per line, not a second,
		 * differently-locked read alongside it. */
		pthread_mutex_lock(&t->lock);
		conn = t->tunnel;
		if (conn)
			tunnel_hold(conn);
		pthread_mutex_unlock(&t->lock);

		active = __atomic_load_n(&t->active, __ATOMIC_RELAXED);
		u_inet_ntoa(t->peer_addr.sin_addr.s_addr, peer_addr);

		if (t->mode == L2TP_SWITCH_MODE_PERSISTENT) {
			/* Tightened to genuinely STATE_ESTB: conn is non-NULL
			 * from the moment l2tp_tunnel_start() is called, well
			 * before the tunnel is actually usable. */
			status = (conn && conn->state == STATE_ESTB) ?
				"up" : "down";
		} else {
			/* "up" is derived from active > 0, not conn's state
			 * directly: an on-demand tunnel can be STATE_ESTB
			 * while idle-lingering with no calls on it,
			 * which must show as "idle" here, not "up" -- a
			 * fresh call always takes the fast path in
			 * l2tp_switch_place_downstream_call() once the
			 * tunnel is up, so active > 0 already implies
			 * STATE_ESTB in practice.
			 *
			 * "connecting" is the real "is a connect actually
			 * in flight" signal -- deliberately NOT
			 * target->connect_budget_open, which (see that
			 * field's own doc comment on struct
			 * l2tp_switch_target_t) stays true across a failed
			 * attempt and the idle gap before the next
			 * reconnect_timer tick, so it does not mean "in
			 * flight right now". conn's own state, already
			 * snapshotted above under the lock and held with a
			 * reference, is exactly that narrower signal.
			 *
			 * Everything else -- never connected, and
			 * post-linger with the tunnel actually closed -- is
			 * "idle": neither is an actionable fault, and this
			 * is a human-facing summary, not the raw
			 * tunnel-established bit (that's what the
			 * target_up metric is for). */
			if (active > 0)
				status = "up";
			else if (conn && conn->state != STATE_ESTB)
				status = "connecting";
			else
				status = "idle";
		}

		cli_sendv(client, "  %s -> %s:%hu [%s] active=%u"
				   " bytes_in=%llu bytes_out=%llu\r\n",
			 t->name, peer_addr,
			 ntohs(t->peer_addr.sin_port),
			 status, active,
			 (unsigned long long)__atomic_load_n(&t->rx_bytes, __ATOMIC_RELAXED),
			 (unsigned long long)__atomic_load_n(&t->tx_bytes, __ATOMIC_RELAXED));
		if (conn) {
			switch_show_calls(conn, client);
			tunnel_put(conn);
		}
	}

	cli_send(client, "calls:\r\n");
	cli_sendv(client, "  matched: %u\r\n",
		  __atomic_load_n(&l2tp_stat.switch_matched, __ATOMIC_RELAXED));
	cli_sendv(client, "  placed: %u\r\n",
		  __atomic_load_n(&l2tp_stat.switch_placed, __ATOMIC_RELAXED));
	cli_sendv(client, "  connected: %u\r\n",
		  __atomic_load_n(&l2tp_stat.switch_downstream_connected, __ATOMIC_RELAXED));
	cli_sendv(client, "  active: %u\r\n", l2tp_switch_active_total());

	return CLI_CMD_OK;
}

static int l2tp_switch_add_exec(const char *cmd, char * const *fields,
				int fields_cnt, void *client)
{
	if (fields_cnt != 7) {
		cli_send(client, "usage: l2tp switch add <attr> <exact|prefix>"
				 " <value> <target>\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (l2tp_switch_rule_add(fields[3], fields[4],
				 (const uint8_t *)fields[5], strlen(fields[5]),
				 fields[6]) < 0) {
		cli_send(client, "failed: unknown target, unknown/non-string"
				 " attr, invalid mode, or an overlapping rule"
				 " already exists\r\n");
		return CLI_CMD_FAILED;
	}

	return CLI_CMD_OK;
}

static int l2tp_switch_del_exec(const char *cmd, char * const *fields,
				int fields_cnt, void *client)
{
	if (fields_cnt != 6) {
		cli_send(client, "usage: l2tp switch del <attr> <exact|prefix>"
				 " <value>\r\n");
		return CLI_CMD_SYNTAX;
	}

	if (l2tp_switch_rule_del(fields[3], fields[4],
				 (const uint8_t *)fields[5],
				 strlen(fields[5])) < 0) {
		cli_send(client, "failed: no such rule\r\n");
		return CLI_CMD_FAILED;
	}

	return CLI_CMD_OK;
}

static void l2tp_init(void)
{
	int fd;

	fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (fd >= 0)
		close(fd);
	else if (system("modprobe -q pppol2tp || modprobe -q l2tp_ppp"))
		log_warn("unable to load l2tp kernel module\n");

	l2tp_conn = _malloc((UINT16_MAX + 1) * sizeof(struct l2tp_conn_t *));
	memset(l2tp_conn, 0, (UINT16_MAX + 1) * sizeof(struct l2tp_conn_t *));

	l2tp_conn_pool = mempool_create(sizeof(struct l2tp_conn_t));
	l2tp_sess_pool = mempool_create(sizeof(struct l2tp_sess_t));

	load_config();

	if (l2tp_switch_conf_load() < 0) {
		log_emerg("l2tp-switch: configuration is invalid,"
			  " terminating\n");
		_exit(EXIT_FAILURE);
	}
	l2tp_switch_targets_connect();

	start_udp_server();

	cli_register_simple_cmd2(&show_stat_exec, NULL, 2, "show", "stat");
	cli_register_simple_cmd2(l2tp_create_tunnel_exec,
				 l2tp_create_tunnel_help, 3,
				 "l2tp", "create", "tunnel");
	cli_register_simple_cmd2(l2tp_create_session_exec,
				 l2tp_create_session_help, 3,
				 "l2tp", "create", "session");
	cli_register_simple_cmd2(l2tp_switch_show_exec, NULL, 3,
				 "l2tp", "switch", "show");
	cli_register_simple_cmd2(l2tp_switch_add_exec, NULL, 3,
				 "l2tp", "switch", "add");
	cli_register_simple_cmd2(l2tp_switch_del_exec, NULL, 3,
				 "l2tp", "switch", "del");

	if (triton_event_register_handler(EV_CONFIG_RELOAD,
					  (triton_event_func)load_config) < 0)
		log_warn("l2tp: registration of CONFIG_RELOAD event failed,"
			 " configuration reloading deactivated\n");
}

DEFINE_INIT(22, l2tp_init);
