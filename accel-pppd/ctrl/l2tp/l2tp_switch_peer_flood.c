/*
 * l2tp-switch peer simulator: --fin-flood, a StopCCN followed by a junk
 * flood, timed so that the tunnel's own FIN_WAIT timer expires while its
 * context thread is still busy draining the flood. See l2tp_switch_peer_test.c.
 */
#include "l2tp_switch_peer_test.h"

/* Same batching rationale as l2tp_switch_peer_listen.c's STORM_BATCH. */
#define FLOOD_BATCH 64

int fin_flood_on = FIN_FLOOD_OFF;
int fin_flood_stopccn_ms;
int fin_flood_start_ms;
int fin_flood_len_ms;

/* Parses "A:S:W" -- milliseconds after the anchor event (see
 * --fin-flood-on) at which to send the StopCCN, at which to start the junk
 * flood, and for how long the flood runs. */
int parse_fin_flood(const char *spec)
{
	if (sscanf(spec, "%d:%d:%d", &fin_flood_stopccn_ms,
		   &fin_flood_start_ms, &fin_flood_len_ms) != 3 ||
	    fin_flood_stopccn_ms < 0 || fin_flood_start_ms < 0 ||
	    fin_flood_len_ms <= 0)
		return die("invalid --fin-flood (expected A:S:W, all in ms)");

	return 0;
}

static int send_stopccn_now(int fd, const struct sockaddr_in *their_addr,
			    uint16_t their_tid, uint16_t our_tid,
			    uint16_t ns, uint16_t nr)
{
	struct l2tp_avp_result_code rc = { htons(1), htons(6) };
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
				 their_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("StopCCN alloc failed");
	l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, our_tid, 1);
	l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc, sizeof(rc), 1);
	pack->hdr.tid = htons(their_tid);
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(ns);
	pack->hdr.Nr = htons(nr);
	if (l2tp_packet_send(fd, pack) < 0) {
		l2tp_packet_free(pack);
		return die("StopCCN send failed");
	}
	l2tp_packet_free(pack);

	return 0;
}

/* Builds the batch of junk datagrams: the bare 12-byte header of an
 * attribute-less control message with a tunnel ID the switch never assigned,
 * which its l2tp_conn_read() drops on the spot -- the same junk
 * send_sccrp_storm() floods with. */
static int init_junk(struct mmsghdr *msgs, struct iovec *iov,
		     struct l2tp_hdr_t *wire,
		     const struct sockaddr_in *their_addr)
{
	struct l2tp_packet_t *junk;
	int i;

	junk = l2tp_packet_alloc(2, 0, their_addr, 0, NULL, 0);
	if (!junk)
		return die("flood junk alloc failed");
	junk->hdr.tid = htons(0xffff);
	junk->hdr.sid = 0;
	*wire = junk->hdr;
	wire->length = htons(sizeof(*wire));
	wire->flags = htons(junk->hdr.flags);
	l2tp_packet_free(junk);

	iov->iov_base = wire;
	iov->iov_len = sizeof(*wire);
	memset(msgs, 0, FLOOD_BATCH * sizeof(*msgs));
	for (i = 0; i < FLOOD_BATCH; i++) {
		msgs[i].msg_hdr.msg_name = (void *)their_addr;
		msgs[i].msg_hdr.msg_namelen = sizeof(*their_addr);
		msgs[i].msg_hdr.msg_iov = iov;
		msgs[i].msg_hdr.msg_iovlen = 1;
	}

	return 0;
}

/*
 * Why this shape. A StopCCN does not free the switch's tunnel: it moves it to
 * FIN_WAIT, and only that state's own timer (one --rtimeout later) frees it.
 * triton's ctx_thread() serves a context's pending timers and md handlers
 * before its pending context calls, and l2tp_conn_read() keeps reading for as
 * long as its socket has something in it -- so a junk flood that outlasts the
 * FIN_WAIT timer leaves that timer, and with it l2tp_tunnel_free(), to run
 * *before* any context call that was scheduled into the tunnel while the flood
 * was on. A test aims the switch's own scheduled call (a connect timeout, an
 * idle linger) into the middle of the flood and the FIN_WAIT expiry between
 * that call and the flood's end; the timing margins are the caller's, given as
 * A:S:W.
 *
 * `ns`/`nr` are the sequence numbers the StopCCN goes out with.
 */
int run_fin_flood(int fd, const struct sockaddr_in *their_addr,
		  uint16_t their_tid, uint16_t our_tid,
		  uint16_t ns, uint16_t nr)
{
	double started = now_monotonic();
	double stop_at = started + (double)fin_flood_stopccn_ms / 1000.0;
	double flood_from = started + (double)fin_flood_start_ms / 1000.0;
	double flood_until = flood_from + (double)fin_flood_len_ms / 1000.0;
	struct mmsghdr msgs[FLOOD_BATCH];
	struct l2tp_hdr_t wire;
	struct iovec iov;
	unsigned long sent = 0;
	int stopped = 0, flooding = 0;

	if (init_junk(msgs, &iov, &wire, their_addr))
		return 1;

	for (;;) {
		double now = now_monotonic();

		if (!stopped && now >= stop_at) {
			if (send_stopccn_now(fd, their_addr, their_tid, our_tid,
					     ns, nr))
				return 1;
			stopped = 1;
			printf("event=fin_flood_stopccn t=%.6f\n", now_monotonic());
			fflush(stdout);
		}
		if (stopped && now >= flood_until)
			break;
		if (now >= flood_from && now < flood_until) {
			int n;

			if (!flooding) {
				flooding = 1;
				printf("event=fin_flood_start t=%.6f\n", now);
				fflush(stdout);
			}
			n = sendmmsg(fd, msgs, FLOOD_BATCH, 0);
			if (n > 0)
				sent += (unsigned long)n;
			continue;
		}
		usleep(500);
	}

	printf("event=fin_flood_end t=%.6f junk=%lu\n", now_monotonic(), sent);
	fflush(stdout);

	return 0;
}

int busy_flood_ms;

/* --busy-flood-ms: like --fin-flood's junk half but with no StopCCN and no
 * anchor -- just keep the peer's tunnel socket continuously readable for
 * `ms` milliseconds, so whatever runs on triton's ctx_thread for that
 * tunnel (an md handler draining the socket) starves out any context call
 * scheduled into it meanwhile, per the same md-handlers-before-context-
 * calls ordering run_fin_flood()'s own comment documents. Widens a
 * cross-context hop's normally microsecond-wide window into something a
 * test can reliably observe mid-flight. */
int run_busy_flood(int fd, const struct sockaddr_in *their_addr, int ms)
{
	double until = now_monotonic() + (double)ms / 1000.0;
	struct mmsghdr msgs[FLOOD_BATCH];
	struct l2tp_hdr_t wire;
	struct iovec iov;

	if (init_junk(msgs, &iov, &wire, their_addr))
		return 1;

	while (now_monotonic() < until)
		sendmmsg(fd, msgs, FLOOD_BATCH, 0);

	return 0;
}
