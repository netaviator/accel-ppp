/*
 * Standalone MK-simulator L2TP LAC peer for integration testing.
 *
 * Not part of the cmake build. Compile and run with:
 *   gcc -O1 -g -Wall -fno-strict-aliasing -D_GNU_SOURCE \
 *       -fsanitize=address,undefined -fno-sanitize-recover=all \
 *       -I accel-pppd/include -I accel-pppd/ctrl/l2tp \
 *       -o /tmp/l2tp_switch_peer_test \
 *       accel-pppd/ctrl/l2tp/l2tp_switch_peer_test.c \
 *       accel-pppd/ctrl/l2tp/packet.c -lcrypto
 *
 * Performs one scripted LAC exchange: SCCRQ -> SCCRP -> SCCCN, then
 * ICRQ -> ICRP -> ICCN, using real packet.c encode/decode. Exits 0 on
 * success. See packet_test.c in this directory for the sibling harness
 * that exercises packet.c's parser directly rather than over a socket,
 * and whose stub-dictionary approach this file copies (real dict.c is
 * not linked here either -- see the note above this listing).
 *
 * --real-ppp swaps the usual --data-pattern raw-byte probe for a real
 * pppd, handed the bearer socket the same way xl2tpd hands it to its own
 * LAC-side pppd -- see run_real_ppp()'s own comment. Requires an
 * /etc/ppp/pap-secrets entry for --proxy-username beforehand.
 *
 * --listen flips this harness to the opposite role: a downstream l2tp-switch
 * target, accepting the switch's own outbound SCCRQ instead of sending one.
 * See run_listen_mode()'s own comment.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_pppox.h>
#include <time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "l2tp.h"
#include "l2tp_prot.h"
#include "attr_defs.h"
#include <openssl/md5.h>

/* Mirrors l2tp.c's static inline comp_chap_md5() (~line 286) -- tunnel-auth
 * Challenge Response is MD5(msg-ident-octet || secret || challenge), per
 * RFC 2661 section 5.1.1 / 4.3. Needed because every test fixture in this
 * plan sets [l2tp] secret=, which makes the real daemon send a mandatory
 * Challenge AVP in its SCCRP and reject a SCCCN that doesn't answer it. */
static void comp_chap_md5(uint8_t *md5, uint8_t ident,
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

/* packet.c needs a working dictionary (attr_alloc() and l2tp_recv()'s AVP
 * loop both call l2tp_dict_find_attr_by_id(), and every l2tp_packet_add_*
 * call fails outright without a match), a mempool implementation, a
 * u_randbuf() (used internally by l2tp_packet_alloc() for the Random-Vector
 * AVP every control message carries), and log_emerg/log_error/log_warn/
 * log_ppp_debug. None of the real implementations are usable standalone --
 * see the note above this listing for why dict.c is out; mempool_*, the
 * log_* functions, and u_randbuf() all live in accel-pppd's core/utils,
 * which pulls in the whole triton runtime. packet_test.c stubs all of
 * these itself for the exact same reason; copy that approach verbatim
 * rather than diverging into a second convention. */
int conf_verbose = 1;
int conf_avp_permissive = 0;

#define DEFINE_LOG_STUB(name)						\
void name(const char *fmt, ...)					\
{									\
	va_list ap;							\
	va_start(ap, fmt);						\
	fprintf(stderr, "l2tp_switch_peer_test: " #name ": ");		\
	vfprintf(stderr, fmt, ap);					\
	va_end(ap);							\
}
DEFINE_LOG_STUB(log_emerg)
DEFINE_LOG_STUB(log_error)
DEFINE_LOG_STUB(log_warn)
DEFINE_LOG_STUB(log_ppp_debug)

mempool_t *mempool_create(int size)
{
	int *pool = malloc(sizeof(int));

	*pool = size;

	return (mempool_t *)pool;
}

void *mempool_alloc(mempool_t *pool)
{
	return malloc(*(int *)pool);
}

void mempool_free(void *ptr)
{
	free(ptr);
}

void triton_register_init(int order, void (*func)(void))
{
	func();
}

int u_randbuf(void *buf, size_t buf_len, int *err)
{
	FILE *f = fopen("/dev/urandom", "rb");

	if (!f) {
		if (err)
			*err = errno;
		return -1;
	}
	if (fread(buf, 1, buf_len, f) != buf_len) {
		if (err)
			*err = errno;
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* Stub dictionary -- see the note above. Types and M values copied
 * verbatim from dict/dictionary.rfc2661. */
static struct l2tp_dict_attr_t dict[] = {
	{ .name = "Message-Type",           .id = Message_Type,           .type = ATTR_TYPE_INT16,  .M = -1, .H =  0 },
	{ .name = "Result-Code",            .id = Result_Code,            .type = ATTR_TYPE_OCTETS, .M =  1, .H =  0 },
	{ .name = "Protocol-Version",       .id = Protocol_Version,       .type = ATTR_TYPE_INT16,  .M =  1, .H =  0 },
	{ .name = "Framing-Capabilities",   .id = Framing_Capabilities,   .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Bearer-Capabilities",    .id = Bearer_Capabilities,    .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Recv-Window-Size",       .id = Recv_Window_Size,       .type = ATTR_TYPE_INT16,  .M =  1, .H =  0 },
	{ .name = "Challenge",              .id = Challenge,              .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Challenge-Response",     .id = Challenge_Response,     .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Cause-Code",             .id = Cause_Code,             .type = ATTR_TYPE_OCTETS, .M =  1, .H = -1 },
	{ .name = "Host-Name",              .id = Host_Name,              .type = ATTR_TYPE_STRING, .M =  1, .H =  0 },
	{ .name = "Vendor-Name",            .id = Vendor_Name,            .type = ATTR_TYPE_STRING, .M =  0, .H =  0 },
	{ .name = "Assigned-Tunnel-ID",     .id = Assigned_Tunnel_ID,     .type = ATTR_TYPE_INT16,  .M =  1, .H = -1 },
	{ .name = "Assigned-Session-ID",    .id = Assigned_Session_ID,    .type = ATTR_TYPE_INT16,  .M =  1, .H = -1 },
	{ .name = "Call-Serial-Number",     .id = Call_Serial_Number,     .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Framing-Type",           .id = Framing_Type,           .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Called-Number",          .id = Called_Number,          .type = ATTR_TYPE_STRING, .M =  1, .H = -1 },
	{ .name = "Calling-Number",         .id = Calling_Number,         .type = ATTR_TYPE_STRING, .M =  1, .H = -1 },
	{ .name = "TX-Speed",               .id = TX_Speed,               .type = ATTR_TYPE_INT32,  .M =  1, .H = -1 },
	{ .name = "Init-Recv-LCP",          .id = Init_Recv_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Last-Sent-LCP",          .id = Last_Sent_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Last-Recv-LCP",          .id = Last_Recv_LCP,          .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Type",      .id = Proxy_Authen_Type,      .type = ATTR_TYPE_INT16,  .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Name",      .id = Proxy_Authen_Name,      .type = ATTR_TYPE_STRING, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Challenge", .id = Proxy_Authen_Challenge, .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-ID",        .id = Proxy_Authen_ID,        .type = ATTR_TYPE_INT16,  .M =  0, .H = -1 },
	{ .name = "Proxy-Authen-Response",  .id = Proxy_Authen_Response,  .type = ATTR_TYPE_OCTETS, .M =  0, .H = -1 },
};

struct l2tp_dict_attr_t *l2tp_dict_find_attr_by_id(int id)
{
	size_t indx;

	for (indx = 0; indx < sizeof(dict) / sizeof(dict[0]); ++indx)
		if (dict[indx].id == id)
			return &dict[indx];

	return NULL;
}

const struct l2tp_dict_value_t *l2tp_dict_find_value(const struct l2tp_dict_attr_t *attr,
						     l2tp_value_t val)
{
	return NULL;
}

static struct sockaddr_in peer_addr;
static const char *secret = "";
static const char *calling_number = "472913";
static const char *called_number;
static const char *proxy_username;
static const char *proxy_password;
static const char *data_pattern;
static int send_stopccn;
static int wait_cdn;
static int real_ppp;
static int minimal_lcp;
static int hold_seconds;
static int listen_mode;
static int listen_rounds = 1;
/* --listen only: how long to stall before answering a received SCCRQ with
 * its SCCRP. Lets a driving test hold the switch's own outbound tunnel in
 * mid-negotiation for a known, controllable window -- the only way to
 * observe what an on-demand target does with a call that arrives while its
 * connect is still in flight (queue it, rather than fail it outright). */
static int sccrp_delay_ms;
/* --listen only: instead of answering the SCCRQ with a single SCCRP, flood
 * the switch's tunnel socket for this many milliseconds with cheap junk
 * datagrams (wrong tunnel ID, discarded by l2tp_conn_read()'s own tid check
 * before anything else looks at them), sprinkling copies of the real SCCRP
 * through the flood.
 *
 * Why a flood makes a microsecond-wide race a deterministic one. Two
 * properties of the switch's own machinery combine:
 *
 *   * l2tp_conn_read() drains its socket in a loop and only *processes*
 *     what it read afterwards, so an SCCRP buried in the flood is not acted
 *     on until the flood stops feeding that loop -- the tunnel establishes
 *     at the end of the window, not when the SCCRP was sent;
 *   * triton's ctx_thread() serves a context's pending md handlers before
 *     its pending context calls, so while the socket keeps going readable
 *     the handler keeps winning and anything scheduled into this tunnel's
 *     context meanwhile (the on-demand connect timeout's abort, which is
 *     the point of the exercise) is starved until the flood ends.
 *
 * Aiming a flood an order of magnitude wider than the jitter at the connect
 * deadline therefore reproduces, every time, an ordering that is otherwise a
 * sub-millisecond coin flip.
 *
 * Duplicate SCCRPs are free: the switch stores control messages by Ns, so
 * copies past the first are deduplicated, and those the kernel drops when
 * the receive buffer is full cost nothing either. */
static int sccrp_storm_ms;
/* How long --wait-cdn waits, in seconds. Default 5 matches every existing
 * caller; the on-demand connect-timeout test needs a budget longer than the
 * daemon's own 10s connect timeout to observe the CDN that follows it. */
static int cdn_timeout = 5;
/* --listen + --minimal-lcp only: after this call's own minimal LCP settles
 * (both directions CONFACKed -- see run_minimal_lcp()), wait this many ms
 * then send a CDN for it over the control channel, instead of just holding
 * the tunnel per --hold-seconds like every other --listen mode does.
 *
 * This is the lever for forcing l2tp.c's live-PAP watcher's cross-context
 * race deterministically instead of relying on rare natural timing: the
 * watcher's cross-leg trigger (both directions' CONFACK seen) fires a
 * triton_context_call() into the downstream leg's own tunnel context to
 * send the injected PAP request -- a call that sits *queued* on that
 * context until its next context-calls pass. A CDN arriving on that same
 * downstream leg's control channel is instead handled directly from an md
 * handler already running on that context (l2tp_conn_read() -> ... ->
 * l2tp_session_free()), and -- per sccrp_storm_ms's own comment above on
 * this exact ordering rule -- md handlers run before context calls on every
 * pass, regardless of which was scheduled first. So a CDN timed to land
 * once the trigger has *just* been queued, but before that context next
 * processes its queued calls, reliably wins the race and frees the
 * watcher out from under its own already-queued send -- a use-after-free
 * if l2tp_switch_pap_send_request() has no liveness check on the watcher
 * it dereferences (see test_switch_downstream_pap_race.py). */
static int cdn_after_lcp_ms;
/* --listen + --minimal-lcp only: after this call's own minimal LCP settles,
 * wait for the switch's injected PAP Authenticate-Request and answer it
 * directly -- see wait_for_pap_request()'s own comment. Both must be set
 * together or not at all (enforced at option-parsing time below); NULL
 * (the default) skips this step entirely, same as omitting
 * --cdn-after-lcp-ms skips that one. */
static const char *expect_pap_name;
static const char *expect_pap_password;
static const char *second_call_number;
/* Randomized per-process rather than fixed: the kernel's L2TP core keys
 * tunnels by tunnel_id alone (global per network namespace), not per
 * socket/fd -- two concurrent invocations of this harness both pointed at
 * the same switch endpoint (e.g. a multi-target concurrency test) would
 * otherwise collide in-kernel on a shared fixed tid, one failing its data
 * socket connect() with no L2TP-level explanation at all. Confirmed on a
 * real two-target run: one leg got exactly that failure until this became
 * randomized. */
static uint16_t local_tid;
static uint16_t local_sid;

static int die(const char *msg)
{
	log_error("%s\n", msg);
	return 1;
}

/* Spawns a real pppd, handed the already-connected pppol2tp data socket by
 * fd number -- exactly how xl2tpd hands its own LAC-side pppd the bearer
 * (confirmed against a real xl2tpd invocation: "pppd plugin pppol2tp.so
 * pppol2tp <fd> passive nodetach ..."). Unlike xl2tpd, this harness is the
 * one constructing the ICRQ/ICCN, so it can actually set Calling-Number and
 * Proxy-Authen-Name/Response, then let this pppd perform genuine LCP/PAP
 * negotiation over the same bearer -- xl2tpd can never exercise this
 * feature's matching at all because it never fills in those AVPs itself.
 *
 * "passive" is deliberately omitted: that flag means "wait for the peer to
 * speak first", appropriate for xl2tpd's LNS-facing pppd. This harness
 * plays the calling side, so its pppd must initiate LCP itself, exactly
 * like a real subscriber's client would.
 *
 * Requires /etc/ppp/pap-secrets to already contain a "<proxy_username> * ..."
 * entry -- pppd's PAP secret lookup path is not configurable via the
 * command line, so the caller (a test fixture or the operator) must have
 * written it there beforehand.
 *
 * Returns 0 and prints "ppp_ip_up: 1" plus the negotiated local/remote IPs
 * if IPCP actually completed (proof of a genuine, working PPP session all
 * the way to the far end); returns 0 and prints "ppp_ip_up: 0" if pppd ran
 * but never reached that point (auth rejected, LNS refused, etc. -- not a
 * harness failure, just a negative result to report); returns non-zero only
 * for a harness-side problem (fork/exec/pipe failure). */
static int run_real_ppp(int data_fd)
{
	int outpipe[2];
	pid_t pid;
	char buf[8192];
	size_t used = 0;
	int ip_up = 0;
	time_t deadline;

	if (pipe(outpipe) < 0)
		return die("pipe() failed");

	pid = fork();
	if (pid < 0)
		return die("fork() failed");

	if (pid == 0) {
		char fdbuf[16];
		int flags;

		snprintf(fdbuf, sizeof(fdbuf), "%d", data_fd);

		dup2(outpipe[1], STDOUT_FILENO);
		dup2(outpipe[1], STDERR_FILENO);
		close(outpipe[0]);
		close(outpipe[1]);

		/* pppd's pppol2tp plugin takes the fd by number and expects
		 * to find it still open post-exec. */
		flags = fcntl(data_fd, F_GETFD);
		if (flags >= 0)
			fcntl(data_fd, F_SETFD, flags & ~FD_CLOEXEC);

		{
			char *child_argv[] = {
				"/usr/sbin/pppd",
				"plugin", "pppol2tp.so",
				"pppol2tp", fdbuf,
				"nodetach",
				"noauth",
				"debug",
				"novj", "novjccomp",
				"lcp-echo-interval", "0",
				"user", (char *)proxy_username,
				NULL,
			};
			execv(child_argv[0], child_argv);
		}
		_exit(127);
	}

	close(outpipe[1]);

	/* Bounded wait: real LCP/PAP/IPCP over a live path takes a few
	 * seconds; this is not meant to hang a soak run if the far end
	 * never responds. */
	deadline = time(NULL) + 20;
	while (time(NULL) < deadline && used < sizeof(buf) - 1) {
		struct pollfd pfd = { .fd = outpipe[0], .events = POLLIN };
		int remaining_ms = (int)((deadline - time(NULL)) * 1000);
		ssize_t n;

		if (remaining_ms <= 0)
			break;
		if (poll(&pfd, 1, remaining_ms) <= 0)
			break;
		n = read(outpipe[0], buf + used, sizeof(buf) - 1 - used);
		if (n <= 0)
			break;
		used += (size_t)n;
		buf[used] = '\0';
		if (strstr(buf, "local  IP address") ||
		    strstr(buf, "local IP address")) {
			ip_up = 1;
			/* Keep draining a little longer so "remote IP
			 * address" (printed right after) makes it into the
			 * captured log too, but don't wait for full EOF --
			 * a long-lived session (soak mode) never closes the
			 * pipe on its own. */
			usleep(300000);
			struct pollfd pfd2 = { .fd = outpipe[0], .events = POLLIN };
			if (poll(&pfd2, 1, 500) > 0) {
				n = read(outpipe[0], buf + used,
					sizeof(buf) - 1 - used);
				if (n > 0) {
					used += (size_t)n;
					buf[used] = '\0';
				}
			}
			break;
		}
	}

	/* Give the caller a window to drive real traffic (e.g. ping the
	 * peer address) over the now-up interface before tearing the call
	 * down -- otherwise ip_up is only ever proven at the control-plane
	 * level (auth + IPCP), never on the actual data path. */
	if (ip_up && hold_seconds > 0)
		sleep((unsigned int)hold_seconds);

	kill(pid, SIGTERM);
	{
		int waited_ms = 0;

		while (waited_ms < 2000) {
			int status;
			pid_t r = waitpid(pid, &status, WNOHANG);

			if (r == pid)
				break;
			usleep(100000);
			waited_ms += 100;
		}
		if (waitpid(pid, NULL, WNOHANG) != pid)
			kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	close(outpipe[0]);

	fputs(buf, stderr);
	printf("ppp_ip_up: %d\n", ip_up);

	return 0;
}

/* Mirrors l2tp.c's own field-for-field mirror of struct lcp_hdr_t (see
 * l2tp_switch_pap_watcher_t's comment block, accel-pppd/ctrl/l2tp/l2tp.c) --
 * this harness is a standalone translation unit and cannot #include l2tp.c's
 * private definitions, so it is a deliberate copy, not a divergence. */
struct minimal_lcp_hdr {
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

#define MINIMAL_PPP_LCP 0xc021
#define MINIMAL_LCP_CONFREQ 1
#define MINIMAL_LCP_CONFACK 2
#define MINIMAL_LCP_RETRANSMIT_SECONDS 1

/* Plays real, minimal LCP directly over the bearer socket -- no pppd, no
 * /etc/ppp/pap-secrets dependency (unlike run_real_ppp() above), and
 * deliberately never sends or answers PAP: this harness's --minimal-lcp mode
 * exists specifically to reproduce production's actual upstream behaviour
 * (the real calling client negotiates real LCP with the far end through the
 * switch's splice, but the upstream LAC proxies authentication via this
 * call's ICCN AVPs instead of ever putting a live PAP frame on the wire --
 * see l2tp_switch_pap_watcher_t's own comment in l2tp.c). --real-ppp's full
 * pppd instead negotiates *and* sends genuine live PAP, which is a different,
 * untested scenario (a downstream target receiving two PAP requests -- see
 * docs/l2tp_switching.md's "Authentication" section) -- do not conflate the
 * two when picking a mode for a new test.
 *
 * Any Configure-Request the peer sends is ACKed unconditionally, echoing its
 * options back verbatim: this harness has no LCP requirements of its own to
 * negotiate, so there is nothing to legitimately NAK or REJ, and a real
 * accel-ppp downstream's default options (MRU, magic-number, possibly an
 * auth-protocol request) are all things a real client would routinely just
 * accept anyway. Returns once both directions have been seen (our own
 * request ACKed, and at least one of the peer's ACKed by us) or the deadline
 * passes -- either way, `data_fd` is left open and untouched for the caller
 * (unlike run_real_ppp(), which takes ownership of it): the existing
 * --hold-seconds sleep after this function returns is what keeps the
 * process, and so this socket, alive long enough for a test to observe
 * whatever the switch's live-PAP watcher does with the LCP this function
 * just opened. */
static int run_minimal_lcp(int data_fd, int timeout_seconds)
{
	/* Generously over any realistic LCP frame a default accel-ppp
	 * Configure-Request carries (MRU + magic-number + maybe an
	 * auth-protocol option is well under 32 bytes); sized to a PPP MTU so
	 * a read() here can never silently truncate a real frame and echo
	 * back a Configure-Ack whose Length field no longer matches what was
	 * actually sent. */
	uint8_t buf[1500];
	struct minimal_lcp_hdr our_req; /* a stack copy, not an alias into
		`buf` -- `buf` gets overwritten by every read() in the loop
		below, so the code this once pointed at "our own request's id"
		would silently start comparing against whatever was just read
		instead if this were a pointer into the same buffer */
	time_t deadline = time(NULL) + timeout_seconds;
	/* RFC 1661 3.2/4.6: a real LCP implementation always retransmits an
	 * unacknowledged Configure-Request on a timer (its own default is
	 * 3s) rather than sending it exactly once -- not just a nicety here.
	 * This data socket's peer-side splice/watcher wiring on the switch
	 * (l2tp_switch_finish_upstream(), scheduled off the *downstream*
	 * leg's own ICRP, which is a further round-trip after this function
	 * is already sending) is set up asynchronously, so there is a real
	 * window early on where this function's very first write() can
	 * reach a socket nothing is relaying from yet and be silently
	 * dropped. One-shot send + no retransmission turns that single lost
	 * packet into permanent silence for the rest of `timeout_seconds`,
	 * exactly matching a CONFREQ that a real, spec-following peer would
	 * have simply seen retransmitted a moment later. */
	time_t next_retransmit;
	int our_req_acked = 0, acked_a_peer_req = 0;

	our_req.proto = htons(MINIMAL_PPP_LCP);
	our_req.code = MINIMAL_LCP_CONFREQ;
	our_req.id = 1;
	/* RFC 1661: the LCP Length field covers Code+Identifier+Length+Data,
	 * not the preceding 2-byte PPP Protocol field -- sizeof(our_req)
	 * includes that field, so it overstates this zero-option request's
	 * real length by 2. A real accel-ppp peer's lcp_recv() checks the
	 * claimed length against the bytes actually received and silently
	 * drops anything that claims more than it got, so getting this wrong
	 * means this Configure-Request is never acked by a real LNS. */
	our_req.len = htons(sizeof(our_req) - sizeof(our_req.proto));
	if (write(data_fd, &our_req, sizeof(our_req)) < 0) {
		fprintf(stderr, "run_minimal_lcp: initial Configure-Request"
			" write failed: %s\n", strerror(errno));
		return -1;
	}
	next_retransmit = time(NULL) + MINIMAL_LCP_RETRANSMIT_SECONDS;

	while (!(our_req_acked && acked_a_peer_req)) {
		struct pollfd pfd = { .fd = data_fd, .events = POLLIN };
		time_t now = time(NULL);
		time_t remaining = deadline - now;
		time_t poll_for;
		ssize_t n;

		if (remaining <= 0) {
			fprintf(stderr, "run_minimal_lcp: timed out waiting"
				" for LCP to open both ways (our_req_acked=%d"
				" acked_a_peer_req=%d)\n", our_req_acked,
				acked_a_peer_req);
			return -1;
		}

		/* Never wait past the next scheduled retransmit, whether or
		 * not it's actually still needed by then -- rechecked below,
		 * same as the overall deadline is rechecked on every lap
		 * regardless of why poll() returned. */
		poll_for = our_req_acked ? remaining : next_retransmit - now;
		if (poll_for < 0)
			poll_for = 0;
		if (poll_for > remaining)
			poll_for = remaining;

		if (poll(&pfd, 1, (int)(poll_for * 1000)) <= 0) {
			if (!our_req_acked && time(NULL) >= next_retransmit) {
				if (write(data_fd, &our_req, sizeof(our_req)) < 0) {
					fprintf(stderr, "run_minimal_lcp:"
						" retransmitting Configure-Request"
						" failed: %s\n", strerror(errno));
					return -1;
				}
				next_retransmit = time(NULL) + MINIMAL_LCP_RETRANSMIT_SECONDS;
			}
			continue; /* timeout or EINTR -- loop re-checks deadline */
		}

		n = read(data_fd, buf, sizeof(buf));
		if (n < 0) {
			fprintf(stderr, "run_minimal_lcp: read failed: %s\n",
				strerror(errno));
			return -1;
		}
		if (n == 0) {
			fprintf(stderr, "run_minimal_lcp: peer closed the"
				" data socket\n");
			return -1;
		}
		if (n < (ssize_t)sizeof(struct minimal_lcp_hdr))
			continue; /* too short to be a control frame we care about */

		{
			struct minimal_lcp_hdr *hdr = (struct minimal_lcp_hdr *)buf;

			if (hdr->proto != htons(MINIMAL_PPP_LCP))
				continue; /* not LCP (e.g. the watcher's injected
					     PAP, or downstream's reply to it --
					     this harness deliberately never
					     touches either) */

			if (hdr->code == MINIMAL_LCP_CONFREQ) {
				hdr->code = MINIMAL_LCP_CONFACK;
				if (write(data_fd, buf, (size_t)n) < 0) {
					fprintf(stderr, "run_minimal_lcp: Configure-Ack"
						" write failed: %s\n", strerror(errno));
					return -1;
				}
				acked_a_peer_req = 1;
			} else if (hdr->code == MINIMAL_LCP_CONFACK &&
				  hdr->id == our_req.id) {
				our_req_acked = 1;
			}
		}
	}

	return 0;
}

/* Mirrors l2tp.c's l2tp_switch_pap_hdr (RFC 1334 2.1/2.2 Authenticate-
 * Request/Ack/Nak) -- same layout as struct minimal_lcp_hdr above, kept as
 * its own named type so call sites read as what they are. */
struct minimal_pap_hdr {
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

#define MINIMAL_PPP_PAP 0xc023
#define MINIMAL_PAP_REQ 1
#define MINIMAL_PAP_ACK 2
#define MINIMAL_PAP_NAK 3

/* --listen + --minimal-lcp + --expect-pap-name only: waits, on the same
 * data socket run_minimal_lcp() just settled LCP on, for the one PAP
 * Authenticate-Request the switch's live-PAP watcher injects
 * (l2tp_switch_pap_send_request() in l2tp.c), decodes its Peer-ID/Password,
 * and replies with an Ack if both match --expect-pap-name/
 * --expect-pap-password exactly, a Nak otherwise -- this harness deciding
 * the outcome itself, the same way it already builds/parses every other
 * frame in this file, rather than handing the frame to a second real
 * accel-pppd instance's own auth stack just to get a yes/no back. Prints
 * one event=pap_received line with the outcome either way, so a test can
 * assert on it directly. Returns 0 once answered (whatever the outcome),
 * -1 on timeout/error/malformed frame. */
static int wait_for_pap_request(int data_fd, const char *expect_name,
				const char *expect_password,
				int timeout_seconds, int round)
{
	uint8_t buf[256]; /* matches l2tp.c's own l2tp_switch_pap_send_request()
		buf[256] -- Proxy-Authen-Name/Response are bounded well under
		this on the sending side, so a genuine frame from that watcher
		can never overrun it. */
	time_t deadline = time(NULL) + timeout_seconds;

	while (1) {
		struct pollfd pfd = { .fd = data_fd, .events = POLLIN };
		time_t remaining = deadline - time(NULL);
		ssize_t n;

		if (remaining <= 0) {
			fprintf(stderr, "wait_for_pap_request: timed out"
				" waiting for a PAP request\n");
			return -1;
		}

		if (poll(&pfd, 1, (int)(remaining * 1000)) <= 0)
			continue; /* timeout or EINTR -- loop re-checks deadline */

		n = read(data_fd, buf, sizeof(buf));
		if (n < 0) {
			fprintf(stderr, "wait_for_pap_request: read failed:"
				" %s\n", strerror(errno));
			return -1;
		}
		if (n == 0) {
			fprintf(stderr, "wait_for_pap_request: peer closed"
				" the data socket\n");
			return -1;
		}
		if (n < (ssize_t)sizeof(struct minimal_pap_hdr))
			continue; /* too short to be a control frame we care about */

		{
			struct minimal_pap_hdr *hdr = (struct minimal_pap_hdr *)buf;
			uint8_t *p = buf + sizeof(*hdr);
			uint8_t *end = buf + n;
			uint8_t name_len, pass_len;
			char name[256], pass[256];
			int matched;
			struct minimal_pap_hdr reply;

			if (hdr->proto != htons(MINIMAL_PPP_PAP) ||
			    hdr->code != MINIMAL_PAP_REQ)
				continue; /* not it yet -- e.g. trailing LCP
					     chatter still in flight */

			if (p >= end || p + 1 + *p > end) {
				fprintf(stderr, "wait_for_pap_request: malformed"
					" PAP request (Peer-ID overruns the"
					" frame)\n");
				return -1;
			}
			name_len = *p++;
			memcpy(name, p, name_len);
			name[name_len] = 0;
			p += name_len;

			if (p >= end || p + 1 + *p > end) {
				fprintf(stderr, "wait_for_pap_request: malformed"
					" PAP request (Password overruns the"
					" frame)\n");
				return -1;
			}
			pass_len = *p++;
			memcpy(pass, p, pass_len);
			pass[pass_len] = 0;

			matched = expect_name && expect_password &&
				  !strcmp(name, expect_name) &&
				  !strcmp(pass, expect_password);

			reply.proto = htons(MINIMAL_PPP_PAP);
			reply.code = matched ? MINIMAL_PAP_ACK : MINIMAL_PAP_NAK;
			reply.id = hdr->id;
			reply.len = htons(sizeof(reply) - sizeof(reply.proto));

			if (write(data_fd, &reply, sizeof(reply)) < 0) {
				fprintf(stderr, "wait_for_pap_request: sending"
					" PAP reply failed: %s\n", strerror(errno));
				return -1;
			}

			printf("event=pap_received round=%d name=%s result=%s"
			       " t=%.6f\n", round, name,
			       matched ? "ack" : "nak", now_monotonic());
			fflush(stdout);

			return 0;
		}
	}
}

static int send_and_recv(int fd, struct l2tp_packet_t *pack,
			 struct l2tp_packet_t **reply)
{
	if (l2tp_packet_send(fd, pack) < 0)
		return -1;
	l2tp_packet_free(pack);

	for (;;) {
		if (l2tp_recv(fd, reply, NULL, (const char *)secret,
			     strlen(secret)) != 0)
			return -1;
		/* l2tp_recv() always sets *reply to a valid, non-NULL packet
		 * -- even a ZLB (zero-AVP ack), which just has an empty
		 * attrs list. A NULL check can never catch that; check
		 * attrs emptiness instead (see the bug note above this
		 * listing). */
		if (*reply == NULL)
			continue;
		if (list_empty(&(*reply)->attrs)) {
			l2tp_packet_free(*reply);
			*reply = NULL;
			continue;
		}
		break;
	}

	return 0;
}

static double now_monotonic(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* How many junk datagrams one sendmmsg() hands the kernel. The flood has to
 * comfortably outrun the switch's own draining of its socket -- a per-datagram
 * sendto() loop only just keeps up with it (both sides are usually built with
 * the same sanitizers), and every moment the switch wins leaves its read loop
 * with an empty socket, which is when the window this flood creates snaps
 * shut. Batching moves the sender an order of magnitude ahead instead. */
#define STORM_BATCH 64

/* --sccrp-storm-ms: keep the switch's tunnel socket continuously readable for
 * that long, so its l2tp_conn_read() never finds the socket dry, and finish by
 * letting the SCCRP sprinkled through the flood establish the tunnel. See
 * sccrp_storm_ms's own comment for what that buys a driving test.
 *
 * The junk carries a tunnel ID the switch has never assigned, which its
 * l2tp_conn_read() drops on the spot ("discarding message with invalid tid")
 * without queueing, acking or otherwise reacting to it -- the cheapest
 * harmless datagram this protocol has. It is the exact 12 bytes
 * l2tp_packet_send() would have put on the wire for an attribute-less control
 * message, built once and then blasted with sendmmsg(); the kernel silently
 * discards whatever overflows the switch's receive buffer, which is precisely
 * the "switch is behind" state this wants.
 *
 * Returns 0 once the flood is over and the SCCRP has been handed to the
 * kernel, non-zero (already reported via die()) on a send error.
 */
static int send_sccrp_storm(int fd, const struct sockaddr_in *their_addr,
			    struct l2tp_packet_t *sccrp)
{
	/* One SCCRP copy per this many junk batches. Small enough that
	 * hundreds of copies are offered across a typical flood (so a full
	 * receive buffer dropping most of them does not matter), large enough
	 * that the junk, not the SCCRP, is what keeps the socket busy. */
	static const int sccrp_every = 4;
	/* Junk-only for the first half of the flood. The switch's read loop
	 * exits the moment its socket runs dry, so an SCCRP offered before
	 * the flood has built up a backlog is simply read, the loop ends, and
	 * the tunnel establishes right there -- which is the one outcome this
	 * flood exists to prevent. Half the window is spent getting the
	 * switch chronically behind before the SCCRP is offered at all; the
	 * connect deadline a driving test aims at belongs in this half. */
	double started = now_monotonic();
	double until = started + (double)sccrp_storm_ms / 1000.0;
	double offer_sccrp_from = started + (double)sccrp_storm_ms / 2000.0;
	/* ...and stop the junk for the last tenth, sending nothing but SCCRP
	 * copies. While the junk is flowing the receive buffer stays full, so
	 * most of what is offered is dropped by the kernel; stopping it lets
	 * the buffer drain just enough for a copy to get in, while the switch
	 * still has a backlog of junk to chew through and so has not yet left
	 * its read loop. Without this tail the flood can end with every SCCRP
	 * copy dropped, and the tunnel never comes up at all. */
	double junk_until = started + (double)sccrp_storm_ms * 0.9 / 1000.0;
	struct mmsghdr msgs[STORM_BATCH];
	struct l2tp_packet_t *junk;
	struct l2tp_hdr_t wire;
	struct iovec iov;
	unsigned long batches = 0, sent = 0;
	int i;

	junk = l2tp_packet_alloc(2, 0, their_addr, 0, NULL, 0);
	if (!junk)
		return die("storm junk alloc failed");
	junk->hdr.tid = htons(0xffff); /* never a live tunnel ID here: the
					* switch assigns its own from
					* l2tp_conn[], which this harness's
					* real messages echo back instead */
	junk->hdr.sid = 0;
	/* What l2tp_packet_send() does to an attribute-less packet's header
	 * on its way out: length is the bare header, and flags -- the one
	 * field kept in host order in struct l2tp_hdr_t -- is byte-swapped. */
	wire = junk->hdr;
	wire.length = htons(sizeof(wire));
	wire.flags = htons(junk->hdr.flags);
	l2tp_packet_free(junk);

	iov.iov_base = &wire;
	iov.iov_len = sizeof(wire);
	memset(msgs, 0, sizeof(msgs));
	for (i = 0; i < STORM_BATCH; i++) {
		msgs[i].msg_hdr.msg_name = (void *)their_addr;
		msgs[i].msg_hdr.msg_namelen = sizeof(*their_addr);
		msgs[i].msg_hdr.msg_iov = &iov;
		msgs[i].msg_hdr.msg_iovlen = 1;
	}

	printf("event=storm_start t=%.6f\n", now_monotonic());
	fflush(stdout);

	while (1) {
		double now = now_monotonic();
		int n;

		if (now >= until)
			break;
		if (now >= junk_until ||
		    (now >= offer_sccrp_from && (batches % sccrp_every) == 0)) {
			if (l2tp_packet_send(fd, sccrp) < 0)
				return die("SCCRP send failed");
			if (now >= junk_until) {
				batches++;
				continue;
			}
		}
		n = sendmmsg(fd, msgs, STORM_BATCH, 0);
		if (n < 0)
			/* ENOBUFS/EAGAIN just mean the local send path is
			 * momentarily full, which is this loop's normal
			 * steady state, not a failure. */
			n = 0;
		sent += (unsigned long)n;
		batches++;
	}

	/* The flood is over but the switch is still working through what it
	 * buffered, so these land in the same read loop -- insurance for the
	 * case where every in-flood copy was dropped by a full receive
	 * buffer. */
	for (i = 0; i < 8; i++) {
		if (l2tp_packet_send(fd, sccrp) < 0)
			return die("SCCRP send failed");
	}

	printf("event=storm_end t=%.6f junk=%lu\n", now_monotonic(), sent);
	fflush(stdout);

	return 0;
}

/*
 * Plays the *downstream target's* role instead of the usual upstream/MK
 * one: binds --peer-port (any source address, since the switch's own
 * outbound tunnel socket uses an ephemeral local port) and, for each of
 * --rounds tunnels, completes SCCRQ -> SCCRP -> SCCCN and then, if
 * --send-stopccn was given, immediately sends an unprompted StopCCN with a
 * zero-session tunnel -- exactly what a real peer's own idle-tunnel policy
 * does (e.g. JunOS's [edit services l2tp tunnel] idle-timeout, 60s default,
 * firing on a tunnel that never carried a session). No ICRQ is ever sent:
 * that is the whole point of this mode, and matches production evidence
 * for the bug this exercises.
 *
 * With --hold-seconds it then stays on the tunnel for that long, serving it
 * as a patient LNS would -- see serve_established_tunnel() above.
 *
 * Emits one "event=... round=N t=<monotonic seconds>" line per step so the
 * driving test can measure the gap between "sent_stopccn" and the next
 * round's "recv_sccrq" -- i.e. how long the switch actually took to
 * reconnect -- without depending on `l2tp switch show`, whose "[up]"/
 * "[down]" status only flips once the old tunnel is actually freed (see the
 * comment on l2tp_switch_target_t.tunnel in l2tp.c).
 */
/* --listen, after the tunnel is established: play a downstream LNS that does
 * *not* hang up the moment a call ends.
 *
 * A real accel-ppp instance cannot play that role. Its l2tp_session_free()
 * disconnects any tunnel as soon as its last session goes away, so a
 * downstream accel-ppp always tears the tunnel down first, before anything
 * the *switch* does with an idle tunnel of its own can be observed at all.
 * Real peers are more patient -- JunOS keeps an idle tunnel for its own
 * idle-timeout, 60s by default -- and that patience is the entire premise of
 * the switch closing its on-demand tunnels on its own, earlier terms. This
 * loop supplies it: answer ICRQ so a switched call can really establish, ack
 * everything else so nothing is retransmitted into a timeout, and otherwise
 * say nothing at all until --hold-seconds is up.
 *
 * Emits one event line per message received, with the monotonic timestamp a
 * driving test measures its windows against. StopCCN also reports its result
 * code, which is what tells a voluntary idle teardown (1, "general request
 * to clear the control connection") from an error-driven one.
 */
/* --listen + --minimal-lcp only, called once this call's ICCN arrives: opens
 * the session-level pppol2tp data socket for it (mirroring the caller
 * role's own setup further down in this file -- same tunnel-registration-
 * before-session-connect two-step, same reasoning, just LNS-mode=1 here
 * since this harness is playing the downstream target rather than the
 * calling client's LAC), runs real minimal LCP over it, and -- if
 * --cdn-after-lcp-ms was given -- sends this call's CDN after the
 * requested delay. See cdn_after_lcp_ms's own comment for why that delay
 * is the deterministic race lever, not just a convenience. Always closes
 * the data socket before returning; the CDN, when sent, goes out over the
 * control channel `fd`, not this one. */
static int serve_minimal_lcp_and_cdn(int fd, const struct sockaddr_in *their_addr,
				     uint16_t my_tid, uint16_t their_tid,
				     uint16_t our_sid, uint16_t their_sid,
				     uint16_t *my_ns, uint16_t *peer_next_nr,
				     int round)
{
	struct sockaddr_pppol2tp pppox_addr;
	int data_fd, reg_fd, lns_mode = 1;

	reg_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (reg_fd < 0)
		return die("tunnel registration socket() failed");

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = fd;
	pppox_addr.pppol2tp.addr = *their_addr;
	pppox_addr.pppol2tp.s_tunnel = my_tid;
	pppox_addr.pppol2tp.d_tunnel = their_tid;
	/* s_session/d_session left at 0: tunnel-level registration only. */

	if (connect(reg_fd, (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		close(reg_fd);
		return die("tunnel registration connect() failed");
	}
	close(reg_fd);

	data_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (data_fd < 0)
		return die("data socket() failed");

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = fd;
	pppox_addr.pppol2tp.addr = *their_addr;
	pppox_addr.pppol2tp.s_tunnel = my_tid;
	pppox_addr.pppol2tp.d_tunnel = their_tid;
	pppox_addr.pppol2tp.s_session = our_sid;
	pppox_addr.pppol2tp.d_session = their_sid;

	if (connect(data_fd, (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		close(data_fd);
		return die("data socket connect() failed");
	}

	if (setsockopt(data_fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE,
		      &lns_mode, sizeof(lns_mode)) < 0) {
		close(data_fd);
		return die("data socket setsockopt(LNSMODE) failed");
	}

	if (run_minimal_lcp(data_fd, 5) != 0) {
		close(data_fd);
		return -1;
	}

	printf("event=downstream_lcp_settled round=%d t=%.6f\n",
	       round, now_monotonic());
	fflush(stdout);

	if (expect_pap_name &&
	    wait_for_pap_request(data_fd, expect_pap_name, expect_pap_password,
				 5, round) != 0) {
		close(data_fd);
		return -1;
	}

	if (cdn_after_lcp_ms > 0) {
		struct l2tp_packet_t *pack;
		struct l2tp_avp_result_code res = { htons(1), htons(0) };

		usleep((useconds_t)cdn_after_lcp_ms * 1000);

		pack = l2tp_packet_alloc(2, Message_Type_Call_Disconnect_Notify,
					 their_addr, 0, secret, strlen(secret));
		if (!pack) {
			close(data_fd);
			return die("CDN alloc failed");
		}
		/* RFC 2661 5.1: Assigned-Session-ID here is the *sender's*
		 * own id for this call -- ours -- while the header sid is
		 * always the recipient's, same convention the ICRP above
		 * already follows for their_sid/our_sid. */
		l2tp_packet_add_int16(pack, Assigned_Session_ID, our_sid, 1);
		l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&res,
				       sizeof(res), 1);
		pack->hdr.tid = htons(their_tid);
		pack->hdr.sid = htons(their_sid);
		pack->hdr.Ns = htons((*my_ns)++);
		pack->hdr.Nr = htons(*peer_next_nr);
		if (l2tp_packet_send(fd, pack) < 0) {
			l2tp_packet_free(pack);
			close(data_fd);
			return die("CDN send failed");
		}
		l2tp_packet_free(pack);

		printf("event=sent_cdn round=%d t=%.6f\n", round, now_monotonic());
		fflush(stdout);
	}

	close(data_fd);
	return 0;
}

static int serve_established_tunnel(int fd, const struct sockaddr_in *their_addr,
				    uint16_t my_tid, uint16_t their_tid,
				    uint16_t *my_ns, uint16_t *peer_next_nr,
				    int round)
{
	double until = now_monotonic() + hold_seconds;
	/* Short enough that the loop notices --hold-seconds running out
	 * promptly on a silent tunnel, which is most of its life. */
	struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
	uint16_t next_sid = (uint16_t)(200 + round * 10);
	/* Set from the ICRQ branch below, read back once its matching ICCN
	 * arrives -- the loop-local `their_sid`/`next_sid` of that earlier
	 * iteration are both gone by then. */
	uint16_t call_our_sid = 0, call_their_sid = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		return die("setsockopt(SO_RCVTIMEO) failed");

	while (now_monotonic() < until) {
		struct l2tp_packet_t *msg = NULL, *rsp;
		struct l2tp_attr_t *attr, *msg_type;
		uint16_t type = 0, their_sid = 0;
		int stop = 0;

		if (l2tp_recv(fd, &msg, NULL, secret, strlen(secret)) != 0)
			continue; /* idle (EAGAIN), or a datagram that failed
				   * to parse -- neither is this loop's
				   * business */
		if (!msg)
			continue;
		if (list_empty(&msg->attrs)) {
			/* A ZLB: it acks something of ours, and acking it back
			 * would be an infinite ping-pong. */
			l2tp_packet_free(msg);
			continue;
		}

		*peer_next_nr = ntohs(msg->hdr.Ns) + 1;
		/* RFC 2661 4.1: Message-Type is always the first AVP. */
		msg_type = list_first_entry(&msg->attrs, typeof(*msg_type),
					    entry);
		if (msg_type->attr && msg_type->attr->id == Message_Type)
			type = msg_type->val.uint16;

		if (type == Message_Type_Incoming_Call_Request) {
			list_for_each_entry(attr, &msg->attrs, entry)
				if (attr->attr &&
				    attr->attr->id == Assigned_Session_ID)
					their_sid = (uint16_t)attr->val.int16;
			call_their_sid = their_sid;
			printf("event=recv_icrq round=%d t=%.6f\n",
			       round, now_monotonic());
		} else if (type == Message_Type_Incoming_Call_Connected) {
			printf("event=recv_iccn round=%d t=%.6f\n",
			       round, now_monotonic());
		} else if (type == Message_Type_Call_Disconnect_Notify) {
			printf("event=recv_cdn round=%d t=%.6f\n",
			       round, now_monotonic());
		} else if (type == Message_Type_Stop_Ctrl_Conn_Notify) {
			unsigned int res = 0;

			list_for_each_entry(attr, &msg->attrs, entry)
				if (attr->attr && attr->attr->id == Result_Code &&
				    attr->length >= 2)
					res = (unsigned int)
						((attr->val.octets[0] << 8) |
						 attr->val.octets[1]);
			printf("event=recv_stopccn round=%d t=%.6f res=%u\n",
			       round, now_monotonic(), res);
			stop = 1;
		}
		l2tp_packet_free(msg);
		fflush(stdout);

		if (type == Message_Type_Incoming_Call_Request && their_sid) {
			/* The reply's header sid is the *recipient's* own
			 * assigned session ID (RFC 2661 5.1), i.e. the one
			 * that arrived in the ICRQ; ours goes in the AVP. */
			rsp = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Reply,
						their_addr, 0, secret,
						strlen(secret));
			if (!rsp)
				return die("ICRP alloc failed");
			if (l2tp_packet_add_int16(rsp, Assigned_Session_ID,
						  next_sid, 1) < 0)
				return die("ICRP Assigned-Session-ID add failed");
			rsp->hdr.tid = htons(their_tid);
			rsp->hdr.sid = htons(their_sid);
			rsp->hdr.Ns = htons((*my_ns)++);
			rsp->hdr.Nr = htons(*peer_next_nr);
			if (l2tp_packet_send(fd, rsp) < 0)
				return die("ICRP send failed");
			l2tp_packet_free(rsp);
			call_our_sid = next_sid;
			next_sid++;
		} else {
			/* A bare ZLB ack. It takes no slot of its own in the
			 * sequence space (RFC 2661 5.8), so my_ns is left
			 * alone -- but without it the switch retransmits every
			 * message until it gives up on the whole tunnel, which
			 * would end exactly the idle window these tests
			 * measure. */
			rsp = l2tp_packet_alloc(2, 0, their_addr, 0, NULL, 0);
			if (!rsp)
				return die("ZLB alloc failed");
			rsp->hdr.tid = htons(their_tid);
			rsp->hdr.sid = 0;
			rsp->hdr.Ns = htons(*my_ns);
			rsp->hdr.Nr = htons(*peer_next_nr);
			if (l2tp_packet_send(fd, rsp) < 0)
				return die("ZLB send failed");
			l2tp_packet_free(rsp);
		}

		/* Deliberately after the ZLB ack just above, not before: a real
		 * peer's own ICCN handling would also finish acking the control
		 * message before doing anything else with the newly-connected
		 * call. */
		if (type == Message_Type_Incoming_Call_Connected && minimal_lcp) {
			if (serve_minimal_lcp_and_cdn(fd, their_addr, my_tid, their_tid,
						      call_our_sid, call_their_sid,
						      my_ns, peer_next_nr, round) < 0)
				return 1;
			if (cdn_after_lcp_ms > 0)
				break; /* the race this round exists to force is
					  already over; nothing more to serve */
		}

		if (stop)
			break;
	}

	return 0;
}

static int run_listen_mode(int rounds)
{
	struct sockaddr_in bind_addr = {
		.sin_family = AF_INET,
		.sin_addr = { htonl(INADDR_ANY) },
		.sin_port = peer_addr.sin_port,
	};
	int fd, round;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return die("listen socket() failed");
	if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0)
		return die("listen bind() failed");

	for (round = 0; round < rounds; ++round) {
		struct l2tp_packet_t *pack, *req;
		struct l2tp_attr_t *attr;
		struct sockaddr_in their_addr;
		uint16_t their_tid = 0, my_tid;
		uint16_t my_ns = 0, peer_next_nr;
		uint8_t chall[16];
		/* l2tp.c's own l2tp_send_SCCRQ()/l2tp_send_SCCRP() randomize
		 * their Challenge length per tunnel: (random & 0x7F) +
		 * MD5_DIGEST_LENGTH, i.e. up to 143 bytes -- confirmed by
		 * hitting a truncated-buffer silent-skip bug here with a
		 * fixed 64-byte buffer on exactly the second tunnel of a
		 * two-round run (first draw 64 bytes, second 82). 160 covers
		 * the real max with margin. */
		uint8_t their_chall[160];
		int their_chall_len = 0;
		uint8_t challresp[MD5_DIGEST_LENGTH];
		int err;

		for (;;) {
			if (l2tp_recv(fd, &req, NULL, secret, strlen(secret)) != 0)
				return die("waiting for SCCRQ failed");
			if (!req)
				continue;
			if (list_empty(&req->attrs)) {
				l2tp_packet_free(req);
				continue;
			}
			break;
		}
		their_addr = req->addr;
		peer_next_nr = ntohs(req->hdr.Ns) + 1;
		list_for_each_entry(attr, &req->attrs, entry) {
			if (attr->attr && attr->attr->id == Assigned_Tunnel_ID)
				their_tid = (uint16_t)attr->val.int16;
			/* RFC 2661 5.1.1 mutual tunnel auth: the SCCRQ's own
			 * Challenge (present whenever the switch has a
			 * [l2tp] secret=, which every fixture in this plan
			 * does) must be answered by a Challenge-Response in
			 * *this* SCCRP -- not in some later message -- or
			 * the switch rejects the SCCRP outright and never
			 * proceeds to SCCCN. Copied out before req is freed
			 * below. */
			if (attr->attr && attr->attr->id == Challenge &&
			    attr->length <= (int)sizeof(their_chall)) {
				memcpy(their_chall, attr->val.octets, attr->length);
				their_chall_len = attr->length;
			}
		}
		l2tp_packet_free(req);
		if (!their_tid)
			return die("SCCRQ carried no Assigned-Tunnel-ID");

		printf("event=recv_sccrq round=%d t=%.6f\n", round, now_monotonic());
		fflush(stdout);

		/* Deliberately stall mid-negotiation (see sccrp_delay_ms). The
		 * switch keeps retransmitting its SCCRQ meanwhile -- those
		 * duplicates are filtered out by the SCCCN wait loop below,
		 * which matches on Message-Type rather than accepting the next
		 * packet that happens to carry any attribute at all. */
		if (sccrp_delay_ms > 0)
			usleep((useconds_t)sccrp_delay_ms * 1000);

		my_tid = 1024 + (uint16_t)(random() % 60000);

		/* --- SCCRP --- */
		if (strlen(secret) > 0 && u_randbuf(chall, sizeof(chall), &err) < 0)
			return die("u_randbuf(challenge) failed");
		if (their_chall_len > 0 && strlen(secret) > 0)
			comp_chap_md5(challresp, Message_Type_Start_Ctrl_Conn_Reply,
				     secret, strlen(secret), their_chall,
				     their_chall_len);

		pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Reply,
					 &their_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("SCCRP alloc failed");
		l2tp_packet_add_int16(pack, Protocol_Version, L2TP_V2_PROTOCOL_VERSION, 1);
		l2tp_packet_add_int32(pack, Framing_Capabilities, 3, 1);
		l2tp_packet_add_string(pack, Host_Name, "fake-downstream", 1);
		l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, my_tid, 1);
		if (strlen(secret) > 0)
			l2tp_packet_add_octets(pack, Challenge, chall, sizeof(chall), 1);
		if (their_chall_len > 0 && strlen(secret) > 0) {
			if (l2tp_packet_add_octets(pack, Challenge_Response,
						   challresp, MD5_DIGEST_LENGTH, 1) < 0)
				return die("SCCRP Challenge-Response add failed");
		}
		pack->hdr.tid = htons(their_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (sccrp_storm_ms > 0) {
			if (send_sccrp_storm(fd, &their_addr, pack) != 0)
				return 1;
		} else if (l2tp_packet_send(fd, pack) < 0) {
			return die("SCCRP send failed");
		}
		l2tp_packet_free(pack);
		my_ns++;

		/* --- SCCCN --- */
		for (;;) {
			struct l2tp_packet_t *cn = NULL;
			struct l2tp_attr_t *msg_type;
			int is_scccn;

			if (l2tp_recv(fd, &cn, NULL, secret, strlen(secret)) != 0)
				return die("waiting for SCCCN failed");
			if (!cn)
				continue;
			if (list_empty(&cn->attrs)) {
				l2tp_packet_free(cn);
				continue;
			}
			/* RFC 2661 4.1: Message-Type is always the first AVP.
			 * Matching on it discards the SCCRQ retransmissions
			 * that pile up while --sccrp-delay-ms stalls us --
			 * accepting one of those as "the SCCCN" would report
			 * the tunnel established seconds before it really is,
			 * and would rewind peer_next_nr to a stale value. */
			msg_type = list_first_entry(&cn->attrs,
						    typeof(*msg_type), entry);
			is_scccn = msg_type->attr &&
				   msg_type->attr->id == Message_Type &&
				   msg_type->val.uint16 ==
					   Message_Type_Start_Ctrl_Conn_Connected;
			if (!is_scccn) {
				l2tp_packet_free(cn);
				continue;
			}
			peer_next_nr = ntohs(cn->hdr.Ns) + 1;
			l2tp_packet_free(cn);
			break;
		}

		printf("event=established round=%d t=%.6f\n", round, now_monotonic());
		fflush(stdout);

		if (send_stopccn) {
			struct l2tp_avp_result_code rc = { htons(1), htons(6) };

			pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
						 &their_addr, 0, secret, strlen(secret));
			if (!pack)
				return die("StopCCN alloc failed");
			l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, my_tid, 1);
			l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
					       sizeof(rc), 1);
			pack->hdr.tid = htons(their_tid);
			pack->hdr.sid = 0;
			pack->hdr.Ns = htons(my_ns);
			pack->hdr.Nr = htons(peer_next_nr);
			if (l2tp_packet_send(fd, pack) < 0)
				return die("StopCCN send failed");
			l2tp_packet_free(pack);
			my_ns++;

			printf("event=sent_stopccn round=%d t=%.6f\n", round, now_monotonic());
			fflush(stdout);
		}

		/* Without --hold-seconds this mode keeps its original
		 * behaviour: establish (or establish-then-StopCCN) and move
		 * straight on to the next round, saying nothing further. */
		if (hold_seconds > 0 &&
		    serve_established_tunnel(fd, &their_addr, my_tid, their_tid,
					     &my_ns, &peer_next_nr, round) < 0)
			return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int fd, opt;
	struct l2tp_packet_t *pack, *reply;
	uint16_t peer_tid, peer_sid;
	/* RFC 2661 5.8: every control message carries a monotonically
	 * increasing Ns and acks the peer's last-received Ns via Nr.
	 * l2tp_packet_alloc() zero-initializes both, so this harness must
	 * track and set them itself on every message beyond the first. */
	uint16_t my_ns = 0, peer_next_nr = 0;

	static struct option opts[] = {
		{"peer-addr", required_argument, 0, 'a'},
		{"peer-port", required_argument, 0, 'p'},
		{"secret", required_argument, 0, 's'},
		{"calling-number", required_argument, 0, 'c'},
		{"called-number", required_argument, 0, 'n'},
		{"proxy-username", required_argument, 0, 'u'},
		{"proxy-password", required_argument, 0, 'w'},
		{"data-pattern", required_argument, 0, 'd'},
		{"send-stopccn", no_argument, 0, 'x'},
		{"wait-cdn", no_argument, 0, 'W'},
		{"second-call", required_argument, 0, 'S'},
		{"real-ppp", no_argument, 0, 'R'},
		{"minimal-lcp", no_argument, 0, 'm'},
		{"hold-seconds", required_argument, 0, 'H'},
		{"listen", no_argument, 0, 'L'},
		{"rounds", required_argument, 0, 'N'},
		{"sccrp-delay-ms", required_argument, 0, 'D'},
		{"sccrp-storm-ms", required_argument, 0, 'M'},
		{"cdn-timeout", required_argument, 0, 'T'},
		{"cdn-after-lcp-ms", required_argument, 0, 'C'},
		{"expect-pap-name", required_argument, 0, 'E'},
		{"expect-pap-password", required_argument, 0, 'P'},
		{0, 0, 0, 0},
	};

	peer_addr.sin_family = AF_INET;
	peer_addr.sin_port = htons(1701);

	{
		unsigned seed = (unsigned)getpid() ^ (unsigned)time(NULL);

		srandom(seed);
		/* Keep both well clear of 0 (used as a "not yet assigned"
		 * sentinel elsewhere in this file) and of each other. */
		local_tid = 1024 + (uint16_t)(random() % 60000);
		local_sid = 1024 + (uint16_t)(random() % 60000);
	}

	while ((opt = getopt_long(argc, argv, "a:p:s:c:n:u:w:d:xWS:RmH:LN:D:M:T:C:E:P:", opts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			if (inet_aton(optarg, &peer_addr.sin_addr) == 0)
				return die("invalid --peer-addr");
			break;
		case 'p':
			peer_addr.sin_port = htons(atoi(optarg));
			break;
		case 's':
			secret = optarg;
			break;
		case 'c':
			calling_number = optarg;
			break;
		case 'n':
			called_number = optarg;
			break;
		case 'u':
			proxy_username = optarg;
			break;
		case 'w':
			proxy_password = optarg;
			break;
		case 'd':
			data_pattern = optarg;
			break;
		case 'x':
			send_stopccn = 1;
			break;
		case 'W':
			wait_cdn = 1;
			break;
		case 'S':
			second_call_number = optarg;
			break;
		case 'R':
			real_ppp = 1;
			break;
		case 'm':
			minimal_lcp = 1;
			break;
		case 'H':
			hold_seconds = atoi(optarg);
			break;
		case 'L':
			listen_mode = 1;
			break;
		case 'N':
			listen_rounds = atoi(optarg);
			break;
		case 'D':
			sccrp_delay_ms = atoi(optarg);
			if (sccrp_delay_ms < 0)
				return die("invalid --sccrp-delay-ms");
			break;
		case 'M':
			sccrp_storm_ms = atoi(optarg);
			if (sccrp_storm_ms < 0)
				return die("invalid --sccrp-storm-ms");
			break;
		case 'T':
			cdn_timeout = atoi(optarg);
			if (cdn_timeout <= 0)
				return die("invalid --cdn-timeout");
			break;
		case 'C':
			cdn_after_lcp_ms = atoi(optarg);
			if (cdn_after_lcp_ms < 0)
				return die("invalid --cdn-after-lcp-ms");
			break;
		case 'E':
			expect_pap_name = optarg;
			break;
		case 'P':
			expect_pap_password = optarg;
			break;
		default:
			return die("usage: --peer-addr A --peer-port P"
				   " --secret S [--calling-number C]"
				   " [--called-number N]"
				   " [--proxy-username U] [--proxy-password W]"
				   " [--data-pattern D] [--send-stopccn]"
				   " [--wait-cdn [--cdn-timeout S]]"
				   " [--second-call C]"
				   " [--real-ppp | --minimal-lcp] [--hold-seconds N]"
				   " [--listen [--rounds N] [--sccrp-delay-ms M]"
				   " [--sccrp-storm-ms M] [--hold-seconds N]"
				   " [--minimal-lcp [--cdn-after-lcp-ms M |"
				   " --expect-pap-name U --expect-pap-password W]]]");
		}
	}

	if (cdn_after_lcp_ms > 0 && !(listen_mode && minimal_lcp))
		return die("--cdn-after-lcp-ms requires --listen and --minimal-lcp");

	if (!!expect_pap_name != !!expect_pap_password)
		return die("--expect-pap-name and --expect-pap-password must be"
			   " given together");
	if (expect_pap_name && !(listen_mode && minimal_lcp))
		return die("--expect-pap-name requires --listen and --minimal-lcp");
	if (expect_pap_name && cdn_after_lcp_ms > 0)
		return die("--expect-pap-name and --cdn-after-lcp-ms are"
			   " mutually exclusive");

	if (listen_mode)
		return run_listen_mode(listen_rounds);

	/* connect()ed to the peer, exactly like the real daemon's own
	 * l2tp_tunnel_alloc() (l2tp.c ~1776) connect()s its per-tunnel UDP
	 * socket. This is required for the pppol2tp data channel: the
	 * kernel's pppol2tp/l2tp_core xmit path routes via the underlying
	 * UDP socket's connected peer (inet_sk(sk)->inet_daddr); leaving fd
	 * unconnected made data-channel write()/splice() report success
	 * while emitting zero wire packets, because the kernel had no
	 * destination to route to. l2tp_packet_send()'s sendto() with an
	 * explicit destination still works fine afterwards -- Linux does
	 * not return EISCONN for a connected SOCK_DGRAM socket used with
	 * sendto() (that restriction is for connection-mode/TCP sockets);
	 * the real daemon relies on exactly this same combination for
	 * every control message it sends. */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return die("socket() failed");
	if (connect(fd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0)
		return die("connect(fd) failed");

	/* --- SCCRQ --- */
	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Request,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("SCCRQ alloc failed");
	l2tp_packet_add_int16(pack, Protocol_Version, L2TP_V2_PROTOCOL_VERSION, 1);
	l2tp_packet_add_int32(pack, Framing_Capabilities, 3, 1);
	l2tp_packet_add_string(pack, Host_Name, "mk-simulator", 1);
	l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, local_tid, 1);
	pack->hdr.tid = 0;
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (send_and_recv(fd, pack, &reply) < 0)
		return die("SCCRQ/SCCRP exchange failed");
	my_ns++;
	peer_next_nr = ntohs(reply->hdr.Ns) + 1;

	/* RFC 2661 3.1: the header's Tunnel ID just echoes back the tunnel ID
	 * *we* assigned (local_tid) -- the peer's own tunnel ID, which we
	 * must use as the header tid on every subsequent message we send,
	 * comes from the Assigned-Tunnel-ID AVP in the SCCRP payload. */
	peer_tid = 0;

	/* Tunnel-auth Challenge (RFC 2661 5.1.1): present in SCCRP whenever
	 * the peer has a [l2tp] secret= configured, which every fixture in
	 * this plan does. */
	{
		struct l2tp_attr_t *attr;
		uint8_t *chall = NULL;
		int chall_len = 0;
		uint8_t challresp[MD5_DIGEST_LENGTH];

		list_for_each_entry(attr, &reply->attrs, entry) {
			if (attr->attr && attr->attr->id == Assigned_Tunnel_ID)
				peer_tid = (uint16_t)attr->val.int16;
			if (attr->attr && attr->attr->id == Challenge) {
				chall = attr->val.octets;
				chall_len = attr->length;
			}
		}

		if (peer_tid == 0) {
			l2tp_packet_free(reply);
			return die("SCCRP carried no Assigned-Tunnel-ID");
		}

		if (chall && strlen(secret) > 0)
			comp_chap_md5(challresp,
				     Message_Type_Start_Ctrl_Conn_Connected,
				     secret, strlen(secret), chall, chall_len);
		l2tp_packet_free(reply);

		/* --- SCCCN --- */
		pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Connected,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("SCCCN alloc failed");
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (chall && strlen(secret) > 0) {
			if (l2tp_packet_add_octets(pack, Challenge_Response,
						   challresp,
						   MD5_DIGEST_LENGTH, 1) < 0)
				return die("SCCCN Challenge-Response add failed");
		}
		if (l2tp_packet_send(fd, pack) < 0)
			return die("SCCCN send failed");
		l2tp_packet_free(pack);
		my_ns++;
	}

	/* --- ICRQ --- */
	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Request,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("ICRQ alloc failed");
	l2tp_packet_add_int16(pack, Assigned_Session_ID, local_sid, 1);
	l2tp_packet_add_int32(pack, Call_Serial_Number, 1, 1);
	l2tp_packet_add_string(pack, Calling_Number, calling_number, 1);
	if (called_number)
		l2tp_packet_add_string(pack, Called_Number, called_number, 1);
	pack->hdr.tid = htons(peer_tid);
	pack->hdr.sid = 0;
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (send_and_recv(fd, pack, &reply) < 0)
		return die("ICRQ/ICRP exchange failed");
	my_ns++;
	peer_next_nr = ntohs(reply->hdr.Ns) + 1;

	{
		struct l2tp_attr_t *a;
		peer_sid = 0;
		list_for_each_entry(a, &reply->attrs, entry)
			if (a->attr && a->attr->id == Assigned_Session_ID)
				peer_sid = a->val.uint16;
	}
	l2tp_packet_free(reply);

	if (!peer_sid)
		return die("ICRP carried no Assigned-Session-ID");

	/* --- ICCN --- */
	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
				 &peer_addr, 0, secret, strlen(secret));
	if (!pack)
		return die("ICCN alloc failed");
	l2tp_packet_add_int32(pack, TX_Speed, 1000, 1);
	l2tp_packet_add_int32(pack, Framing_Type, 3, 1);
	if (proxy_username) {
		/* Proxy-Authen-Type is int16 per dict/dictionary.rfc2661 (id 29),
		 * not an octet string -- 2 = PPP_PAP is sufficient here since this
		 * harness only needs to prove the AVP survives the switch intact,
		 * not exercise real PAP semantics. */
		l2tp_packet_add_int16(pack, Proxy_Authen_Type, 2, 1);
		l2tp_packet_add_string(pack, Proxy_Authen_Name, proxy_username, 1);
		if (proxy_password)
			l2tp_packet_add_string(pack, Proxy_Authen_Response,
					       proxy_password, 1);
	}
	pack->hdr.tid = htons(peer_tid);
	pack->hdr.sid = htons(peer_sid);
	pack->hdr.Ns = htons(my_ns);
	pack->hdr.Nr = htons(peer_next_nr);
	if (l2tp_packet_send(fd, pack) < 0)
		return die("ICCN send failed");
	l2tp_packet_free(pack);
	my_ns++;

	/* The switch places its downstream call off *this* message, so this
	 * timestamp is the zero point for measuring how long the switch takes
	 * to disconnect a call it cannot place (e.g. against an unreachable
	 * on-demand target). Only emitted under --wait-cdn, which is the only
	 * mode that waits around for that answer: this harness's plain
	 * "ok tid=... sid=..." output is a contract other tests assert on
	 * as-is. */
	if (wait_cdn) {
		printf("event=sent_iccn t=%.6f\n", now_monotonic());
		fflush(stdout);
	}

	if (real_ppp && (!proxy_username || !proxy_password))
		return die("--real-ppp requires --proxy-username and --proxy-password");

	if (real_ppp && minimal_lcp)
		return die("--real-ppp and --minimal-lcp are mutually exclusive");

	if (data_pattern || real_ppp || minimal_lcp) {
		struct sockaddr_pppol2tp pppox_addr;
		int data_fd, reg_fd, lns_mode = 0;

		/* Sending our own ICCN only completes *our* (MK's) side of the
		 * handshake -- on a real switch, ICCN triggers placing the
		 * downstream call asynchronously (its own ICRQ/ICRP/ICCN round
		 * trip), and only once *that* finishes does the switch open
		 * its own kernel socket for this (upstream) session and the
		 * splice actually starts moving bytes. Writing immediately
		 * races that: this local connect() below still succeeds
		 * regardless (it only sets up local kernel state for
		 * encapsulating outgoing packets, independent of whether the
		 * peer has a matching session yet), but the switch's kernel
		 * has nowhere to route the resulting packet until pairing
		 * finishes, so it is silently dropped -- confirmed on a real
		 * VM: the write "succeeds" but the byte pattern never reaches
		 * the downstream leg. A real PPP client papers over this via
		 * LCP's own retransmission; this harness has no such retry,
		 * so give the switch a moment instead. */
		usleep(300000);

		/* The real accel-ppp daemon registers each tunnel with the
		 * kernel's L2TP subsystem via a throwaway pppol2tp connect
		 * with session IDs left at 0 (l2tp_tunnel_connect(), l2tp.c
		 * ~2071) as soon as its own SCCRQ/SCCRP/SCCCN handshake
		 * completes -- confirmed on real hardware (Step 0 above) to
		 * be a hard prerequisite for any *session*-level pppol2tp
		 * connect() on that tunnel, which otherwise fails ENOENT.
		 * This harness plays the MK/LAC side of the upstream tunnel,
		 * so it must do the same registration itself before the real
		 * session-level connect below -- nothing else on this
		 * process's side ever does it, unlike the daemon, which
		 * always goes through l2tp_tunnel_connect() for every tunnel
		 * it establishes. */
		reg_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
		if (reg_fd < 0)
			return die("tunnel registration socket() failed");

		memset(&pppox_addr, 0, sizeof(pppox_addr));
		pppox_addr.sa_family = AF_PPPOX;
		pppox_addr.sa_protocol = PX_PROTO_OL2TP;
		pppox_addr.pppol2tp.fd = fd;
		pppox_addr.pppol2tp.addr = peer_addr;
		pppox_addr.pppol2tp.s_tunnel = local_tid;
		pppox_addr.pppol2tp.d_tunnel = peer_tid;
		/* s_session/d_session left at 0: this is the tunnel-level
		 * registration, not a real session. */

		if (connect(reg_fd, (struct sockaddr *)&pppox_addr,
			   sizeof(pppox_addr)) < 0)
			return die("tunnel registration connect() failed");
		close(reg_fd);

		data_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
		if (data_fd < 0)
			return die("data socket() failed");

		memset(&pppox_addr, 0, sizeof(pppox_addr));
		pppox_addr.sa_family = AF_PPPOX;
		pppox_addr.sa_protocol = PX_PROTO_OL2TP;
		pppox_addr.pppol2tp.fd = fd; /* share the control-channel UDP socket */
		pppox_addr.pppol2tp.addr = peer_addr;
		pppox_addr.pppol2tp.s_tunnel = local_tid;
		pppox_addr.pppol2tp.d_tunnel = peer_tid;
		pppox_addr.pppol2tp.s_session = local_sid;
		pppox_addr.pppol2tp.d_session = peer_sid;

		if (connect(data_fd, (struct sockaddr *)&pppox_addr,
			   sizeof(pppox_addr)) < 0)
			return die("data socket connect() failed");

		if (setsockopt(data_fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE,
			      &lns_mode, sizeof(lns_mode)) < 0)
			return die("data socket setsockopt(LNSMODE) failed");

		if (real_ppp) {
			/* run_real_ppp() takes ownership of data_fd -- it is
			 * inherited by the pppd child and closed by the
			 * parent right after fork(). */
			if (run_real_ppp(data_fd) != 0)
				return 1;
		} else if (minimal_lcp) {
			/* run_minimal_lcp() leaves data_fd open -- it is held
			 * alive by the existing --hold-seconds sleep below,
			 * same as the plain data_pattern branch's socket stays
			 * registered via `fd` (the control channel) rather
			 * than this one. */
			if (run_minimal_lcp(data_fd, 5) != 0)
				return 1;
		} else {
			ssize_t n = write(data_fd, data_pattern, strlen(data_pattern));

			if (n < 0)
				return die("data socket write() failed");

			close(data_fd);

			/* Give the kernel a moment to finish encapsulating and
			 * emitting the queued datagram before the process (and
			 * so `fd`, the UDP socket the tunnel/session are keyed
			 * to) exits and tears down the underlying socket. */
			usleep(200000);
		}
	}

	if (send_stopccn) {
		pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("StopCCN alloc failed");
		l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, local_tid, 1);
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (l2tp_packet_send(fd, pack) < 0)
			return die("StopCCN send failed");
		l2tp_packet_free(pack);
		my_ns++;
	}

	if (wait_cdn) {
		/* RFC 2661 5.1: a control message's header sid/tid is the ID
		 * *assigned by the recipient* -- a session-level CDN sent to
		 * us for our own call carries our own fixed local_sid (not
		 * peer_sid); a tunnel-level StopCCN carries sid 0 and our own
		 * local_tid. Accept either: l2tp_tunnel_disconnect() (l2tp.c
		 * ~1039) deliberately discards any already-queued CDN and
		 * sends only StopCCN when the tunnel itself is going down
		 * (the common case when the call being torn down is the
		 * tunnel's last session) -- "to minimise delay in case of
		 * congestion", per that function's own comment. Both signals
		 * unambiguously mean the same thing to a peer: this call is
		 * over. Requiring a CDN specifically would fail exactly the
		 * scenario this flag exists to test. Poll with a wall-clock
		 * deadline rather than a single SO_RCVTIMEO-bounded call,
		 * since SO_RCVTIMEO bounds each individual recv(), not the
		 * cumulative wait -- an intervening Hello/ZLB would
		 * otherwise reset the budget. */
		struct timeval tv = { .tv_sec = cdn_timeout, .tv_usec = 0 };
		time_t deadline = time(NULL) + cdn_timeout;
		int got_cdn = 0;

		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
			return die("setsockopt(SO_RCVTIMEO) failed");

		while (time(NULL) < deadline) {
			struct l2tp_packet_t *cdn = NULL;
			struct l2tp_attr_t *msg_type;
			int is_ours;

			if (l2tp_recv(fd, &cdn, NULL, secret, strlen(secret)) != 0) {
				if (errno == EAGAIN)
					break;
				continue;
			}
			if (!cdn)
				continue;
			is_ours = ntohs(cdn->hdr.sid) == local_sid ||
				  (ntohs(cdn->hdr.sid) == 0 &&
				   ntohs(cdn->hdr.tid) == local_tid);
			if (list_empty(&cdn->attrs) || !is_ours) {
				l2tp_packet_free(cdn);
				continue;
			}
			msg_type = list_first_entry(&cdn->attrs,
						    typeof(*msg_type), entry);
			if (msg_type->attr &&
			    msg_type->attr->id == Message_Type &&
			    (msg_type->val.uint16 ==
				     Message_Type_Call_Disconnect_Notify ||
			     msg_type->val.uint16 ==
				     Message_Type_Stop_Ctrl_Conn_Notify))
				got_cdn = 1;
			l2tp_packet_free(cdn);
			if (got_cdn)
				break;
		}

		if (!got_cdn)
			return die("timed out waiting for CDN");

		printf("event=recv_cdn t=%.6f\n", now_monotonic());
		fflush(stdout);
	}

	if (second_call_number) {
		/* A second call on the *same* tunnel, with a calling number
		 * that (by test setup) doesn't match any [l2tp-switch] line=
		 * entry -- exercises the switch instance's own normal,
		 * locally-terminated call path side by side with a switched
		 * one, to confirm one has no effect on the other. Own session
		 * ID (local_sid + 1): the tunnel is shared, but session IDs
		 * are not. */
		uint16_t second_local_sid = local_sid + 1;
		uint16_t second_peer_sid;

		pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Request,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("second ICRQ alloc failed");
		l2tp_packet_add_int16(pack, Assigned_Session_ID, second_local_sid, 1);
		l2tp_packet_add_int32(pack, Call_Serial_Number, 2, 1);
		l2tp_packet_add_string(pack, Calling_Number, second_call_number, 1);
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = 0;
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (send_and_recv(fd, pack, &reply) < 0)
			return die("second ICRQ/ICRP exchange failed");
		my_ns++;
		peer_next_nr = ntohs(reply->hdr.Ns) + 1;

		second_peer_sid = 0;
		{
			struct l2tp_attr_t *a;

			list_for_each_entry(a, &reply->attrs, entry)
				if (a->attr && a->attr->id == Assigned_Session_ID)
					second_peer_sid = a->val.uint16;
		}
		l2tp_packet_free(reply);

		if (!second_peer_sid)
			return die("second ICRP carried no Assigned-Session-ID");

		pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
					 &peer_addr, 0, secret, strlen(secret));
		if (!pack)
			return die("second ICCN alloc failed");
		l2tp_packet_add_int32(pack, TX_Speed, 1000, 1);
		l2tp_packet_add_int32(pack, Framing_Type, 3, 1);
		pack->hdr.tid = htons(peer_tid);
		pack->hdr.sid = htons(second_peer_sid);
		pack->hdr.Ns = htons(my_ns);
		pack->hdr.Nr = htons(peer_next_nr);
		if (l2tp_packet_send(fd, pack) < 0)
			return die("second ICCN send failed");
		l2tp_packet_free(pack);
		my_ns++;

		printf("second_call sid=%hu\n", second_local_sid);
	}

	/* Keep this process (and so the upstream tunnel's UDP socket) alive
	 * for a while after the handshake: without --real-ppp there is
	 * nothing else holding it open, and a test that needs to watch what
	 * the switch does with this call *seconds* later would otherwise be
	 * racing this socket's own teardown. --real-ppp does its own holding
	 * inside run_real_ppp(), so it is excluded here rather than sleeping
	 * twice. */
	if (hold_seconds > 0 && !real_ppp)
		sleep((unsigned int)hold_seconds);

	printf("ok tid=%hu sid=%hu\n", peer_tid, peer_sid);
	return 0;
}
