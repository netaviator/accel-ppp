/*
 * l2tp-switch peer simulator: PPP/LCP/PAP helpers (real pppd, minimal LCP,
 * PAP request wait). See l2tp_switch_peer_test.c.
 */
#include "l2tp_switch_peer_test.h"

/* Mirrors l2tp.c's static inline comp_chap_md5() (~line 286) -- tunnel-auth
 * Challenge Response is MD5(msg-ident-octet || secret || challenge), per
 * RFC 2661 section 5.1.1 / 4.3. Needed because every test fixture in this
 * plan sets [l2tp] secret=, which makes the real daemon send a mandatory
 * Challenge AVP in its SCCRP and reject a SCCCN that doesn't answer it. */
void comp_chap_md5(uint8_t *md5, uint8_t ident,
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
int run_real_ppp(int data_fd)
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
int run_minimal_lcp(int data_fd, int timeout_seconds)
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
int wait_for_pap_request(int data_fd, const char *expect_name,
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
