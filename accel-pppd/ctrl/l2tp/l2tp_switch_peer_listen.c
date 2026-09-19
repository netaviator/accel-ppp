/*
 * l2tp-switch peer simulator: --listen role (downstream l2tp-switch target).
 * See l2tp_switch_peer_test.c.
 */
#include "l2tp_switch_peer_test.h"

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
 * Plays the *downstream target's* role instead of the usual upstream
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

	/* The kernel's L2TP transmit path needs the tunnel's UDP socket
	 * connect()ed to the peer (the client role does the same before
	 * registering, see main(); so does the real daemon's
	 * l2tp_tunnel_alloc()). This listening socket is only bound, so
	 * without this every frame written to the data socket below -- our
	 * own Configure-Request, our Ack of the peer's -- is silently never
	 * emitted, and LCP can never open. */
	if (connect(fd, (const struct sockaddr *)their_addr, sizeof(*their_addr)) < 0)
		return die("connect(fd) to the calling peer failed");

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

int run_listen_mode(int rounds)
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
			 * [l2tp] secret=, which every fixture in this test
			 * suite does) must be answered by a Challenge-Response in
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
