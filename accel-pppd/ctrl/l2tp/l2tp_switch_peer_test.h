/*
 * Internal shared header for the standalone l2tp-switch peer simulator
 * (l2tp_switch_peer_test.c, l2tp_switch_peer_lcp.c, l2tp_switch_peer_listen.c).
 * Not part of the cmake build; see l2tp_switch_peer_test.c for how to compile.
 */
#ifndef L2TP_SWITCH_PEER_TEST_H
#define L2TP_SWITCH_PEER_TEST_H

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

/* Option globals, defined (with their documentation) in
 * l2tp_switch_peer_test.c. */
extern struct sockaddr_in peer_addr;
extern const char *secret;
extern const char *calling_number;
extern const char *called_number;
extern const char *proxy_username;
extern const char *proxy_password;
extern const char *data_pattern;
extern int send_stopccn;
extern int wait_cdn;
extern int real_ppp;
extern int minimal_lcp;
extern int hold_seconds;
extern int listen_mode;
extern int listen_rounds;
extern int sccrp_delay_ms;
extern int sccrp_storm_ms;
extern int cdn_timeout;
extern int cdn_after_lcp_ms;
extern const char *expect_pap_name;
extern const char *expect_pap_password;
extern const char *second_call_number;
extern uint16_t local_tid;
extern uint16_t local_sid;

int u_randbuf(void *buf, size_t buf_len, int *err);
int die(const char *msg);
double now_monotonic(void);

/* l2tp_switch_peer_lcp.c */
void comp_chap_md5(uint8_t *md5, uint8_t ident,
		   const void *secret, size_t secret_len,
		   const void *chall, size_t chall_len);
int run_real_ppp(int data_fd);
int run_minimal_lcp(int data_fd, int timeout_seconds);
int wait_for_pap_request(int data_fd, const char *expect_name,
			 const char *expect_password,
			 int timeout_seconds, int round);

/* l2tp_switch_peer_listen.c */
int run_listen_mode(int rounds);

#endif /* L2TP_SWITCH_PEER_TEST_H */
