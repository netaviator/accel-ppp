import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, read_log, wait_up, switch_show, wait_for, finish_harness


@pytest.mark.l2tp_switch
def test_switch_downstream_pap_injection_authenticates_real_lns(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    """The switch's live-PAP watcher (dda0105e, accel-pppd/ctrl/l2tp/l2tp.c)
    injects one synthesized PAP Authenticate-Request on the downstream leg,
    built from the Proxy-Authen-Name/Response AVPs already captured off the
    upstream ICCN, once it has observed a real LCP Configure-Ack in both
    directions.

    The downstream target is the peer test harness itself, in --listen +
    --minimal-lcp + --expect-pap-name/--expect-pap-password mode: it does
    real LCP, then decodes the injected PAP request byte-for-byte and
    checks it against the credentials expected here, rather than handing
    the frame to a second real accel-pppd instance's own auth stack just to
    get a yes/no back. This is deliberately simpler than an earlier version
    of this test that used a second real accel-pppd as the downstream: that
    dragged in a second daemon's entire auth_pap/any-login configuration as
    a dependency just to prove this watcher sent the right bytes, and BOTH
    of these things -- the watcher, and the test infrastructure needed to
    observe it -- are much easier to get right when they aren't tangled
    together. See wait_for_pap_request() in l2tp_switch_peer_test.c for the
    interception itself.

    The upstream side must use --minimal-lcp (not the default --data-pattern,
    which never negotiates real LCP at all, and not --real-ppp, which
    negotiates real LCP *and* sends its own genuine live PAP -- a different,
    untested scenario, see docs/l2tp_switching.md's "Authentication"
    section) so the watcher's "CONFACK both ways" condition is actually
    satisfied the same way production traffic satisfies it.
    """
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        switch_cli,
        "127.0.0.1",
        switch_l2tp,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    # Pinned to persistent: this test's own subject is the live-PAP watcher,
    # not connection mode -- see test_switch_avp_forward.py for the same
    # reasoning.
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started

    try:
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_l2tp),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--hold-seconds", "10",
                "--minimal-lcp",
                "--expect-pap-name", "injected-user",
                "--expect-pap-password", "injected-pass",
            ],
        )

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "injected-user",
                    "--proxy-password", "injected-pass",
                    "--minimal-lcp",
                    # long enough to cover LCP settling and the watcher's
                    # injected request.
                    "--hold-seconds", "8",
                ],
            )
            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{harness_out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)
            assert "event=pap_received" in down_out and "result=ack" in down_out, (
                "downstream harness never confirmed the injected PAP"
                " request -- it was never sent, malformed, or the"
                f" credentials didn't match:\n{down_out}\n{down_err}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )
        finally:
            finish_harness(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_switch_downstream_pap_nak_tears_down_both_legs(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    """When the downstream target NAKs the injected PAP request (here: the
    peer harness in --listen + --expect-pap-name mode, given credentials
    that don't match what the upstream side actually sends), the watcher
    must tear down both legs cleanly rather than leaving an orphaned
    pairing or hanging until some unrelated outer timeout -- see
    l2tp_switch_pap_send_request()'s NAK path in l2tp.c, which calls
    l2tp_session_disconnect_push() the same way every other switch-teardown
    path in this codebase does.
    """
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        switch_cli,
        "127.0.0.1",
        switch_l2tp,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started

    try:
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_l2tp),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--hold-seconds", "10",
                "--minimal-lcp",
                "--expect-pap-name", "correct-user",
                "--expect-pap-password", "correct-pass",
            ],
        )

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "nobody",
                    "--proxy-password", "wrong",
                    "--minimal-lcp",
                    "--hold-seconds", "8",
                    "--wait-cdn",
                ],
            )

            # RFC-level proof, mirroring test_switch_teardown.py: the switch
            # must send the upstream leg a CDN once the paired downstream
            # leg is gone, not just update an internal counter silently.
            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, (
                f"upstream harness never saw a CDN (rc={rc}): {err}\n{harness_out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            down_rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)
            assert "event=pap_received" in down_out and "result=nak" in down_out, (
                "downstream harness never NAKed the mismatched credentials"
                f" it was given:\n{down_out}\n{down_err}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            out = ""

            def drained():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 0" in out

            assert wait_for(drained, 8.0), (
                f"switch pairing left active after NAK:\n{out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )
        finally:
            finish_harness(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        config.delete_tmp(s_cfg)
