import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance, read_log

PEER_BIN = "/tmp/l2tp_switch_peer_test"


def _finish(thread, ctrl, timeout):
    """Join a harness process, killing it if it outlives `timeout`.

    Mirrors test_switch_downstream_pap_race.py's own helper of the same
    name exactly: a --listen instance blocks on its bound UDP port until
    --hold-seconds is up regardless of what happened to the call it
    served, and left alone past this test's own patience it would poison
    every later test in the same run that needs that port. Safe to call
    more than once on the same (thread, ctrl) -- joining an already-
    finished thread just returns immediately with the same stored output.
    """
    rc, out, err = l2tp_peer_process.wait(thread, ctrl, timeout)
    if rc is None:
        ctrl["process"].kill()
        thread.join(5.0)
        rc = ctrl["process"].returncode
        out, err = ctrl["out"], ctrl["err"]
    return rc, out, err


@pytest.mark.l2tp_switch
def test_switch_downstream_pap_injection_authenticates_real_lns(pytestconfig, accel_cmd, accel_pppd):
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
        2001,
        "127.0.0.1",
        17071,
        "upstreamsecret",
        extra="""
    [l2tp-switch]
    # Pinned to persistent: this test's own subject is the live-PAP watcher,
    # not connection mode -- see test_switch_avp_forward.py for the same
    # reasoning.
    target=downstream,127.0.0.1,17070,downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started

    try:
        down_thread, down_ctrl = l2tp_peer_process.start(
            PEER_BIN,
            [
                "--listen",
                "--peer-port", "17070",
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--hold-seconds", "10",
                "--minimal-lcp",
                "--expect-pap-name", "injected-user",
                "--expect-pap-password", "injected-pass",
            ],
        )

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17071",
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

            down_rc, down_out, down_err = _finish(down_thread, down_ctrl, 15.0)
            assert "event=pap_received" in down_out and "result=ack" in down_out, (
                "downstream harness never confirmed the injected PAP"
                " request -- it was never sent, malformed, or the"
                f" credentials didn't match:\n{down_out}\n{down_err}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )
        finally:
            _finish(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_switch_downstream_pap_nak_tears_down_both_legs(pytestconfig, accel_cmd, accel_pppd):
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
        2002,
        "127.0.0.1",
        17073,
        "upstreamsecret",
        extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17072,downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
    )
    assert s_started

    try:
        down_thread, down_ctrl = l2tp_peer_process.start(
            PEER_BIN,
            [
                "--listen",
                "--peer-port", "17072",
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--hold-seconds", "10",
                "--minimal-lcp",
                "--expect-pap-name", "correct-user",
                "--expect-pap-password", "correct-pass",
            ],
        )

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2002", "l2tp switch show"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17073",
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

            down_rc, down_out, down_err = _finish(down_thread, down_ctrl, 15.0)
            assert "event=pap_received" in down_out and "result=nak" in down_out, (
                "downstream harness never NAKed the mismatched credentials"
                f" it was given:\n{down_out}\n{down_err}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            active = None
            out = ""
            for _ in range(80):
                (exit, out, err) = process.run([accel_cmd, "-p", "2002", "l2tp switch show"])
                assert exit == 0
                if "active: 0" in out:
                    active = 0
                    break
                time.sleep(0.1)
            assert active == 0, (
                f"switch pairing left active after NAK:\n{out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )
        finally:
            _finish(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2002)
        config.delete_tmp(s_cfg)
