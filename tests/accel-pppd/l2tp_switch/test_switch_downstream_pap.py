import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance, read_log


@pytest.mark.l2tp_switch
def test_switch_downstream_pap_injection_authenticates_real_lns(pytestconfig, accel_cmd, accel_pppd):
    """The switch's live-PAP watcher (dda0105e, accel-pppd/ctrl/l2tp/l2tp.c)
    injects one synthesized PAP Authenticate-Request on the downstream leg,
    built from the Proxy-Authen-Name/Response AVPs already captured off the
    upstream ICCN, once it has observed a real LCP Configure-Ack in both
    directions. The downstream target here is a second, real, unmodified
    accel-pppd instance -- proving the injected frame is well-formed and
    actually authenticates against genuine PAP handling, not just that the
    switch believes it sent something.

    The upstream side must use --minimal-lcp (not the default --data-pattern,
    which never negotiates real LCP at all, and not --real-ppp, which
    negotiates real LCP *and* sends its own genuine live PAP -- a different,
    untested scenario, see docs/l2tp_switching.md's "Authentication"
    section) so the watcher's "CONFACK both ways" condition is actually
    satisfied the same way production traffic satisfies it.
    """
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        2101,
        "127.0.0.1",
        17070,
        "downstreamsecret",
        extra="""
    [modules]
    auth_pap

    [auth]
    any-login=1
    """,
    )
    assert d_started

    try:
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
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17071",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "injected-user",
                    "--proxy-password", "injected-pass",
                    "--minimal-lcp",
                    # long enough to cover LCP settling, the watcher's
                    # injected request, and this test's own polling below.
                    "--hold-seconds", "8",
                ],
            )

            # The proof: the DOWNSTREAM instance's own session state, not
            # just the switch's "placed" counter -- that only shows the
            # switch attempted to place the call, not that authentication
            # (the actual thing this feature adds) succeeded.
            active = False
            out = ""
            for _ in range(80):
                (exit, out, err) = process.run(
                    [accel_cmd, "-p", "2101", "show sessions", "state"]
                )
                assert exit == 0
                if "active" in out:
                    active = True
                    break
                time.sleep(0.1)
            assert active, (
                "downstream accel-pppd never reached an active session --"
                " the injected PAP request was never sent, malformed, or"
                f" rejected:\n{out}"
                f"\n--- switch (upstream) log ---\n{read_log(s_cfg)}"
                f"\n--- downstream log ---\n{read_log(d_cfg)}"
            )

            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{harness_out}"
                f"\n--- switch (upstream) log ---\n{read_log(s_cfg)}"
                f"\n--- downstream log ---\n{read_log(d_cfg)}"
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_switch_downstream_pap_nak_tears_down_both_legs(pytestconfig, accel_cmd, accel_pppd):
    """When the downstream target NAKs the injected PAP request (here: a
    real accel-pppd with auth_pap loaded but no any-login/matching secret,
    so it rejects every credential), the watcher must tear down both legs
    cleanly rather than leaving an orphaned pairing or hanging until some
    unrelated outer timeout -- see l2tp_switch_pap_send_request()'s NAK path
    in l2tp.c, which calls l2tp_session_disconnect_push() the same way every
    other switch-teardown path in this codebase does.
    """
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        2102,
        "127.0.0.1",
        17072,
        "downstreamsecret",
        extra="""
    [modules]
    auth_pap
    """,
    )
    assert d_started

    try:
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
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2002", "l2tp switch show"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
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
                f"\n--- switch (upstream) log ---\n{read_log(s_cfg)}"
                f"\n--- downstream log ---\n{read_log(d_cfg)}"
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
                f"\n--- switch (upstream) log ---\n{read_log(s_cfg)}"
                f"\n--- downstream log ---\n{read_log(d_cfg)}"
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2002)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2102)
        config.delete_tmp(d_cfg)
