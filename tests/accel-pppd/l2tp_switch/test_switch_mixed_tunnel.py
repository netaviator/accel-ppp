import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, switch_show, wait_for, wait_up


@pytest.mark.l2tp_switch
def test_downstream_failure_does_not_affect_locally_terminated_session(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """A real upstream tunnel plausibly carries both switched calls and
    ordinary, locally-terminated calls side by side -- only the calling
    numbers listed under [l2tp-switch] match= get switched, everything
    else on the same tunnel goes through accel-ppp's own normal PPP
    stack. When one switched call's downstream leg fails, only that one
    call may be affected: the shared upstream tunnel and any other,
    unrelated session riding on it (switched or not) must survive.
    """
    switch_cli, down_cli, switch_l2tp, down_l2tp = alloc_ports(4)
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, down_cli, "127.0.0.1", down_l2tp, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            switch_cli,
            "127.0.0.1",
            switch_l2tp,
            "upstreamsecret",
            extra=f"""
    [l2tp-switch]
    # Pinned to persistent: this test's own subject is mixed switched/local
    # call isolation, not connection mode -- it relies on the target's
    # tunnel already being up before any call is placed, which on-demand
    # mode's default no longer does. See
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # place a switched call (472913, matches the match= entry above)
            # and, on the *same* tunnel, a second call with a calling number
            # that does NOT match any match= entry -- an ordinary,
            # locally-terminated call on the switch instance's own PPP stack.
            #
            # --hold-seconds keeps this "upstream LAC" alive -- and with it the
            # upstream tunnel's socket -- for the whole teardown below.
            # Without it the harness exits as soon as both calls are up, and
            # the switched call's own CDN (sent to the upstream leg when its
            # downstream leg fails) lands on a closed port: the ICMP
            # unreachable that comes back takes the entire upstream tunnel
            # down, locally-terminated session and all, with nothing to do
            # with the isolation this test is about. A real the upstream LAC does not
            # vanish between placing a call and hearing that it ended.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--second-call", "999999",
                    "--hold-seconds", "20",
                ],
            )

            out = ""
            def active_1():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 1" in out

            assert wait_for(active_1, 5.0), out

            (exit, sessions_out, err) = process.run([accel_cmd, "-p", str(switch_cli), "show sessions"])
            assert "999999" in sessions_out, sessions_out

            # gracefully end the downstream instance -- the switched call's
            # own leg fails, but the locally-terminated call (999999) on the
            # same upstream tunnel must be completely unaffected. Check
            # promptly: the fake second call has no real PPP client behind
            # it, so it eventually times out on its own (unrelated to this
            # test) after a while -- the assertion here is about the moment
            # right after the switched call's own teardown, not the second
            # call's own eventual, unrelated lifecycle.
            accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)

            out = ""
            def active_0():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 0" in out

            assert wait_for(active_0, 5.0), out

            (exit, sessions_out, err) = process.run([accel_cmd, "-p", str(switch_cli), "show sessions"])
            assert exit == 0
            assert "999999" in sessions_out, (
                "locally-terminated session was torn down alongside the "
                "unrelated switched call's failure:\n" + sessions_out
            )

            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 30.0)
            assert rc == 0, err
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
