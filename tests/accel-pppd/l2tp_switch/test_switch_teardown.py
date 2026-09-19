import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, switch_show, wait_for, wait_up


@pytest.mark.l2tp_switch
def test_downstream_drop_tears_down_upstream(pytestconfig, accel_cmd, accel_pppd, peer_bin):
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
    # Pinned to persistent: this test's own subject is downstream-drop
    # teardown cascades, not connection mode -- it relies on the target's
    # tunnel already being up before any call is placed, which on-demand
    # mode's default no longer does. See
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # establish one switched call, then block waiting for the CDN
            # the switch's upstream leg must send once the paired downstream
            # leg goes away -- proves the actual RFC-level teardown, not
            # just an internal counter.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--wait-cdn",
                ],
            )

            out = ""
            def active_1():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 1" in out

            assert wait_for(active_1, 5.0), out

            # kill the downstream instance mid-call -- the switch's
            # l2tp_session_free() teardown hook must notice and tear down
            # the paired upstream leg too, rather than crashing or leaking.
            accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)

            rc, out2, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            out = ""
            def active_0():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 0" in out

            assert wait_for(active_0, 5.0), out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        # already ended mid-test above in the success path; end() is a
        # no-op on an already-terminated process, so this still cleans up
        # correctly if an earlier assertion failed first.
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
