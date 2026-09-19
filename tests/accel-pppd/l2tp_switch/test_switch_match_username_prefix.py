import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, switch_show, wait_for, wait_up


@pytest.mark.l2tp_switch
def test_switch_matches_on_proxied_username_prefix(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """Proxy-Authen-Name only arrives in ICCN, not ICRQ (unlike
    Calling-Number/Called-Number) -- this exercises the switch's other
    matching pass, run from within l2tp_recv_ICCN's own AVP loop, and its
    prefix mode rather than exact.
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
    # Pinned to persistent: this test's own subject is username-prefix
    # matching, not connection mode -- it relies on the target's tunnel
    # already being up before any call is placed, which on-demand mode's
    # default no longer does. See
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Proxy-Authen-Name,prefix,downstream-,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # calling-number deliberately does NOT match anything -- only
            # the proxied username's prefix should route this call.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "000000",
                    "--proxy-username", "downstream-54546#level66@bsa-vdsl",
                    "--proxy-password", "irrelevant",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            (exit, out, err) = process.run([accel_cmd, "-p", str(switch_cli), "l2tp switch show"])
            assert "matched: 1" in out, out
            assert "placed: 1" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_switch_calling_number_takes_precedence_over_username_prefix(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """When both an exact Calling-Number rule and a username-prefix rule
    could apply, Calling-Number wins -- it's checked at ICRQ time, before
    Proxy-Authen-Name is even available (ICCN-time matching only runs at
    all if sess->switch_target is still unset)."""
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
    # Pinned to persistent: this test's own subject is match-rule
    # precedence, not connection mode -- it relies on the target's tunnel
    # already being up before any call is placed, which on-demand mode's
    # default no longer does. See
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    match=Proxy-Authen-Name,prefix,downstream-,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            # both rules could apply to this one call -- proves this
            # doesn't double-count (matched: 1, not 2) and doesn't crash
            # attempting to re-match an already-tagged session.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "downstream-54546#level66@bsa-vdsl",
                    "--proxy-password", "irrelevant",
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            (exit, out, err) = process.run([accel_cmd, "-p", str(switch_cli), "l2tp switch show"])
            assert "matched: 1" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
