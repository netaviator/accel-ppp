import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, read_log, wait_up, switch_show, wait_for, finish_harness


@pytest.mark.l2tp_switch
def test_switch_downstream_no_pap_help(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """accel-ppp does not authenticate a switched call on the downstream
    target's behalf (see docs/l2tp_switching.md's Authentication section
    and docs/superpowers/specs/2026-09-22-l2tp-switch-drop-pap-injection-design.md).
    A target that asks for PAP gets that fact logged for operator
    visibility, but the switch never injects a PAP request and never tears
    the call down on the target's behalf -- it stays a transparent pipe.
    """
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
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
                "--hold-seconds", "12",
                "--minimal-lcp",
                "--lcp-auth", "pap",
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
                    "--hold-seconds", "10",
                ],
            )

            out = ""

            def is_up():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 1" in out

            assert wait_for(is_up, 5.0), (
                f"call never came up:\n{out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            def torn_down():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "active: 1" not in out

            # Negative check (scale=False, per wait_for's own docstring):
            # spend the full window watching for the switch to tear the
            # call down on its own -- confirms no injected PAP request, no
            # reply-timeout, no CDN from the switch itself.
            assert not wait_for(torn_down, 4.0, scale=False), (
                f"switch tore the call down on its own:\n{out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{harness_out}"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )

            log = read_log(s_cfg)
            assert "downstream LCP Configure-Request asks for PAP" in log, (
                "expected the visibility log line for the target's own PAP"
                f" request, got:\n{log}"
            )
            assert "injected live PAP request" not in log, (
                f"switch injected a PAP request -- this feature was removed:\n{log}"
            )
        finally:
            finish_harness(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        config.delete_tmp(s_cfg)
