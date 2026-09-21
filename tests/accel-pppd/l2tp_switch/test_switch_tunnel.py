import pytest
from common import config, accel_pppd_process
from helpers import alloc_ports, switch_show, wait_for


def _start_downstream(accel_pppd, accel_cmd, cli_port, l2tp_port, secret):
    downstream_config = config.make_tmp(
        f"""
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={l2tp_port}
    secret={secret}
    """
    )
    # cli_port -- this instance's own [cli] tcp= above, which isn't
    # accel-cmd's default port (2001); without it, the readiness/shutdown
    # checks silently target the wrong port for the whole max_wait_time
    # instead of ever reaching this daemon.
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + downstream_config], accel_cmd, 5.0, cli_port=cli_port,
    )
    return started, thread, ctrl, downstream_config


@pytest.mark.l2tp_switch
def test_switch_tunnel_persistent_comes_up_with_no_calls(pytestconfig, accel_cmd, accel_pppd):
    switch_cli, down_cli, switch_l2tp, down_l2tp = alloc_ports(4)
    # downstream ("customer") LNS instance, plain L2TP LNS
    downstream_started, downstream_thread, downstream_ctrl, downstream_config = (
        _start_downstream(accel_pppd, accel_cmd, down_cli, down_l2tp, "downstreamsecret")
    )
    assert downstream_started

    try:
        # switch instance, pointing a persistent target at the downstream
        # instance -- persistent targets connect eagerly at startup, with
        # no call needed, unchanged from this test's original (pre-mode=)
        # behavior.
        switch_config = config.make_tmp(
            f"""
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{switch_cli}
    [l2tp]
    port={switch_l2tp}
    secret=upstreamsecret
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    """
        )
        switch_started, switch_thread, switch_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + switch_config], accel_cmd, 5.0,
            cli_port=switch_cli,
        )
        assert switch_started

        try:
            out = ""

            def target_up():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return f"downstream -> 127.0.0.1:{down_l2tp} [up]" in out

            assert wait_for(target_up, 5.0), out
        finally:
            accel_pppd_process.end(
                switch_thread, switch_ctrl, accel_cmd, 10.0, cli_port=switch_cli
            )
            config.delete_tmp(switch_config)
    finally:
        accel_pppd_process.end(
            downstream_thread, downstream_ctrl, accel_cmd, 10.0, cli_port=down_cli
        )
        config.delete_tmp(downstream_config)


@pytest.mark.l2tp_switch
def test_switch_tunnel_on_demand_stays_down_with_no_calls(pytestconfig, accel_cmd, accel_pppd):
    # This is the direct behavioral regression test for the bug motivating
    # this whole plan: an on-demand target must NOT eagerly open a
    # session-less tunnel at startup -- doing so left a tunnel sitting idle
    # for a downstream peer's own idle-timeout policy to eventually flap
    # (e.g. JunOS tearing down a session-less tunnel after 60s). Uses
    # The friendlier "[idle]" wording for on-demand targets at rest
    # (persistent targets, elsewhere in this file, keep plain "[down]").
    switch_cli, down_cli, switch_l2tp, down_l2tp = alloc_ports(4)
    downstream_started, downstream_thread, downstream_ctrl, downstream_config = (
        _start_downstream(accel_pppd, accel_cmd, down_cli, down_l2tp, "downstreamsecret")
    )
    assert downstream_started

    try:
        # 4-field target= (mode omitted) -- on-demand is the default, so
        # this must behave identically to an explicit "on-demand" mode.
        switch_config = config.make_tmp(
            f"""
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{switch_cli}
    [l2tp]
    port={switch_l2tp}
    secret=upstreamsecret
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret
    """
        )
        switch_started, switch_thread, switch_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + switch_config], accel_cmd, 5.0,
            cli_port=switch_cli,
        )
        assert switch_started

        try:
            # give the (buggy, pre-fix) eager-connect sweep every chance to
            # run before asserting it didn't -- same polling budget as the
            # persistent test's "comes up" assertion, just inverted.
            out = ""

            def target_up():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return f"downstream -> 127.0.0.1:{down_l2tp} [up]" in out

            assert not wait_for(target_up, 5.0, scale=False)
            assert f"downstream -> 127.0.0.1:{down_l2tp} [idle]" in out
        finally:
            accel_pppd_process.end(
                switch_thread, switch_ctrl, accel_cmd, 10.0, cli_port=switch_cli
            )
            config.delete_tmp(switch_config)
    finally:
        accel_pppd_process.end(
            downstream_thread, downstream_ctrl, accel_cmd, 10.0, cli_port=down_cli
        )
        config.delete_tmp(downstream_config)
