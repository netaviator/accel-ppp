import pytest
import time
from common import process, config, accel_pppd_process


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
    # accel-cmd's default port (2001, used by the switch instance); without
    # it, the readiness/shutdown checks silently target the wrong port for
    # the whole max_wait_time instead of ever reaching this daemon.
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + downstream_config], accel_cmd, 5.0, cli_port=cli_port,
    )
    return started, thread, ctrl, downstream_config


@pytest.mark.l2tp_switch
def test_switch_tunnel_persistent_comes_up_with_no_calls(pytestconfig, accel_cmd, accel_pppd):
    # downstream ("customer") LNS instance, plain L2TP LNS on port 12345
    downstream_started, downstream_thread, downstream_ctrl, downstream_config = (
        _start_downstream(accel_pppd, accel_cmd, 2101, 12345, "downstreamsecret")
    )
    assert downstream_started

    try:
        # switch instance, pointing a persistent target at the downstream
        # instance -- persistent targets connect eagerly at startup, with
        # no call needed, unchanged from this test's original (pre-mode=)
        # behavior.
        switch_config = config.make_tmp(
            """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [l2tp]
    secret=upstreamsecret
    [l2tp-switch]
    target=downstream,127.0.0.1,12345,downstreamsecret,persistent
    """
        )
        switch_started, switch_thread, switch_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + switch_config], accel_cmd, 5.0
        )
        assert switch_started

        try:
            up = False
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])
                assert exit == 0
                if "downstream -> 127.0.0.1:12345 [up]" in out:
                    up = True
                    break
                time.sleep(0.1)

            assert up
        finally:
            accel_pppd_process.end(switch_thread, switch_ctrl, accel_cmd, 10.0)
            config.delete_tmp(switch_config)
    finally:
        accel_pppd_process.end(
            downstream_thread, downstream_ctrl, accel_cmd, 10.0, cli_port=2101
        )
        config.delete_tmp(downstream_config)


@pytest.mark.l2tp_switch
def test_switch_tunnel_on_demand_stays_down_with_no_calls(pytestconfig, accel_cmd, accel_pppd):
    # This is the direct behavioral regression test for the bug motivating
    # this whole plan: an on-demand target must NOT eagerly open a
    # session-less tunnel at startup -- doing so left a tunnel sitting idle
    # for a downstream peer's own idle-timeout policy to eventually flap
    # (e.g. JunOS tearing down a session-less tunnel after 60s). Uses
    # today's plain "[down]" wording; Task 4 introduces a friendlier
    # "[idle]" state and updates this same assertion once that lands.
    downstream_started, downstream_thread, downstream_ctrl, downstream_config = (
        _start_downstream(accel_pppd, accel_cmd, 2101, 12346, "downstreamsecret")
    )
    assert downstream_started

    try:
        # 4-field target= (mode omitted) -- on-demand is the default, so
        # this must behave identically to an explicit "on-demand" mode.
        switch_config = config.make_tmp(
            """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [l2tp]
    secret=upstreamsecret
    [l2tp-switch]
    target=downstream,127.0.0.1,12346,downstreamsecret
    """
        )
        switch_started, switch_thread, switch_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + switch_config], accel_cmd, 5.0
        )
        assert switch_started

        try:
            # give the (buggy, pre-fix) eager-connect sweep every chance to
            # run before asserting it didn't -- same polling budget as the
            # persistent test's "comes up" assertion, just inverted.
            up = False
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])
                assert exit == 0
                if "downstream -> 127.0.0.1:12346 [up]" in out:
                    up = True
                    break
                time.sleep(0.1)

            assert not up
            assert "downstream -> 127.0.0.1:12346 [down]" in out
        finally:
            accel_pppd_process.end(switch_thread, switch_ctrl, accel_cmd, 10.0)
            config.delete_tmp(switch_config)
    finally:
        accel_pppd_process.end(
            downstream_thread, downstream_ctrl, accel_cmd, 10.0, cli_port=2101
        )
        config.delete_tmp(downstream_config)
