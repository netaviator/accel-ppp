import threading
import time

import pytest
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports, start_instance, read_log, show_stat, switch_show, wait_up, wait_for, finish_harness,
)


@pytest.mark.l2tp_switch
def test_pap_reply_timeout_disconnects_call(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """A downstream that finishes LCP but never answers the injected PAP
    request must get the call torn down by the watcher's own reply timeout.

    Regression: l2tp_switch_pap_watcher_put() used to mark the watcher
    resolved on every call -- including the release send_request() does on
    its own success path -- so this timeout, and the handling of a downstream
    Nak, were silently dead after any successful injection.
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
    target=mute,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,mute
    """,
    )
    assert s_started

    try:
        # --minimal-lcp without --expect-pap-*: real LCP, then the harness
        # drops its data socket and never answers PAP.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_l2tp),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--hold-seconds", "12",
                "--minimal-lcp",
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
                    "--proxy-username", "someone",
                    "--proxy-password", "somepw",
                    "--minimal-lcp",
                    "--hold-seconds", "10",
                ],
            )

            deadline = time.monotonic() + 12.0
            log = ""
            while time.monotonic() < deadline:
                log = read_log(s_cfg)
                if "never answered our injected live PAP request" in log:
                    break
                time.sleep(0.2)
            assert "never answered our injected live PAP request" in log, log

            out = ""

            def drained():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "  active: 0" in out

            wait_for(drained, 5.0)
            assert "  active: 0" in out, out

            l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
        finally:
            finish_harness(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_rule_churn_while_calls_are_matched(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """`l2tp switch add|del` runs on the CLI thread while every ICRQ/ICCN is
    matched against the same rule list on a tunnel context. Hammer the CLI
    while calls arrive: the daemon must stay alive, every call must still
    match (the untouched base rule is never removed), and the churned rules
    must all be gone afterwards.

    Nondeterministic by nature -- it is the kind of test a ThreadSanitizer
    or ASAN leg turns from "rarely crashes" into "reliably reports".
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
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            stop = threading.Event()
            failures = []

            def churn():
                i = 0
                while not stop.is_set():
                    value = f"9{i:05d}"
                    add = process.run([accel_cmd, "-p", str(switch_cli),
                                       f"l2tp switch add Calling-Number exact {value} downstream"])
                    if add[0] != 0:
                        failures.append(("add", value, add))
                    dele = process.run([accel_cmd, "-p", str(switch_cli),
                                        f"l2tp switch del Calling-Number exact {value}"])
                    if dele[0] != 0:
                        failures.append(("del", value, dele))
                    i += 1

            churner = threading.Thread(target=churn)
            churner.start()
            try:
                calls = 3
                for _ in range(calls):
                    peer_thread, peer_ctrl = l2tp_peer_process.start(
                        peer_bin,
                        [
                            "--peer-addr", "127.0.0.1",
                            "--peer-port", str(switch_l2tp),
                            "--secret", "upstreamsecret",
                            "--calling-number", "472913",
                        ],
                    )
                    rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
                    assert rc == 0, err
            finally:
                stop.set()
                churner.join(30.0)

            assert not failures, failures[:3]
            assert "uptime" in show_stat(accel_cmd, switch_cli)
            assert f"matched: {calls}" in switch_show(accel_cmd, switch_cli)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_rapid_call_churn_leaves_no_pairing(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """Calls that end almost as soon as they start put the upstream leg's
    teardown right next to the downstream leg's placement and splice setup,
    which run on two different tunnel contexts. Whatever order the two land
    in, every pairing must be torn down again: nothing may stay "active", the
    daemon must stay responsive, and every call must still have matched.

    Like the rule-churn test this is a stress test -- under the CI TSAN leg a
    lost update between the two contexts shows up as a report even when the
    run itself happens to pass.
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
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            calls = 8
            for _ in range(calls):
                peer_thread, peer_ctrl = l2tp_peer_process.start(
                    peer_bin,
                    [
                        "--peer-addr", "127.0.0.1",
                        "--peer-port", str(switch_l2tp),
                        "--secret", "upstreamsecret",
                        "--calling-number", "472913",
                        "--proxy-username", "churn",
                        "--proxy-password", "churnpw",
                    ],
                )
                rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
                assert rc == 0, err

            out = ""
            for _ in range(100):
                out = switch_show(accel_cmd, switch_cli)
                if "  active: 0" in out:
                    break
                time.sleep(0.1)
            assert "  active: 0" in out, out
            assert f"matched: {calls}" in out, out
            assert "uptime" in show_stat(accel_cmd, switch_cli)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)
