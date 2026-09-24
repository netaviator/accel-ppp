import subprocess
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, read_log, finish_harness

DATA_PATTERN = "SWITCHOK"


@pytest.mark.l2tp_switch
def test_switch_upstream_data_sent_during_slow_downstream_connect_is_not_lost(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """The switch deliberately does not connect the upstream leg's own
    kernel pppol2tp socket at ICCN time -- it is only connected later, once
    the downstream leg's own SCCRQ/SCCRP/SCCCN + ICRQ/ICRP handshake with
    the target has finished (l2tp_switch_finish_upstream(), scheduled from
    l2tp_recv_ICRP() on the downstream leg's own context).

    Until that connect() happens, the kernel has no session registered for
    the upstream leg at all: any data frame the real upstream peer sends in
    the meantime -- which it has every reason to do the moment its own ICCN
    exchange with the switch completes, independent of how long the
    downstream target takes to answer -- is silently dropped by the
    kernel, with no log anywhere in this codebase. This is the same
    ordering hazard l2tp_switch_peer_test.c's own comment above its
    `usleep(300000)` documents fighting around in the test harness itself
    ("A real PPP client papers over this via LCP's own retransmission;
    this harness has no such retry, so give the switch a moment instead"):
    the harness's own pre-write sleep is not a fix, just a big enough grace
    period that other tests (whose downstream targets answer near-instantly)
    don't hit this window in practice.

    On an on-demand target with no already-warm tunnel, the downstream
    handshake can easily take longer than that fixed 300ms grace period --
    exactly the shape of the production traffic this test reproduces:
    every call is a cold start (idle-linger long since closed the previous
    call's tunnel), and the downstream leg takes over a second to answer.
    Anything the upstream peer wrote is gone before the upstream socket is
    ever connected.
    """
    sccrp_delay = 1.5
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "10",
            "--sccrp-delay-ms", str(int(sccrp_delay * 1000)),
        ],
    )

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
    target=slow,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,slow
    """,
        )
        assert s_started

        try:
            capture = subprocess.Popen(
                ["tcpdump", "-l", "-A", "-i", "lo", "udp", "port", str(down_l2tp)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            time.sleep(0.5)  # let tcpdump attach before traffic starts

            try:
                # No --hold-seconds truncation risk here: the harness's own
                # default hold comfortably outlasts sccrp_delay, and the
                # call must not hang up before the slow downstream leg
                # finishes connecting -- "a call ending always tears down
                # its pair" would otherwise tear the queued call down
                # before there is anything to observe.
                peer_thread, peer_ctrl = l2tp_peer_process.start(
                    peer_bin,
                    [
                        "--peer-addr", "127.0.0.1",
                        "--peer-port", str(switch_l2tp),
                        "--secret", "upstreamsecret",
                        "--calling-number", "472913",
                        "--data-pattern", DATA_PATTERN,
                        "--hold-seconds", str(sccrp_delay + 2.5),
                    ],
                )
                rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 15.0)
                assert rc == 0, (
                    f"upstream harness failed (rc={rc}): {err}\n{out}"
                    f"\n--- switch log ---\n{read_log(s_cfg)}"
                )

                # Give the (now-completed) downstream handshake time to
                # finish and, if the fix is in place, for the buffered
                # write to actually be spliced through.
                time.sleep(sccrp_delay + 1.0)
            finally:
                capture.terminate()
                capture_out, _ = capture.communicate(timeout=5.0)

            assert DATA_PATTERN in capture_out, (
                "the upstream peer's data, written right after its own"
                " ICCN while the downstream leg was still mid-handshake,"
                " never reached the downstream target -- it was dropped"
                " by the kernel because the upstream session's own socket"
                " was not connected yet"
                f"\n--- switch log ---\n{read_log(s_cfg)}"
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        finish_harness(down_thread, down_ctrl, 15.0)
