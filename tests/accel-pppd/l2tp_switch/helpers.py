import re
import time

from common import config, accel_pppd_process, process


def start_instance(accel_pppd, accel_cmd, cli_port, l2tp_bind, l2tp_port, secret, extra=""):
    cfg = config.make_tmp(
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
    bind={l2tp_bind}
    port={l2tp_port}
    secret={secret}
    {extra}
    """
    )
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
    )
    return started, thread, ctrl, cfg


def show_stat(accel_cmd, cli_port=2001):
    (exit_code, out, err) = process.run([accel_cmd, "-p", str(cli_port), "show stat"])
    assert exit_code == 0, f"show stat failed: {err}"
    return out


def tunnels_active(accel_cmd, cli_port=2001):
    """Global l2tp tunnel count, from `show stat`'s "l2tp: tunnels: active:"
    line -- deliberately NOT `l2tp switch show`'s per-target status word.

    Task 4 makes that per-target word ("[idle]" for on-demand targets)
    intentionally ambiguous between "idle but the tunnel is still open,
    lingering" and "the tunnel is genuinely gone" -- see this module's own
    l2tp_switch_show_exec() and docs/l2tp_switching.md's Observability
    section for why (`target_up` + `target_active` is the intended way to
    tell those apart, not the CLI's human-facing summary word). `show
    stat`'s tunnel-active count is untouched by that ambiguity: it reflects
    real STATE_ESTB tunnel objects, one-for-one. Safe to use as ground
    truth in any test scenario with at most one l2tp tunnel open at a time
    (true of every on-demand test in this suite, one target each).
    """
    out = show_stat(accel_cmd, cli_port)
    m = re.search(r"tunnels:\r?\n\s*starting: \d+\r?\n\s*active: (\d+)", out)
    assert m, f"couldn't parse tunnel count from show stat:\n{out}"
    return int(m.group(1))


def wait_for_tunnels_active(accel_cmd, expected, timeout, cli_port=2001):
    """Poll `tunnels_active()` until it equals `expected`.

    Returns (found, elapsed-seconds, last-observed-count).
    """
    started = time.monotonic()
    n = None
    while time.monotonic() - started < timeout:
        n = tunnels_active(accel_cmd, cli_port)
        if n == expected:
            return True, time.monotonic() - started, n
        time.sleep(0.1)
    return False, time.monotonic() - started, n
