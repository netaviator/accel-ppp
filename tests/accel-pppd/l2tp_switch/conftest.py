import subprocess
from pathlib import Path

import pytest

# l2tp_switch_peer_test.c is deliberately not part of the cmake build (it
# stubs the AVP dictionary and links packet.c standalone -- see the comment
# at the top of that file for why it can't share the real daemon's dict.c).
# Every test in this directory that drives it assumes it already exists at
# a fixed path; nothing else builds it for them, so without this fixture a
# fresh checkout (CI included) fails every one of those tests with no
# indication beyond "no such file or directory" buried in a Popen traceback.
_PEER_TEST_SRC_DIR = Path(__file__).resolve().parents[3] / "accel-pppd" / "ctrl" / "l2tp"
_PEER_TEST_BIN = Path("/tmp/l2tp_switch_peer_test")


@pytest.fixture(scope="session", autouse=True)
def l2tp_switch_peer_test_binary():
    result = subprocess.run(
        [
            "gcc",
            "-O1",
            "-g",
            "-Wall",
            "-fno-strict-aliasing",
            "-D_GNU_SOURCE",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-I",
            str(_PEER_TEST_SRC_DIR / ".." / ".." / "include"),
            "-I",
            str(_PEER_TEST_SRC_DIR),
            "-o",
            str(_PEER_TEST_BIN),
            str(_PEER_TEST_SRC_DIR / "l2tp_switch_peer_test.c"),
            str(_PEER_TEST_SRC_DIR / "packet.c"),
            "-lcrypto",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            "failed to build l2tp_switch_peer_test (needed by every "
            "l2tp_switch test):\n" + result.stdout + result.stderr
        )
    return _PEER_TEST_BIN


@pytest.fixture()
def l2tp_switch_config():
    # should be redefined by specific tests
    return ""


@pytest.fixture()
def accel_pppd_config(l2tp_switch_config):
    return (
        """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [l2tp]
    verbose=1
    secret=testsecret

    """
        + l2tp_switch_config
    )
