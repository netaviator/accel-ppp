import pytest
from common import process

pytestmark = pytest.mark.xdist_group("fixed-port")


@pytest.mark.l2tp_switch
class TestTargetModePersistentExplicit:
    """explicit "persistent" parses and the target still shows in
    `l2tp switch show` -- config-parse-only, the peer-addr is an
    unreachable TEST-NET-3 address by design, so this never waits on
    "[up]"."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,persistent
    """

    def test_switch_target_mode_persistent_explicit(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeOnDemandExplicit:
    """explicit "on-demand" parses and the target still shows in
    `l2tp switch show`."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,on-demand
    """

    def test_switch_target_mode_on_demand_explicit(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeOmittedDefaultsOnDemand:
    """4-field target= (mode omitted) must still parse successfully and
    default to on-demand -- not a parse error, not a crash."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_target_mode_omitted_defaults_on_demand(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeUnknownRejected:
    """An unrecognized 5th field must be a fatal config-load error, same as
    an unknown match= mode today -- not silently ignored, not a crash."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,bogus
    """

    def test_switch_target_mode_unknown_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
def test_l2tp_switch_show_empty(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

    assert exit == 0
    assert "targets:" in out


@pytest.mark.l2tp_switch
class TestWithTarget:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    match=Calling-Number,exact,472913,acme
    """

    def test_l2tp_switch_show_target(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestDuplicateMatch:
    """An exact match= value must not appear twice for the same attr, even
    pointing at different targets -- a fatal config-load error, not silent
    last-wins."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Calling-Number,exact,472913,acme
    match=Calling-Number,exact,472913,other
    """

    def test_duplicate_match_value_rejected(self, accel_pppd_instance):
        # l2tp_switch_conf_load() returning -1 makes l2tp_init() call
        # log_emerg()+_exit(EXIT_FAILURE) before the daemon ever becomes
        # ready -- accel_pppd_instance (the shared fixture) should report
        # this as a failed start, not a successful one.
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestOverlappingPrefix:
    """Two prefix rules on the same attr are ambiguous if either one is a
    prefix of the other's own value -- also a fatal config-load error."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Proxy-Authen-Name,prefix,downstream,acme
    match=Proxy-Authen-Name,prefix,downstream-a,other
    """

    def test_overlapping_prefix_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestExactOverlapsPrefix:
    """An exact value that would itself satisfy another rule's prefix (or
    vice versa) is exactly as ambiguous as two overlapping prefixes -- also
    rejected."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Proxy-Authen-Name,prefix,downstream-,acme
    match=Proxy-Authen-Name,exact,downstream-54546,other
    """

    def test_exact_overlapping_prefix_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestSelfLoopTarget:
    """A target whose peer-addr equals this host's own [l2tp] bind
    address is a tunnel-to-itself misconfiguration -- also a fatal
    config-load error (spec section 11)."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=loopback,127.0.0.1,1701,targetsecret
    match=Calling-Number,exact,472913,loopback
    """

    @pytest.fixture()
    def accel_pppd_config(self, l2tp_switch_config):
        # Overrides the module-level fixture to add an explicit
        # [l2tp] bind= -- without one, l2tp_conf_get_bind_addr() returns
        # INADDR_ANY, which validate_no_self_loop() deliberately treats as
        # "skip the check", so this test would otherwise
        # never actually exercise the rejection it's testing for.
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
    bind=127.0.0.1

    """
            + l2tp_switch_config
        )

    def test_self_loop_target_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestMalformedTargetRejected:
    """Every one of these used to be accepted with the fields silently
    shifted or truncated (strtok_r collapses empty fields, ignores extra
    ones, and strtol() was never told to check for trailing junk) -- each
    must instead be a fatal config-load error."""

    @pytest.fixture(
        params=[
            "acme,203.0.113.50,1701,,persistent",  # empty secret
            "acme,203.0.113.50,1701,targetsecret,persistent,extra",  # extra field
            "acme,203.0.113.50,1701abc,targetsecret",  # junk after the port
            "acme,203.0.113.50,,targetsecret",  # empty port
            "ac/me,203.0.113.50,1701,targetsecret",  # name outside [A-Za-z0-9_.-]
            "acme,203.0.113.50,1701,targetsecret,",  # trailing empty mode
        ],
        ids=["empty-secret", "extra-field", "port-junk", "empty-port", "bad-name", "empty-mode"],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    target={request.param}
    """

    def test_switch_target_malformed_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestTargetNameWithDotsDashesAccepted:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=lns-1.example_a,203.0.113.50,1701,targetsecret
    """

    def test_switch_target_name_charset_accepted(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "lns-1.example_a -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestMalformedMatchRejected:
    @pytest.fixture(
        params=[
            "Calling-Number,exact,,acme",  # empty value
            "Calling-Number,exact,472913,acme,extra",  # extra field
            "Calling-Number,exact,472913",  # missing target
        ],
        ids=["empty-value", "extra-field", "missing-target"],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    match={request.param}
    """

    def test_switch_match_malformed_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestTimingOptionsAccepted:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    idle-linger=3
    connect-timeout=7
    reconnect-interval=2
    pap-timeout=4
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_timing_options_accepted(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTimingOptionsInvalidRejected:
    """Not a whole number of seconds in 1..3600 -- a fatal config-load
    error, like a malformed target=, not a silent fall-back to the default."""

    @pytest.fixture(
        params=[
            "idle-linger=0",
            "idle-linger=-5",
            "idle-linger=abc",
            "idle-linger=2.5",
            "idle-linger=3601",
            "idle-linger=",
            "connect-timeout=0",
            "connect-timeout=10s",
            "reconnect-interval=0",
            "pap-timeout=0",
            "pap-timeout=abc",
            "reconnect-interval=x",
        ],
        ids=[
            "linger-zero", "linger-negative", "linger-text", "linger-fraction",
            "linger-too-big", "linger-empty", "connect-zero", "connect-suffix",
            "reconnect-zero", "pap-zero", "pap-text", "reconnect-text",
        ],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    {request.param}
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_timing_invalid_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False
