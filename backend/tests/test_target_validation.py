import pytest

from app.services.target_validation import TargetError, validate_scope_cidr, validate_target

SCOPES = [(1, "172.30.0.0/24", False), (2, "10.10.0.0/16", False)]


@pytest.mark.parametrize("target", ["172.30.0.15", "172.30.0.0/24", "172.30.0.0/25", "10.10.4.0/22", " 172.30.0.11 "])
def test_valid_targets(target):
    net, scope_id = validate_target(target, SCOPES)
    assert scope_id in (1, 2)


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "192.168.1.0/24",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "10.10.0.0/16",
        "172.30.0.0/23",
        "172.30.0.1; rm -rf /",
        "example.com",
        "",
        "2001:db8::1",
        "$(whoami)",
        "172.30.0.1 -oN /tmp/x",
        "172.30.0.1\n10.0.0.1",
    ],
)
def test_invalid_targets(target):
    with pytest.raises(TargetError):
        validate_target(target, SCOPES)


def test_public_needs_explicit_permission():
    with pytest.raises(TargetError):
        validate_target("8.8.8.8", [(3, "8.8.8.0/24", False)])
    net, _ = validate_target("8.8.8.8", [(3, "8.8.8.0/24", True)])
    assert str(net) == "8.8.8.8/32"


def test_scope_cidr_rules():
    with pytest.raises(TargetError):
        validate_scope_cidr("127.0.0.0/8", False)
    with pytest.raises(TargetError):
        validate_scope_cidr("8.8.8.0/24", False)
    assert str(validate_scope_cidr("192.168.0.0/16", False)) == "192.168.0.0/16"
