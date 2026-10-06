import pytest

from wifileverage.scope import Scope, ScopeError


def test_empty_scope_is_permissive():
    s = Scope.empty()
    assert s.ssid_in_scope("anything")
    assert s.address_in_scope("10.1.2.3")
    assert not s.restricts_targets


def test_from_dict_parses_fields():
    s = Scope.from_dict(
        {
            "engagement": "test",
            "client": "acme",
            "ssids": ["Guest"],
            "target_cidrs": ["10.0.0.0/8"],
            "exclude_cidrs": ["10.9.0.0/16"],
        }
    )
    assert s.engagement == "test"
    assert s.restricts_targets
    assert s.ssid_in_scope("Guest")
    assert not s.ssid_in_scope("Corp")


def test_exclusion_beats_inclusion():
    s = Scope.from_dict({"target_cidrs": ["10.0.0.0/8"], "exclude_cidrs": ["10.9.0.0/16"]})
    assert s.address_in_scope("10.1.1.1")
    assert not s.address_in_scope("10.9.1.1")


def test_include_rules_require_membership():
    s = Scope.from_dict({"target_cidrs": ["192.168.0.0/16"]})
    assert s.address_in_scope("192.168.1.1")
    assert not s.address_in_scope("10.1.1.1")


def test_network_in_scope_overlap():
    s = Scope.from_dict({"target_cidrs": ["10.0.0.0/8"], "exclude_cidrs": ["10.9.0.0/16"]})
    assert s.network_in_scope("10.20.0.0/16")
    assert not s.network_in_scope("10.9.0.0/24")
    assert not s.network_in_scope("172.16.0.0/16")


def test_merge_inline():
    s = Scope.empty().merge_inline(include=["10.0.0.0/8"], exclude=["10.9.0.0/16"], ssids=["X"])
    assert s.restricts_targets
    assert s.address_in_scope("10.1.1.1")
    assert not s.address_in_scope("10.9.1.1")
    assert s.ssid_in_scope("X")


def test_bad_cidr_raises():
    with pytest.raises(Exception):
        Scope.from_dict({"target_cidrs": ["not-a-cidr"]})


def test_from_dict_rejects_non_mapping():
    with pytest.raises(ScopeError):
        Scope.from_dict(["nope"])
