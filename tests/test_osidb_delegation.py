"""Tests for request-isolated OSIDB delegated authentication."""

import logging
import os
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from aegis_ai.toolsets.tools.osidb import osidb_delegation


def _fake_krb5_library(
    *, resolve_result=0, destroy_result=0, close_result=0, cache_handle=0xCAFE
):
    def resolve(_context, _name, cache):
        cache._obj.value = cache_handle
        return resolve_result

    library = SimpleNamespace(
        krb5_init_context=MagicMock(return_value=0),
        krb5_cc_resolve=MagicMock(side_effect=resolve),
        krb5_cc_destroy=MagicMock(return_value=destroy_result),
        krb5_cc_close=MagicMock(return_value=close_result),
        krb5_free_context=MagicMock(),
    )
    return library


def test_concurrent_token_fetches_do_not_change_process_kerberos_env(monkeypatch):
    credential_barrier = threading.Barrier(2)
    request_barrier = threading.Barrier(2)
    seen_credentials = []

    class FakeCredentials:
        def __init__(self, *, store, usage):
            assert usage == "initiate"
            self.ccache = store["ccache"]
            credential_barrier.wait()

    class FakeAuth:
        def __init__(self, *, creds):
            self.creds = creds

    class FakeClient:
        def __init__(self, *, base_url, auth, timeout):
            assert base_url == "https://osidb.example.com"
            assert timeout == 30.0
            self.auth = auth

    def fetch_token(*, client):
        seen_credentials.append(client.auth.creds.ccache)
        request_barrier.wait()
        return SimpleNamespace(access=f"token:{client.auth.creds.ccache}")

    monkeypatch.setattr(osidb_delegation, "Credentials", FakeCredentials)
    monkeypatch.setattr(osidb_delegation, "HTTPSPNEGOAuth", FakeAuth)
    monkeypatch.setattr(osidb_delegation, "AuthenticatedClient", FakeClient)
    monkeypatch.setattr(
        osidb_delegation.auth_api.auth_token_retrieve, "sync", fetch_token
    )
    monkeypatch.setenv("KRB5CCNAME", "FILE:/process/ccache")
    monkeypatch.setenv("KRB5_KTNAME", "FILE:/process/keytab")
    results = {}

    def run(ccache):
        results[ccache] = osidb_delegation.get_osidb_token_for_delegated_cred(
            ccache, "https://osidb.example.com/"
        )

    threads = [
        threading.Thread(target=run, args=(ccache,))
        for ccache in ("MEMORY:user-a", "MEMORY:user-b")
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert results == {
        "MEMORY:user-a": "token:MEMORY:user-a",
        "MEMORY:user-b": "token:MEMORY:user-b",
    }
    assert set(seen_credentials) == {"MEMORY:user-a", "MEMORY:user-b"}
    assert os.environ["KRB5CCNAME"] == "FILE:/process/ccache"
    assert os.environ["KRB5_KTNAME"] == "FILE:/process/keytab"


def test_destroy_ccache_uses_in_process_kerberos_api(monkeypatch):
    library = _fake_krb5_library()
    monkeypatch.setattr(osidb_delegation.ctypes.util, "find_library", lambda _: "krb5")
    monkeypatch.setattr(osidb_delegation.ctypes, "CDLL", lambda _: library)

    osidb_delegation.destroy_kerberos_ccache("MEMORY:request-cache")

    library.krb5_init_context.assert_called_once()
    assert library.krb5_cc_resolve.call_args.args[1] == b"MEMORY:request-cache"
    library.krb5_cc_destroy.assert_called_once()
    library.krb5_cc_close.assert_not_called()
    library.krb5_free_context.assert_called_once()


def test_destroy_ccache_reports_failure_and_releases_context(monkeypatch, caplog):
    library = _fake_krb5_library(resolve_result=42)
    monkeypatch.setattr(osidb_delegation.ctypes.util, "find_library", lambda _: "krb5")
    monkeypatch.setattr(osidb_delegation.ctypes, "CDLL", lambda _: library)

    with caplog.at_level(logging.WARNING):
        osidb_delegation.destroy_kerberos_ccache("MEMORY:request-cache")

    library.krb5_cc_destroy.assert_not_called()
    library.krb5_cc_close.assert_called_once()
    library.krb5_free_context.assert_called_once()
    assert "Could not destroy delegated ccache MEMORY:request-cache" in caplog.text


def test_destroy_ccache_does_not_close_handle_consumed_by_failed_destroy(
    monkeypatch, caplog
):
    library = _fake_krb5_library(destroy_result=42)
    monkeypatch.setattr(osidb_delegation.ctypes.util, "find_library", lambda _: "krb5")
    monkeypatch.setattr(osidb_delegation.ctypes, "CDLL", lambda _: library)

    with caplog.at_level(logging.WARNING):
        osidb_delegation.destroy_kerberos_ccache("MEMORY:request-cache")

    library.krb5_cc_destroy.assert_called_once()
    library.krb5_cc_close.assert_not_called()
    library.krb5_free_context.assert_called_once()
    assert "Could not destroy delegated ccache MEMORY:request-cache" in caplog.text


def test_destroy_ccache_closes_handle_when_destroy_raises(monkeypatch):
    library = _fake_krb5_library()
    library.krb5_cc_destroy.side_effect = RuntimeError("destroy invocation failed")
    monkeypatch.setattr(osidb_delegation.ctypes.util, "find_library", lambda _: "krb5")
    monkeypatch.setattr(osidb_delegation.ctypes, "CDLL", lambda _: library)

    with pytest.raises(RuntimeError, match="destroy invocation failed"):
        osidb_delegation.destroy_kerberos_ccache("MEMORY:request-cache")

    library.krb5_cc_close.assert_called_once()
    library.krb5_free_context.assert_called_once()


def test_destroy_ccache_releases_context_when_close_reports_failure(
    monkeypatch, caplog
):
    library = _fake_krb5_library(resolve_result=42, close_result=17)
    monkeypatch.setattr(osidb_delegation.ctypes.util, "find_library", lambda _: "krb5")
    monkeypatch.setattr(osidb_delegation.ctypes, "CDLL", lambda _: library)

    with caplog.at_level(logging.WARNING):
        osidb_delegation.destroy_kerberos_ccache("MEMORY:request-cache")

    library.krb5_cc_close.assert_called_once()
    library.krb5_free_context.assert_called_once()
    assert "Could not close delegated ccache handle MEMORY:request-cache" in caplog.text


def test_destroy_ccache_releases_context_when_close_raises(monkeypatch):
    library = _fake_krb5_library(resolve_result=42)
    library.krb5_cc_close.side_effect = RuntimeError("close invocation failed")
    monkeypatch.setattr(osidb_delegation.ctypes.util, "find_library", lambda _: "krb5")
    monkeypatch.setattr(osidb_delegation.ctypes, "CDLL", lambda _: library)

    with pytest.raises(RuntimeError, match="close invocation failed"):
        osidb_delegation.destroy_kerberos_ccache("MEMORY:request-cache")

    library.krb5_cc_close.assert_called_once()
    library.krb5_free_context.assert_called_once()
