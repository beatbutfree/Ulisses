"""Tests for wazuh.client — WazuhIndexerClient (OpenSearch mocked)."""

from unittest.mock import MagicMock, patch

import pytest

from wazuh.client import DEFAULT_INDEX, WazuhIndexerClient
from wazuh.parser import ParsedResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_os_response(sources: list[dict], total: int = None, took: int = 2) -> dict:
    hits = [{"_index": "wazuh-archives-4.x-2024", "_source": s} for s in sources]
    return {
        "took": took,
        "hits": {
            "total": {"value": total if total is not None else len(sources), "relation": "eq"},
            "hits": hits,
        },
    }


def _make_client(mock_os: MagicMock) -> WazuhIndexerClient:
    """Return a WazuhIndexerClient whose inner OpenSearch is replaced by a mock."""
    client = WazuhIndexerClient.__new__(WazuhIndexerClient)
    client._client = mock_os
    return client


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_default_index(self):
        assert DEFAULT_INDEX == "wazuh-archives-*"


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestInit:
    @patch("wazuh.client.OpenSearch")
    def test_https_url_parsed(self, mock_os_cls):
        WazuhIndexerClient("https://10.0.0.1:9200", "admin", "secret")
        call_kwargs = mock_os_cls.call_args
        hosts = call_kwargs[1]["hosts"]
        assert hosts[0]["host"] == "10.0.0.1"
        assert hosts[0]["port"] == 9200
        assert call_kwargs[1]["use_ssl"] is True

    @patch("wazuh.client.OpenSearch")
    def test_http_url_use_ssl_false(self, mock_os_cls):
        WazuhIndexerClient("http://10.0.0.1:9200", "admin", "secret")
        call_kwargs = mock_os_cls.call_args
        assert call_kwargs[1]["use_ssl"] is False

    @patch("wazuh.client.OpenSearch")
    def test_credentials_passed_as_http_auth(self, mock_os_cls):
        WazuhIndexerClient("https://10.0.0.1:9200", "wazuh", "pass123")
        call_kwargs = mock_os_cls.call_args
        assert call_kwargs[1]["http_auth"] == ("wazuh", "pass123")

    @patch("wazuh.client.OpenSearch")
    def test_verify_ssl_false_by_default(self, mock_os_cls):
        WazuhIndexerClient("https://10.0.0.1:9200", "u", "p")
        call_kwargs = mock_os_cls.call_args
        assert call_kwargs[1]["verify_certs"] is False

    @patch("wazuh.client.OpenSearch")
    def test_verify_ssl_true_passed_through(self, mock_os_cls):
        WazuhIndexerClient("https://10.0.0.1:9200", "u", "p", verify_ssl=True)
        call_kwargs = mock_os_cls.call_args
        assert call_kwargs[1]["verify_certs"] is True


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------


class TestFromEnv:
    @patch("wazuh.client.OpenSearch")
    @patch("wazuh.client.load_dotenv")
    def test_reads_env_vars(self, mock_load_dotenv, mock_os_cls, monkeypatch):
        monkeypatch.setenv("WAZUH_INDEXER_URL", "https://10.0.0.1:9200")
        monkeypatch.setenv("WAZUH_API_USER", "wazuh")
        monkeypatch.setenv("WAZUH_API_PASSWORD", "secret")

        client = WazuhIndexerClient.from_env()

        assert isinstance(client, WazuhIndexerClient)
        mock_load_dotenv.assert_called_once()

    @patch("wazuh.client.load_dotenv")
    def test_missing_env_var_raises(self, mock_load_dotenv, monkeypatch):
        monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
        monkeypatch.delenv("WAZUH_API_USER", raising=False)
        monkeypatch.delenv("WAZUH_API_PASSWORD", raising=False)

        with pytest.raises(KeyError):
            WazuhIndexerClient.from_env()


# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------


class TestPing:
    def test_ping_true_when_reachable(self):
        mock_os = MagicMock()
        mock_os.ping.return_value = True
        client = _make_client(mock_os)
        assert client.ping() is True

    def test_ping_false_when_unreachable(self):
        from opensearchpy.exceptions import ConnectionError as OSConnectionError

        mock_os = MagicMock()
        mock_os.ping.side_effect = OSConnectionError("unreachable", None, None)
        client = _make_client(mock_os)
        assert client.ping() is False

    def test_ping_false_on_transport_error(self):
        from opensearchpy.exceptions import TransportError

        mock_os = MagicMock()
        mock_os.ping.side_effect = TransportError(503, "unavailable")
        client = _make_client(mock_os)
        assert client.ping() is False


# ---------------------------------------------------------------------------
# execute_query
# ---------------------------------------------------------------------------


class TestExecuteQuery:
    def test_delegates_to_opensearch_search(self):
        mock_os = MagicMock()
        raw = _make_os_response([{"rule": {"id": "1"}}])
        mock_os.search.return_value = raw
        client = _make_client(mock_os)

        dsl = {"query": {"match_all": {}}}
        result = client.execute_query(dsl)

        mock_os.search.assert_called_once_with(
            body=dsl, index=DEFAULT_INDEX, size=100
        )
        assert result is raw

    def test_custom_index_passed_through(self):
        mock_os = MagicMock()
        mock_os.search.return_value = _make_os_response([])
        client = _make_client(mock_os)

        client.execute_query({"query": {}}, index="wazuh-alerts-*")
        assert mock_os.search.call_args[1]["index"] == "wazuh-alerts-*"

    def test_custom_size_passed_through(self):
        mock_os = MagicMock()
        mock_os.search.return_value = _make_os_response([])
        client = _make_client(mock_os)

        client.execute_query({"query": {}}, size=500)
        assert mock_os.search.call_args[1]["size"] == 500


# ---------------------------------------------------------------------------
# query (convenience method)
# ---------------------------------------------------------------------------


class TestQuery:
    def test_returns_parsed_response(self):
        mock_os = MagicMock()
        mock_os.search.return_value = _make_os_response(
            [{"rule": {"id": "5402", "level": 3}, "full_log": "raw line"}]
        )
        client = _make_client(mock_os)

        result = client.query({"query": {"match_all": {}}})

        assert isinstance(result, ParsedResponse)
        assert len(result.hits) == 1
        assert "full_log" not in result.hits[0]

    def test_keep_full_log_propagated(self):
        mock_os = MagicMock()
        mock_os.search.return_value = _make_os_response(
            [{"rule": {"id": "1"}, "full_log": "raw line"}]
        )
        client = _make_client(mock_os)

        result = client.query({"query": {}}, keep_full_log=True)
        assert result.hits[0]["full_log"] == "raw line"

    def test_empty_result(self):
        mock_os = MagicMock()
        mock_os.search.return_value = _make_os_response([])
        client = _make_client(mock_os)

        result = client.query({"query": {}})
        assert result.is_empty() is True
