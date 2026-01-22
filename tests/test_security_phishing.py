import pytest
from unittest.mock import Mock, patch

from urlp import _security
from urlp.url import URL
from urlp.exceptions import InvalidURLError


@pytest.fixture(autouse=True)
def clear_phishing_cache():
    # Ensure PHISHING_SET is reset before each test
    _security.PHISHING_SET = None
    yield
    _security.PHISHING_SET = None


def test_check_against_phishing_db_detects_known_host(monkeypatch):
    fake_text = "malicious.example.com\nphish.bad\n"
    mock_resp = Mock()
    mock_resp.data = fake_text.encode('utf-8')
    mock_resp.status = 200

    with patch("urlp._security.request.urlopen", return_value=mock_resp) as mocked_get:
        assert _security.check_against_phishing_db("phish.bad") is True
        mocked_get.assert_called_once()


def test_check_against_phishing_db_returns_false_for_safe_host(monkeypatch):
    fake_text = "malicious.example.com\nphish.bad\n"
    mock_resp = Mock()
    mock_resp.data = fake_text.encode('utf-8')
    mock_resp.status = 200

    with patch("urlp._security.request.urlopen", return_value=mock_resp):
        assert _security.check_against_phishing_db("good.example.com") is False


def test_check_against_phishing_db_handles_network_error(monkeypatch):
    # If the remote download fails, the function should return False (empty set)
    with patch("urlp._security.request.urlopen", side_effect=Exception("network")) as mocked_get:
        assert _security.check_against_phishing_db("phish.bad") is False
        mocked_get.assert_called_once()


def test_caching_prevents_multiple_downloads(monkeypatch):
    # Patch the internal downloader to return a proper set
    with patch("urlp._security._download_phishing_db", return_value={"one", "two"}) as mocked_get:
        # First call triggers download
        assert _security.check_against_phishing_db("one") is True
        # Second call should use the cached PHISHING_SET
        assert _security.check_against_phishing_db("two") is True
        mocked_get.assert_called_once()


def test_url_raises_on_phishing_domain(monkeypatch):
    fake_text = "evil.com\n"
    mock_resp = Mock()
    mock_resp.data = fake_text.encode('utf-8')
    mock_resp.status = 200

    with patch("urlp._security.request.urlopen", return_value=mock_resp):
        with pytest.raises(InvalidURLError):
            URL("http://evil.com/", check_phishing=True)


def test_non_string_inputs_return_false():
    assert _security.check_against_phishing_db(None) is False
    assert _security.check_against_phishing_db(123) is False
