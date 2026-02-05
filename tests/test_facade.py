from urlp import parse_url, compose_url, URL


def test_parse_url_returns_URL() -> None:
    u = parse_url("https://user:pw@example.com:8080/path?x=1&x=2#f")
    assert isinstance(u, URL)
    assert u.host == "example.com"
    assert u.query_params == [("x", "1"), ("x", "2")]



def test_compose_url_matches_builder_compose() -> None:
    u = parse_url("https://example.com:8443/a/b?c=1#z")
    components = {
        "scheme": u.scheme,
        "host": u.host,
        "port": u.port,
        "path": u.path,
        "query_pairs": u.query_params,
        "fragment": "z",
    }
    composed = compose_url(components)
    assert "example.com" in composed
    assert "8443" in composed


def test_URL_direct_construction() -> None:
    u = URL("https://example.com/foo")
    assert u.as_string() == "https://example.com/foo"

