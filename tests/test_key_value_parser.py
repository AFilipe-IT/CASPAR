"""
tests/test_key_value_parser.py
-------------------------------
Tests for the generic key-value parser (Peça 2a).
"""

from __future__ import annotations

from core.parsers.key_value import parse_file


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def _by_name(directives):
    return {d.name: d for d in directives}


class TestKeyValueParser:
    def test_equals_form(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", "listen_addresses = localhost\nport = 5432\n")
        d = _by_name(parse_file(str(cfg)))
        assert d["listen_addresses"].value == "localhost"
        assert d["port"].value == "5432"

    def test_space_form(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", "ssl on\nmax_connections 100\n")
        d = _by_name(parse_file(str(cfg)))
        assert d["ssl"].value == "on"
        assert d["max_connections"].value == "100"

    def test_keys_lowercased(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", "Listen_Addresses = '*'\nSSL = on\n")
        d = _by_name(parse_file(str(cfg)))
        assert "listen_addresses" in d and "ssl" in d

    def test_quoted_value_with_spaces(self, tmp_path):
        # Interior spaces are preserved; Directive.__post_init__ trims the ends,
        # so a trailing space is dropped — assert the interior space survives.
        cfg = _write(tmp_path, "c.conf", 'log_line_prefix = "%m [%p]"\n')
        d = _by_name(parse_file(str(cfg)))
        assert d["log_line_prefix"].value == "%m [%p]"

    def test_single_quotes_stripped(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", "listen_addresses = '127.0.0.1'\n")
        d = _by_name(parse_file(str(cfg)))
        assert d["listen_addresses"].value == "127.0.0.1"

    def test_full_line_comment_ignored(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", "# a comment\nport = 5432\n")
        d = parse_file(str(cfg))
        assert len(d) == 1 and d[0].name == "port"

    def test_inline_comment_stripped(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", "port = 5432   # default port\n")
        d = _by_name(parse_file(str(cfg)))
        assert d["port"].value == "5432"

    def test_hash_inside_quotes_kept(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", 'password = "a#b#c"\n')
        d = _by_name(parse_file(str(cfg)))
        assert d["password"].value == "a#b#c"

    def test_include_followed(self, tmp_path):
        (tmp_path / "conf.d").mkdir()
        _write(tmp_path / "conf.d", "extra.conf", "ssl = on\n")
        cfg = _write(tmp_path, "c.conf", "include conf.d/*.conf\nport = 5432\n")
        d = _by_name(parse_file(str(cfg)))
        assert "ssl" in d and "port" in d

    def test_include_dir_keyword(self, tmp_path):
        (tmp_path / "conf.d").mkdir()
        _write(tmp_path / "conf.d", "a.conf", "ssl = on\n")
        cfg = _write(tmp_path, "c.conf", "include_dir conf.d/*.conf\n")
        d = _by_name(parse_file(str(cfg)))
        assert "ssl" in d

    def test_include_cycle_guarded(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", "include c.conf\nport = 5432\n")
        d = parse_file(str(cfg))  # must not recurse forever
        assert any(x.name == "port" for x in d)

    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_file(str(tmp_path / "nope.conf")) == []

    def test_line_numbers_and_source(self, tmp_path):
        cfg = _write(tmp_path, "c.conf", "# header\nport = 5432\n")
        d = parse_file(str(cfg))
        assert d[0].line_number == 2
        assert d[0].source_file.endswith("c.conf")
