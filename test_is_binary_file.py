"""Unit tests for Egyscan's backup-file helpers (no network access)."""

import io

from egyscan import is_binary_file


def test_is_binary_file_detects_binary_stream():
    assert is_binary_file(io.BytesIO(b"\x00\x01\x02binary")) is True


def test_is_binary_file_rejects_text_stream():
    assert is_binary_file(io.StringIO("plain text")) is False


def test_is_binary_file_handles_unsupported_operation():
    class Unreadable:
        def read(self, n=-1):
            raise io.UnsupportedOperation("unsupported")

    assert is_binary_file(Unreadable()) is True


def test_is_binary_file_accepts_raw_bytes():
    assert is_binary_file(b"\x00\x01\x02binary") is True
