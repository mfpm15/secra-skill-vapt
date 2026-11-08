import pytest

from app.masking import MemoryVault, StreamingRedactor, redact
from app.masking.redact import UnsupportedInputError

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


def test_jwt_split_at_every_character_boundary():
    source = "Authorization: Bearer " + JWT + "\n"
    expected = "Authorization: Bearer <TOKEN_1>\n"
    for boundary in range(1, len(source)):
        v = MemoryVault()
        stream = StreamingRedactor(vault=v)
        assert stream.feed(source[:boundary]) == ""
        assert stream.feed(source[boundary:]) == ""
        masked, delta = stream.finish()
        assert masked == expected
        assert delta["count"] == 1
        assert v.get("<TOKEN_1>") == JWT


def test_jwt_single_character_chunk_stream_equivalent_to_batch():
    source = "token=" + JWT + " sent by ops@example.com"
    s = StreamingRedactor(vault=MemoryVault())
    for char in source:
        assert s.feed(char) == ""
    masked, _ = s.finish()
    expected, _ = redact(source)
    assert masked == expected
    assert JWT not in masked
    assert "ops@example.com" not in masked


def test_split_bearer_across_lines_not_leaked():
    source = "Authorization: Bea\nrer abcDEFghijkLmnopQ12\n"
    s = StreamingRedactor()
    for part in ("Authorization: Bea\n", "rer abcDEFghijkL", "mnopQ12\n"):
        assert s.feed(part) == ""
    assert s.finish()[0] == "Authorization: Bea\nrer <TOKEN_1>\n"


def test_stream_oversize_quarantines_without_output():
    s = StreamingRedactor()
    with pytest.raises(UnsupportedInputError):
        s.feed("A" * 2_000_001)
    with pytest.raises(UnsupportedInputError):
        s.finish()


def test_stream_cannot_finalize_twice():
    s = StreamingRedactor()
    s.feed("10.1.2.3")
    assert s.finish()[0] == "<IP_1>"
    with pytest.raises(UnsupportedInputError):
        s.finish()
