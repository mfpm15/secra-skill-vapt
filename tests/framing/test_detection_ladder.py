import pytest
from app.framing import detect, FormatLadder

@pytest.mark.parametrize("response,reason,retry", [
    ("Maaf, saya tidak dapat membantu permintaan tersebut.", "SAFETY_REFUSAL", False),
    ("Sorry, I cannot assist.", "SAFETY_REFUSAL", False),
    ("Secara umum, ada beberapa hal yang perlu dipertimbangkan.", "CONSULTATIVE_RESPONSE", True),
    ("Berikut adalah penjelasan umum langkahnya.", "CONSULTATIVE_RESPONSE", True),
    ("Apakah Anda dapat mengirim contoh?", "CLARIFICATION_ONLY", True),
    ("", "EMPTY_OR_INVALID", True),
])
def test_nonartifact_classification(response, reason, retry):
    result = detect(response)
    assert result.non_artifact is True
    assert result.reason == reason and result.retryable is retry

@pytest.mark.parametrize("response", [
    "- [ ] Periksa sertifikat TLS secara manual",
    "1. Catat port dan layanan yang diamati",
    '{"artifact":{"checks":["verify HTTP status"]}}',
])
def test_artifact_not_retried(response):
    result = detect(response)
    assert not result.non_artifact and not result.retryable

def test_refusal_is_terminal():
    result = detect("- [ ] Something", provider_refusal=True)
    assert result.reason == "SAFETY_REFUSAL"
    ladder = FormatLadder(1)
    assert ladder.next_level() == 1
    assert ladder.next_level(result) is None and ladder.status == "refused"

def test_format_ladder_at_most_two_attempts():
    ladder = FormatLadder(1, max_attempts=2)
    assert ladder.next_level() == 1
    assert ladder.next_level(detect("Secara umum tidak ada daftar.")) == 2
    assert ladder.next_level(detect("Bisakah Anda memberikan konteks?")) is None
    assert ladder.status == "exhausted" and ladder.tried == [1, 2]

def test_ladder_finishes_on_artifact():
    ladder = FormatLadder(2)
    assert ladder.next_level() == 2
    assert ladder.next_level(detect("- [ ] Check certificate")) is None
    assert ladder.status == "completed"

def test_last_level_cannot_repeat():
    ladder = FormatLadder(3)
    assert ladder.next_level() == 3
    assert ladder.next_level(detect("Secara umum ...")) is None
    assert ladder.status == "exhausted" and ladder.tried == [3]
