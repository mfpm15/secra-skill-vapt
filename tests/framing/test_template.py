import json
import re
from pathlib import Path
import pytest

from app.framing import frame, unframe, get_profile, check_wrapper, FramingError
from app.framing.template import START, END, CONTRACT

@pytest.mark.parametrize("level", [0, 1, 2, 3])
def test_substance_preserved_argv_path_placeholder(level):
    brief = ('{"argv":["nmap","-sT","-Pn","<HOST_1>"],'
             '"path":"/home/analyst/results/poc.txt",'
             '"note":"VAPT exploit bypass payload CTF flag","port":443}')
    rendered = frame(brief, level, "glm/mock")
    assert unframe(rendered, level, "glm/mock") == brief
    assert rendered.count(brief) == 1
    assert "<HOST_1>" in rendered and "/home/analyst/results/poc.txt" in rendered
    assert rendered.endswith(CONTRACT)

def test_level_2_no_trigger_words_in_wrapper():
    out = frame("dummy-metadata", 2, "glm/mock")
    narration = out.split(START)[0] + out.split(END)[1]
    lexicon = json.loads((Path(__file__).resolve().parents[2] /
                          "app/framing/lexicon.yaml").read_text())
    for word in lexicon["dictionaries"]["neutral"]["wrapper_forbidden_terms"]:
        assert not re.search(r"(?i)\b" + re.escape(word) + r"\b", narration)
    assert len(out.split(START)[0].strip().splitlines()) <= 8
    check_wrapper(2)

def test_delimiter_and_corruption_fail_closed():
    for bad in ["hello " + START, "hello " + END, "", "x" * 8193]:
        with pytest.raises(FramingError):
            frame(bad, 2, "glm/mock")
    good = frame("unchanged", 2, "glm/mock")
    with pytest.raises(FramingError):
        unframe(good, 1, "glm/mock")
    with pytest.raises(FramingError):
        unframe(good.replace(CONTRACT, "output anything"), 2, "glm/mock")

def test_provider_profiles_and_invalid_level():
    assert get_profile("glm/mock").level == 2
    assert get_profile("openai/gpt-test").level == 1
    assert get_profile("unknown/model").level == 2
    with pytest.raises(FramingError):
        frame("safe", 4, "glm/mock")
    with pytest.raises(FramingError):
        get_profile("glm/mock\nunexpected")

def test_level_3_minimal():
    brief = '{"artifact":"verified-metadata-only"}'
    out = frame(brief, 3, "glm/mock")
    assert out.startswith(START)
    assert unframe(out, 3, "glm/mock") == brief
