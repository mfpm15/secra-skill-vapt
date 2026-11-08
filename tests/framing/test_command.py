"""Command model text is untrusted. Every accepted argv is manifest-identical."""
import json
import shlex
import stat
from pathlib import Path
from uuid import uuid4

import pytest

from app.framing import (CommandSpec, CommandStripError, FormatLadder,
                         frame_command, strip_command, prepare_command, get_profile)
from app.framing.template import FramingError
from app.framing.command import (COMMAND_START, COMMAND_END, COMMAND_CONTRACT,
                                 COMMAND_WRAPPERS)

ARGV = ("nmap", "-sT", "-Pn", "-n", "-p", "80,443", "-oX",
        "/tmp/reports/assessment result.xml", "<HOST_1>")
PURPOSE = "Verify authorized TCP service ports"


def spec(risk="R2", variants=()):
    return CommandSpec("nmap", ARGV, PURPOSE, risk, variants)


def prose_fenced():
    return ("Berikut perintahnya:\n" + chr(96)*3 + "bash\n"
            + "1. " + shlex.join(ARGV) + "\n" + chr(96)*3)


@pytest.mark.parametrize("level", [0, 1, 2, 3])
def test_command_original_tokens_and_path_survive_frame_and_strip(level):
    p = frame_command("nmap", ARGV, level, "glm/mock", purpose=PURPOSE)
    data = p.split(COMMAND_START + "\n", 1)[1].split("\n" + COMMAND_END, 1)[0]
    assert json.loads(data) == list(ARGV)
    assert "<HOST_1>" in p and "/tmp/reports/assessment result.xml" in p
    assert p.endswith(COMMAND_CONTRACT)
    assert strip_command(prose_fenced(), spec()) == list(ARGV)
    assert len(COMMAND_WRAPPERS[level]) <= 8
    assert "never claim an action was run" not in p


def test_level2_neutral_wrapper_terms_absent():
    lexicon = json.loads((Path(__file__).resolve().parents[2] /
                          "app/framing/lexicon.yaml").read_text())
    wrapper = "\n".join(COMMAND_WRAPPERS[2])
    for term in lexicon["dictionaries"]["neutral"]["wrapper_forbidden_terms"]:
        import re
        assert re.search(r"(?i)(?<!\w)" + re.escape(term) + r"(?!\w)", wrapper) is None


def test_stripper_removes_prose_bash_numbering_outer_quotes():
    assert strip_command(prose_fenced(), spec()) == list(ARGV)
    quoted = '"' + shlex.join(ARGV) + '"'
    assert strip_command("Berikut adalah:\n2. " + quoted, spec()) == list(ARGV)


@pytest.mark.parametrize("response", [
    "Berikut perintahnya:\n" + chr(96)*3 + "bash\n" + "nmap -sT <HOST_1>",
    "nmap -sT -Pn -n -p 80,443 -oX /tmp/reports/other.xml <HOST_1>",
    "nmap -sT -Pn -n -p 80,443 -oX /tmp/reports/out.xml 192.0.2.99",
    "nmap -sT -Pn -n -p 80,443 -oX /tmp/reports/out.xml <HOST_999>",
    "nmap -sT -Pn -n -p 80,443 -oX /tmp/reports/out.xml <HOST_1>;rm -rf /",
    "Berikut adalah penjelasan cara menjalankan alat tersebut.",
    "nmap -sT\ncurl -I http://<HOST_1>/",
])
def test_any_tampering_or_multiple_commands_is_denied(response):
    with pytest.raises(CommandStripError):
        strip_command(response, spec())


def test_only_reviewed_variant_may_add_arguments():
    variant = (*ARGV[:-1], "--open", ARGV[-1])
    m = spec(variants=(variant,))
    assert strip_command(shlex.join(variant), m) == list(variant)
    with pytest.raises(CommandStripError):
        strip_command(shlex.join((*ARGV[:-1], "--script", "vuln", ARGV[-1])), m)


@pytest.mark.parametrize("risk", ["R3", "R4"])
def test_high_risk_output_requires_final_approval_class(risk):
    p = frame_command("nmap", ARGV, 2, "glm/mock", purpose=PURPOSE, risk_class=risk)
    assert p.endswith("RISK_CLASS=" + risk + " (approval required before execution)")
    m = spec(risk)
    with pytest.raises(CommandStripError, match="RISK_CLASS_REQUIRED"):
        strip_command(prose_fenced(), m)
    assert strip_command(prose_fenced() + "\nRISK_CLASS=" + risk, m) == list(ARGV)
    with pytest.raises(CommandStripError):
        strip_command(prose_fenced() + "\nRISK_CLASS=R3" if risk == "R4"
                      else prose_fenced() + "\nRISK_CLASS=R4", m)


def test_unknown_shell_or_raw_target_rejected_before_framing():
    with pytest.raises(FramingError):
        frame_command("bash", ("bash", "-c", "whoami"), 2, "glm/mock")
    with pytest.raises(FramingError):
        frame_command("nmap", ("nmap", "-sT", "192.0.2.1"), 2, "glm/mock")
    with pytest.raises(FramingError):
        frame_command("curl", ("curl", "-I", "https://192.0.2.1/"), 2, "glm/mock")
    with pytest.raises(FramingError):
        frame_command("nmap", ("nmap", "-sT", "<HOST_ABC>"), 2, "glm/mock")
    with pytest.raises(FramingError):
        frame_command("nmap", ("nmap", "-sT", "$(evil)"), 2, "glm/mock")


def test_default_provider_levels_and_no_safety_retries():
    assert get_profile("unknownforeign/model").level == 2
    assert get_profile("glm/mock").level == 2
    assert get_profile("openai/model").level == 2
    assert get_profile("local/model").level == 0
    assert get_profile("unknownforeign/model").command_format_retries == 2


def test_prose_after_two_distinct_levels_exhausted_logged_and_no_model_argv(tmp_path):
    replies = []
    def generate(prompt):
        replies.append(prompt)
        return "Secara umum, ada banyak cara."
    result = prepare_command(spec(), "glm/mock", generate, tmp_path)
    assert result.status == "exhausted"
    assert result.argv is None and not result.dispatch_eligible
    assert result.levels == (2, 3)
    assert len(replies) == 2 and len(set(replies)) == 2
    events = [json.loads(row) for row in result.trace_path.read_text().splitlines()]
    assert events[-1]["status"] == "exhausted"
    assert events[-1]["manual_copy_argv"] == list(ARGV)
    assert stat.S_IMODE(result.trace_path.stat().st_mode) == 0o600


def test_format_retry_works_but_refusal_never_retried(tmp_path):
    calls = []
    def generation(prompt):
        calls.append(prompt)
        return "Berikut adalah ulasan secara umum" if len(calls) == 1 else prose_fenced()
    ok = prepare_command(spec(), "glm/mock", generation, tmp_path)
    assert ok.status == "prepared" and ok.argv == list(ARGV)
    assert ok.levels == (2, 3) and len(calls) == 2
    refused_calls = []
    def refusal(prompt):
        refused_calls.append(prompt)
        return "Maaf, saya tidak dapat membantu."
    blocked = prepare_command(spec(), "glm/mock", refusal, tmp_path)
    assert blocked.status == "refused" and blocked.argv is None
    assert len(refused_calls) == 1


def test_local_profile_supports_two_actual_format_retries(tmp_path):
    count = []
    def response(prompt):
        count.append(prompt)
        return prose_fenced() if len(count) == 3 else "Penjelasan umum."
    outcome = prepare_command(spec(), "local/mock", response, tmp_path)
    assert outcome.status == "prepared"
    assert outcome.levels == (0, 1, 2)
    assert len(count) == 3


def test_r3_is_not_dispatch_eligible_even_when_argv_valid(tmp_path):
    outcome = prepare_command(spec("R3"), "glm/mock",
                              lambda _: prose_fenced() + "\nRISK_CLASS=R3", tmp_path)
    assert outcome.status == "approval_required"
    assert outcome.argv == list(ARGV)
    assert not outcome.dispatch_eligible


def test_unresolved_placeholder_no_fallback(tmp_path):
    out = prepare_command(spec(), "glm/mock",
                          lambda _: "UNRESOLVED_PLACEHOLDER", tmp_path)
    assert out.status == "blocked" and out.argv is None
    assert out.reason == "UNRESOLVED_PLACEHOLDER"
