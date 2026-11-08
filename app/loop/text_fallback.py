"""Format-only fallback for 9Router providers that return text instead of tool_calls.

No user-supplied argv or rehydrated target is sent to the model. Only two
strictly reviewed passive tool proposals are representable; the dispatcher
still builds its own argv after separate scope/risk/kernel checks.
Refusals stop immediately. Unsupported or changed argv never executes.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Callable

from app.framing import (CommandSpec, CommandStripError, frame_command,
                         get_profile, strip_command, detect)
from app.tool_registry import TOP20_TCP
from .provider import Choice, ModelError, ModelRefused  # imported lazily by provider


class TextFallbackExhausted(ModelError):
    pass


@dataclass(frozen=True)
class ReviewedFallback:
    action: str
    spec: CommandSpec
    arguments: dict


def _reviewed_choice(candidates, prior, services: list[dict]) -> ReviewedFallback | None:
    allowed = {x.name for x in candidates
               if x.risk in {"R0", "R1", "R2"} and x.adapter != "catalog_only"}
    if prior is None and "nmap.tcp_top20" in allowed:
        argv = ("nmap", "-sT", "-Pn", "-n", "-T2", "-p",
                ",".join(str(x) for x in TOP20_TCP),
                "-oX", "/tmp/secra-reviewed-observation.xml", "<HOST_1>")
        spec = CommandSpec("nmap", argv, "Verify authorized TCP service ports", "R2")
        return ReviewedFallback("nmap.tcp_top20", spec, {})
    if prior and prior[0] == "nmap.tcp_top20" and "curl.http_head" in allowed:
        ports = {x.get("port") for x in services[:30] if
                 isinstance(x, dict) and type(x.get("port")) is int
                 and x.get("service") in {"http", "https"}}
        for port in (443, 80):
            if port in ports:
                scheme = "https" if port == 443 else "http"
                argv = ("curl", "-q", "-I", "--noproxy", "*",
                        scheme + "://<HOST_1>:" + str(port) + "/")
                spec = CommandSpec("curl", argv,
                                   "Review authorized HTTP response headers", "R2")
                return ReviewedFallback("curl.http_head", spec, {"port": port})
    return None


def looks_like_command(text: str) -> bool:
    """Do not treat a legitimate 'finished' message as a request to run tools."""
    return bool(isinstance(text, str) and len(text) <= 4096 and
                re.search(r"(?im)(?:^|\n)\s*(?:berikut perintahnya|here is the command|"
                          r"```bash|(?:nmap|curl)\s)", text))


def select_text_fallback(provider: str, *, content: str, tools: list,
                         prior: tuple[str, str] | None, services: list[dict],
                         send_text_prompt: Callable[[str], str]) -> Choice | None:
    """Use exact manifest-checked argv; no fallback after safety refusal."""
    signal = detect(content)
    if signal.reason == "SAFETY_REFUSAL":
        raise ModelRefused("MODEL_SAFETY_REFUSAL")
    if not looks_like_command(content):
        return None
    selected = _reviewed_choice(tools, prior, services)
    if selected is None:
        return None
    spec = selected.spec
    try:
        stripped = strip_command(content, spec)
        if tuple(stripped) == spec.argv:
            return Choice(selected.action, dict(selected.arguments))
    except CommandStripError as exc:
        if str(exc) == "COMMAND_SAFETY_REFUSAL":
            raise ModelRefused("MODEL_SAFETY_REFUSAL") from exc
    profile = get_profile(provider)
    levels = list(range(profile.level,
                        min(3, profile.level + profile.command_format_retries) + 1))
    for level in levels:
        prompt = frame_command(spec.tool, spec.argv, level, provider,
                               purpose=spec.purpose, risk_class=spec.risk_class)
        text = send_text_prompt(prompt)
        if detect(text).reason == "SAFETY_REFUSAL":
            raise ModelRefused("MODEL_SAFETY_REFUSAL")
        if isinstance(text, str) and text.strip() == "UNRESOLVED_PLACEHOLDER":
            raise ModelError("TEXT_FALLBACK_UNRESOLVED_PLACEHOLDER")
        try:
            accepted = strip_command(text, spec)
        except CommandStripError:
            continue
        if tuple(accepted) == spec.argv:
            return Choice(selected.action, dict(selected.arguments))
    raise TextFallbackExhausted("TEXT_FALLBACK_EXHAUSTED")
