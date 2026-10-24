"""Bring-your-own-model. No SDKs: plain HTTPS so the dependency surface stays small.

Configure with CAIRN_MODEL="<provider>:<model>", for example:

    anthropic:claude-sonnet-5-5          (needs ANTHROPIC_API_KEY)
    openai:gpt-5.5                       (needs OPENAI_API_KEY; OPENAI_BASE_URL for compatible APIs)
    ollama:qwen3-coder                   (local; OLLAMA_HOST defaults to http://localhost:11434)
    mock:path/to/responses.yaml          (tests and offline demos)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml


class ModelError(Exception):
    pass


# USD per million tokens (input, output), from platform.claude.com/docs/en/about-claude/pricing,
# checked 2026-10-24. Used only to show estimated cost; your invoice is the source of truth.
PRICES_PER_MTOK = {
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
}


@dataclass
class Usage:
    """Running token count for one model object, with an estimated cost when the price is known."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    price: tuple[float, float] | None = None

    def add(self, input_tokens: int, output_tokens: int) -> None:
        self.calls += 1
        self.input_tokens += int(input_tokens or 0)
        self.output_tokens += int(output_tokens or 0)

    @property
    def cost_usd(self) -> float | None:
        if self.price is None:
            return None
        return (self.input_tokens * self.price[0] + self.output_tokens * self.price[1]) / 1_000_000

    def describe(self) -> str:
        tokens = (
            f"{self.calls} call(s), {self.input_tokens:,} in / {self.output_tokens:,} out tokens"
        )
        cost = self.cost_usd
        return f"{tokens}, about ${cost:.2f}" if cost is not None else tokens


class Model(Protocol):
    name: str
    usage: Usage

    def complete(self, system: str, prompt: str) -> str: ...


def _post(url: str, headers: dict[str, str], body: dict, timeout: int = 300) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise ModelError(f"{url} returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ModelError(f"could not reach {url}: {exc.reason}") from exc


@dataclass
class Anthropic:
    model: str
    api_key: str
    max_tokens: int = 4096
    usage: Usage = field(default_factory=Usage)

    def __post_init__(self) -> None:
        self.usage.price = PRICES_PER_MTOK.get(self.model)

    @property
    def name(self) -> str:
        return f"anthropic:{self.model}"

    def complete(self, system: str, prompt: str) -> str:
        data = _post(
            os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com") + "/v1/messages",
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        u = data.get("usage") or {}
        self.usage.add(
            (u.get("input_tokens") or 0)
            + (u.get("cache_creation_input_tokens") or 0)
            + (u.get("cache_read_input_tokens") or 0),
            u.get("output_tokens") or 0,
        )
        return "".join(
            b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
        )


@dataclass
class OpenAICompatible:
    model: str
    api_key: str
    base_url: str
    usage: Usage = field(default_factory=Usage)

    @property
    def name(self) -> str:
        return f"openai:{self.model}"

    def complete(self, system: str, prompt: str) -> str:
        data = _post(
            self.base_url.rstrip("/") + "/chat/completions",
            {"authorization": f"Bearer {self.api_key}"},
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        u = data.get("usage") or {}
        self.usage.add(u.get("prompt_tokens") or 0, u.get("completion_tokens") or 0)
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError) as exc:
            raise ModelError(f"unexpected response shape from {self.base_url}") from exc


@dataclass
class Ollama:
    model: str
    host: str
    usage: Usage = field(default_factory=lambda: Usage(price=(0.0, 0.0)))

    @property
    def name(self) -> str:
        return f"ollama:{self.model}"

    def complete(self, system: str, prompt: str) -> str:
        data = _post(
            self.host.rstrip("/") + "/api/chat",
            {},
            {
                "model": self.model,
                "stream": False,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        self.usage.add(data.get("prompt_eval_count") or 0, data.get("eval_count") or 0)
        return (data.get("message") or {}).get("content", "")


@dataclass
class Mock:
    """Replays canned responses in order. Used by tests and the offline demo."""

    path: Path
    _responses: list[str] | None = None
    _i: int = 0
    usage: Usage = field(default_factory=lambda: Usage(price=(0.0, 0.0)))

    @property
    def name(self) -> str:
        return f"mock:{self.path.name}"

    def complete(self, system: str, prompt: str) -> str:
        if self._responses is None:
            try:
                loaded = yaml.safe_load(self.path.read_text("utf-8"))
            except OSError as exc:
                raise ModelError(f"mock responses not readable: {exc}") from exc
            self._responses = [str(r) for r in (loaded or [])]
        if self._i >= len(self._responses):
            raise ModelError(f"mock model ran out of responses after {self._i}")
        out = self._responses[self._i]
        self._i += 1
        self.usage.add(len(prompt) // 4, len(out) // 4)
        return out


SETUP_HELP = (
    "Rule synthesis needs a model. Set CAIRN_MODEL, for example:\n"
    "  export CAIRN_MODEL=anthropic:claude-sonnet-5-5   ANTHROPIC_API_KEY=...\n"
    "  export CAIRN_MODEL=openai:<model>                OPENAI_API_KEY=...  [OPENAI_BASE_URL=...]\n"
    "  export CAIRN_MODEL=ollama:<model>                (runs locally, nothing leaves your machine)"
)


def from_spec(spec: str | None = None) -> Model:
    spec = spec or os.environ.get("CAIRN_MODEL")
    if not spec:
        raise ModelError(SETUP_HELP)
    provider, _, model = spec.partition(":")
    if not model:
        raise ModelError(f"CAIRN_MODEL={spec!r} should look like provider:model\n\n{SETUP_HELP}")
    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ModelError("ANTHROPIC_API_KEY is not set.")
        return Anthropic(model=model, api_key=key)
    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ModelError("OPENAI_API_KEY is not set.")
        return OpenAICompatible(
            model=model,
            api_key=key,
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        )
    if provider == "ollama":
        return Ollama(model=model, host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    if provider == "mock":
        return Mock(path=Path(model))
    raise ModelError(f"unknown model provider {provider!r}\n\n{SETUP_HELP}")
