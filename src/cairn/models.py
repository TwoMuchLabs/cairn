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
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml


class ModelError(Exception):
    pass


class Model(Protocol):
    name: str

    def complete(self, system: str, prompt: str) -> str: ...


def _post(url: str, headers: dict[str, str], body: dict, timeout: int = 300) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers={"content-type": "application/json", **headers}
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
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


@dataclass
class OpenAICompatible:
    model: str
    api_key: str
    base_url: str

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
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError) as exc:
            raise ModelError(f"unexpected response shape from {self.base_url}") from exc


@dataclass
class Ollama:
    model: str
    host: str

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
        return (data.get("message") or {}).get("content", "")


@dataclass
class Mock:
    """Replays canned responses in order. Used by tests and the offline demo."""

    path: Path
    _responses: list[str] | None = None
    _i: int = 0

    @property
    def name(self) -> str:
        return f"mock:{self.path.name}"

    def complete(self, system: str, prompt: str) -> str:
        if self._responses is None:
            loaded = yaml.safe_load(self.path.read_text("utf-8"))
            self._responses = [str(r) for r in (loaded or [])]
        if self._i >= len(self._responses):
            raise ModelError(f"mock model ran out of responses after {self._i}")
        out = self._responses[self._i]
        self._i += 1
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
            model=model, api_key=key, base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        )
    if provider == "ollama":
        return Ollama(model=model, host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    if provider == "mock":
        return Mock(path=Path(model))
    raise ModelError(f"unknown model provider {provider!r}\n\n{SETUP_HELP}")
