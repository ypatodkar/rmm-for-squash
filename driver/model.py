"""Model access, kept behind a small interface.

The investigation loop is the interesting part and should not be entangled with
one vendor's request shape. Everything below exposes the same three concepts --
messages, tool definitions, and a reply that either calls tools or doesn't -- so
swapping provider is a configuration change, and tests can substitute a scripted
model with no network at all.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class ModelError(RuntimeError):
    """The provider could not be reached, or refused the request."""


@dataclass(frozen=True)
class ToolCall:
    call_id: str
    name: str
    arguments: dict


@dataclass(frozen=True)
class ModelReply:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class Model:
    """Interface the investigation loop depends on."""

    name = "abstract"

    def respond(self, messages: list[dict], tools: list[dict]) -> ModelReply:
        raise NotImplementedError


class OpenAIModel(Model):
    ENDPOINT = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str, model: str = "gpt-4.1", *,
                 timeout: float = 60.0, temperature: float = 0.0,
                 one_check_at_a_time: bool = True) -> None:
        if not api_key:
            raise ModelError("no API key configured")
        self._key = api_key
        self.name = model
        self._timeout = timeout
        self._temperature = temperature
        # Left to itself the model requests several checks at once, which
        # commits it before it has seen any evidence. Restricting it to one
        # call per turn is what makes each check a decision informed by the
        # last -- and it is the behaviour the latency requirement describes.
        self._one_check_at_a_time = one_check_at_a_time

    def respond(self, messages: list[dict], tools: list[dict]) -> ModelReply:
        payload = {
            "model": self.name,
            "messages": messages,
            "temperature": self._temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
            if self._one_check_at_a_time:
                payload["parallel_tool_calls"] = False

        request = urllib.request.Request(
            self.ENDPOINT,
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {self._key}",
                     "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                body = json.load(response)
        except urllib.error.HTTPError as error:
            raise ModelError(_provider_message(error)) from None
        except urllib.error.URLError as error:
            raise ModelError(f"model provider unreachable: {error.reason}") from None

        choice = (body.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = body.get("usage") or {}

        calls = []
        for raw in message.get("tool_calls") or []:
            function = raw.get("function") or {}
            # Arguments are model-generated text. A malformed object is a model
            # failure, not a crash: record it and let the loop tell the model.
            try:
                arguments = json.loads(function.get("arguments") or "{}")
            except json.JSONDecodeError:
                arguments = {"__invalid_json__": function.get("arguments", "")}
            if not isinstance(arguments, dict):
                arguments = {"__invalid_json__": str(arguments)}
            calls.append(ToolCall(call_id=raw.get("id") or "",
                                  name=function.get("name") or "",
                                  arguments=arguments))

        return ModelReply(
            text=message.get("content") or "",
            tool_calls=calls,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )


class ScriptedModel(Model):
    """A model whose replies are fixed in advance.

    Safety properties must hold regardless of what a model asks for, so the
    tests that prove them use this rather than a real provider: it can be made
    to request forbidden things on demand, and costs nothing to run.
    """

    name = "scripted"

    def __init__(self, replies: list[ModelReply]) -> None:
        self._replies = list(replies)
        self.calls: list[tuple[list[dict], list[dict]]] = []

    def respond(self, messages: list[dict], tools: list[dict]) -> ModelReply:
        self.calls.append((messages, tools))
        if not self._replies:
            return ModelReply(text="(scripted model exhausted)")
        return self._replies.pop(0)


def from_environment() -> Model:
    """Builds the configured model. Credentials are read here and never placed
    into prompts, progress events, or stored state."""
    provider = os.environ.get("SQUASH_MODEL_PROVIDER", "openai").lower()
    if provider == "openai":
        key = os.environ.get("OPEN_AI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ModelError("set OPEN_AI_API_KEY (or OPENAI_API_KEY)")
        return OpenAIModel(
            key, os.environ.get("SQUASH_MODEL", "gpt-4.1"),
            one_check_at_a_time=os.environ.get("SQUASH_PARALLEL_CHECKS", "0") != "1")
    raise ModelError(f"unsupported model provider: {provider!r}")


def load_dotenv(path: str = ".env") -> None:
    """Minimal .env reader so a key never has to be pasted onto a command line,
    where it would land in shell history."""
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, _, value = line.partition("=")
                os.environ.setdefault(name.strip(), value.strip().strip("'\""))
    except FileNotFoundError:
        pass


def _provider_message(error: urllib.error.HTTPError) -> str:
    try:
        detail = json.load(error).get("error", {}).get("message", "")
    except Exception:
        detail = ""
    return f"model provider returned {error.code}: {detail or error.reason}"
