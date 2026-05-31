# AEGIS — Multi-LLM-Backend (mehr als Ollama)

Bauplan, um AEGIS hinter EINE kleine `LLMProvider`-Abstraktion zu setzen, die Ollama,
jeden OpenAI-kompatiblen Server UND Claude bedient. Standard: OpenAI-kompatible
`/v1/chat/completions`-API — die sprechen ~alle lokalen Server.

## Server, die out-of-the-box passen (nur base_url/model/api_key ändern)
| Server | base_url | api_key |
|---|---|---|
| Ollama (`/v1`) | `http://localhost:11434/v1` | beliebig (ignoriert) |
| LM Studio | `http://localhost:1234/v1` | beliebig |
| llama.cpp `llama-server` | `http://localhost:8080/v1` | optional |
| vLLM | `http://localhost:8000/v1` | optional |
| text-generation-webui | `http://localhost:5000/v1` | optional |
| Jan | `http://localhost:1337/v1` | optional |
| LocalAI | `http://localhost:8080/v1` | optional |
| KoboldCpp | `http://localhost:5001/v1` | optional |
| GPT4All | `http://localhost:4891/v1` | – |
| Cloud (OpenAI/Groq/OpenRouter/…) | Provider-URL `…/v1` | **nötig** |

Viele bieten `GET /v1/models` → Modell-Dropdown automatisch füllen.

## Bibliotheken
- **`openai`** (Apache-2.0) — deckt alle OpenAI-kompatiblen Server + Cloud ab, inkl. Streaming.
- **`anthropic`** (MIT) — Claude (anders: `max_tokens` Pflicht, `system=` top-level, eigener Stream).
- Ollama nativ: bestehender HTTP-Code, **keine neue Abhängigkeit**.
- Optional **`keyring`** (MIT) für verschlüsselte Cloud-API-Keys statt Klartext.

## Interface (`aegis2/cognition/llm/base.py`)
```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator, Literal, Optional

Role = Literal["system", "user", "assistant"]

@dataclass
class Message: role: Role; content: str

@dataclass
class LLMConfig:
    provider: str           # "ollama" | "openai_compatible" | "anthropic"
    model: str
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout_s: int = 120

class LLMProvider(ABC):
    def __init__(self, cfg: LLMConfig): self.cfg = cfg
    @abstractmethod
    def complete(self, messages: list[Message], *, stream: bool = False) -> Iterator[str]: ...
    def list_models(self) -> list[str]: return []
```

## Adapter: OpenAI-kompatibel (deckt ~9 Server + Cloud)
```python
from openai import OpenAI
from .base import LLMProvider

class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, cfg):
        super().__init__(cfg)
        base = (cfg.base_url or "http://localhost:11434").rstrip("/")
        if not base.endswith("/v1"): base += "/v1"
        self._c = OpenAI(base_url=base, api_key=cfg.api_key or "not-needed", timeout=cfg.timeout_s)
    def complete(self, messages, *, stream=False):
        kw = dict(model=self.cfg.model,
                  messages=[{"role": m.role, "content": m.content} for m in messages],
                  temperature=self.cfg.temperature, max_tokens=self.cfg.max_tokens)
        if stream:
            for ch in self._c.chat.completions.create(**kw, stream=True):
                if ch.choices and ch.choices[0].delta.content:
                    yield ch.choices[0].delta.content
        else:
            yield self._c.chat.completions.create(**kw).choices[0].message.content
    def list_models(self):
        return [m.id for m in self._c.models.list().data]
```

## Adapter: Anthropic (Unterschiede beachten!)
```python
from anthropic import Anthropic
from .base import LLMProvider

class AnthropicProvider(LLMProvider):
    def __init__(self, cfg):
        super().__init__(cfg); self._c = Anthropic(api_key=cfg.api_key, timeout=cfg.timeout_s)
    def complete(self, messages, *, stream=False):
        system = "\n".join(m.content for m in messages if m.role == "system") or None
        turns = [{"role": m.role, "content": m.content} for m in messages if m.role != "system"]
        kw = dict(model=self.cfg.model, max_tokens=self.cfg.max_tokens, system=system, messages=turns)
        if stream:
            with self._c.messages.stream(**kw) as s:
                for t in s.text_stream: yield t
        else:
            msg = self._c.messages.create(**kw)
            yield "".join(b.text for b in msg.content if b.type == "text")
```

## Factory + Config-Felder
```python
def make_provider(cfg):
    return {"ollama": OllamaProvider, "openai_compatible": OpenAICompatibleProvider,
            "anthropic": AnthropicProvider}[cfg.provider](cfg)
```
Settings: `provider`, `base_url`, `model`, `api_key` (Secret), `temperature`, `max_tokens`, `stream`.
Default `provider=ollama`/`http://localhost:11434` → bestehende Nutzer merken nichts. Presets
(LM Studio :1234, Jan :1337 …) vorbefüllen. „Test"-Knopf ruft `/v1/models`.

## Fallstricke
- `api_key` darf nicht leer sein (SDK), bei lokalen Servern Platzhalter `"not-needed"` injizieren.
- base_url `/v1` anhängen, falls Nutzer ohne `/v1` einträgt.
- Anthropic ist NICHT OpenAI-shaped (s. o.) — eigener Adapter, nicht durch den OpenAI-Pfad zwingen.
- Stream-Chunks: `delta.content` kann `None`/`choices` leer sein → vor dem Yield prüfen.
- Großzügiges Timeout (≥120 s) + Streaming, lokale Modelle brauchen bis zum ersten Token.

## Empfohlene lokale Modelle (Anfang 2026)
**Qwen3** (Apache-2.0): 8B (Q4_K_M) ~8 GB VRAM, 14B ~16 GB. Default-Empfehlung: **Qwen3-8B**.
Alternativen: Llama-3.x 8B, Phi-4-mini (3.8B, sehr knapper Speicher), Gemma 3 12B.
