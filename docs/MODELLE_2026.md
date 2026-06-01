# AEGIS — Bestes KI-Modell/Backend 2026 (Web-Recherche)

Kurzfassung der Frage „gibt es was Besseres als Ollama (frei)?" — recherchiert mit Agent,
gegen Primärquellen geprüft.

## Verdikt: Ollama ist 2026 ein völlig guter, freier Standard
Der Mythos „die Alternativen sind viel schneller" stimmt **nicht**: Ollama, LM Studio,
Jan, KoboldCpp laufen alle auf **derselben llama.cpp-Engine** — bei gleichem Modell/Setting
liegen die Token/s im einstelligen Prozentbereich beieinander. Seit Ollama-PR #16031
(Mai 2026) nutzt Ollama direkt das obere `llama-server`, erbt also Tempo + neue Features.
**Entscheidend ist das MODELL, nicht der Runtime.** Und AEGIS unterstützt jetzt ohnehin
jedes OpenAI-kompatible Backend (Einstellungen → KI-Modell/Backend).

## Runtime
- **Ollama** (Standard, MIT) — am einfachsten, GPU-Autoerkennung, gut zum Bündeln. Tempo-
  Gewinn gratis per Umgebungsvariablen: `OLLAMA_FLASH_ATTENTION=1` und
  `OLLAMA_KV_CACHE_TYPE=q8_0` (halbiert KV-Speicher, ~doppelter Kontext, kaum Qualitätsverlust).
- **LM Studio** (gratis, closed) — beste GUI für Nicht-Techniker (Modell-Browser, wählt Quant).
- **llama.cpp `llama-server`** (MIT) — kleinster Fußabdruck (<90 MB), neueste Quant-Kernels,
  **Speculative Decoding** (~1,5–2,5× bei Code), AMD/Intel via Vulkan. Für Power-User.
- **vLLM** — auf Windows unpraktisch (WSL2/Docker); nur für viele parallele Nutzer sinnvoll. Skip.

## Modell (für ein DEUTSCHES Assistenz-/Security-Tool)
- **Deutsch-Politur:** **Gemma 3** — 12B (~8 GB VRAM) / 27B (~16 GB). Bestes Deutsch der Klasse.
- **Reasoning/Agenten/Code:** **Qwen3** (Apache-2.0) — 8B (~8 GB) / 14B (~16 GB). Bester Allrounder.
- **Schwache GPU:** Gemma 3 4B oder Phi-4-mini.
- **NICHT als Deutsch-Default:** gpt-oss (exzellent Englisch/Code, aber schwach im Deutschen).
- Quant-Default: **Q4_K_M** (bestes Verhältnis), IQ-Quants zum Reinquetschen größerer Modelle.

AEGIS' Auto-Wahl bevorzugt jetzt Gemma 3 (Deutsch) + Qwen3 (Reasoning), nimmt aber das beste
installierte Modell. Frei wählbar in den Einstellungen.

## Schnell-aber-gratis ohne starke GPU (Cloud, OpenAI-kompatibel)
- **Groq** (gratis, ~30 req/min) — **schnellste** Tokens **und** beste Privatsphäre der
  Gratis-Tiers (**trainiert NICHT** auf deinen Daten). Erste Wahl, falls Cloud.
- **Google AI Studio (Gemini)** gratis ist sehr großzügig, **trainiert aber auf deinen Daten**
  → für ein Security-Tool/sensible Inhalte **meiden**.
- Cloud heißt immer: Daten verlassen den PC. Für sensible Sicherheits-Inhalte → lokal bleiben.

**Fazit für dich:** Ollama behalten, ggf. die zwei Umgebungsvariablen setzen; spannender ist,
mal **Gemma 3 12B** für Deutsch gegen dein **qwen3:14b** zu testen. Beides läuft sofort, da
AEGIS jedes Backend/Modell unterstützt.
