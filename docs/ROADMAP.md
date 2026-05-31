# AEGIS — Roadmap „10 Schritte weiter"

Recherchiert mit 2 Web-Agenten (OSS-Jarvis-Ökosystem + Multi-LLM-Backends), 2026-06-01.
Ziel: besserer/schnellerer Assistent, mehr als nur Ollama, moderne UI, proaktiv —
mit sauberen Open-Source-Bausteinen (Lizenzen geprüft). Reihenfolge = Wirkung/Aufwand.

> **Lizenz-Ampel:** ✅ MIT/Apache/BSD (frei nutzbar, auch closed) · ⚠️ GPL/AGPL
> (copyleft — nur als separater Prozess/Binary, nicht statisch linken).

---

## ✅ Schon erledigt (in dieser Nacht, v2.4.8)

- **Proaktive Begrüßung** — AEGIS meldet sich beim Start selbst (Chat-Bubble + Sprache),
  ohne dass man erst einen Knopf drücken muss. (`bridge.greet()` + `window._on_load_finished`)
- **TTS robust + diagnostizierbar** — eigene Event-Loop statt `asyncio.run` (thread-sicher),
  Logging jeder Sprachausgabe in `shell.log` („TTS: edge-neural … -> OK"). Verifiziert: spricht.
- **Ordner-Selbstplatzierung** — `install.cmd` legt AEGIS selbst nach `%LOCALAPPDATA%\Programs\AEGIS`.
- **GitHub-Seite/Doku glasklar** — Release-Notes, README, INSTALL.txt führen eindeutig zum
  `AEGIS.zip`+`install.cmd`-Weg; .exe-Block ehrlich erklärt.

---

## TIER 1 — größter Effekt, wenig/mittel Aufwand

### 1. Voll-offline Neural-TTS: edge-tts → **Kokoro** ✅
- `kokoro-onnx` (Wrapper MIT, Modell Apache-2.0) — https://github.com/thewh1teagle/kokoro-onnx
- Heute hängt die schöne Stimme an Microsofts **Online**-edge-tts. Ein Security-Tool, das ohne
  Internet verstummt, ist eine echte Lücke. Kokoro (82M, <2 GB, Echtzeit auf CPU) schließt sie
  offline + lizenzsauber. **Empfehlung: Kokoro als Primär-Stimme, edge-tts/SAPI als Fallback.**
- Aufwand: **leicht**.

### 2. LLM-Tokens direkt in Sprache streamen: **RealtimeTTS** ✅ (MIT)
- https://github.com/KoljaB/RealtimeTTS — spricht Satz-für-Satz, während das Modell noch generiert.
- Größter „fühlt-sich-schneller-an"-Gewinn: AEGIS redet ~1 s nach dem Reden los, nicht erst nach
  der kompletten Antwort. Unterstützt Piper/Kokoro/edge-tts unter einer API.
- Aufwand: **leicht**.

### 3. **Multi-Backend** (mehr als Ollama) via OpenAI-kompatible API ✅ (`openai` SDK, Apache-2.0)
- EINE Client-Klasse spricht Ollama (`/v1`), LM Studio, llama.cpp, vLLM, Jan, LocalAI, KoboldCpp,
  GPT4All **und** Cloud (OpenAI/Groq/OpenRouter…) — nur `base_url` + `model` + optional `api_key`.
- Design: kleine `LLMProvider`-Abstraktion mit Adaptern für (a) Ollama nativ, (b) OpenAI-kompatibel,
  (c) Anthropic. Streaming inklusive. Default bleibt Ollama → bestehende Nutzer merken nichts.
  Voller Entwurf + Code-Skizze: siehe `docs/LLM_BACKENDS.md` (unten als Anhang).
- Aufwand: **leicht–mittel**.

### 4. **Function-Calling / Tool-Use** statt nur Regex-Intents
- Ollama Tool-Support: https://ollama.com/blog/tool-support — strukturierte `tool_calls` sind
  zuverlässiger als Regex-Parsing zum Auslösen von AEGIS-Aktionen. Allowlist bleibt die Sicherheits-
  Schicht hinter dem Tool-Schema.
- Aufwand: **mittel**.

---

## TIER 2 — hoher Effekt, mittlerer Aufwand

### 5. Eigenes „AEGIS"-Weckwort: Porcupine → **openWakeWord** ✅ (Apache/MIT)
- https://github.com/dscripka/openWakeWord — kein Picovoice-Key/keine kommerzielle Lizenz nötig,
  bessere Far-Field-Genauigkeit, eigenes „AEGIS"-Wort aus synthetischen TTS-Daten trainierbar.
- Entfernt eine Vendor-Abhängigkeit + Lizenz-Risiko. Aufwand: **mittel**.

### 6. **Reden ohne Knopf halten**: Silero-VAD + Turn-Detection ✅ (MIT/BSD)
- Silero-VAD https://github.com/snakers4/silero-vad (<2 MB) + Smart-Turn
  https://github.com/pipecat-ai/smart-turn — erkennt, ob du WIRKLICH fertig bist vs. nur kurz
  Pause machst. Kern des „dritte Person im Raum"-Gefühls (kontinuierliche Konversation).
- Aufwand: **mittel**.

### 7. **Barge-in / Unterbrechen** (Pipecat-Muster) ✅ (BSD-2)
- https://github.com/pipecat-ai/pipecat — wenn der Nutzer anfängt zu reden, laufendes TTS+LLM
  sofort abbrechen. Macht aus Demo „täglich nutzbar". Aufwand: **mittel** (Muster) / hart (Framework).

### 8. **Langzeitgedächtnis**: mem0 ✅ (Apache-2.0)
- https://github.com/mem0ai/mem0 — extrahiert Fakten automatisch, ~90 % weniger Token/Latenz als
  History-Stuffing. Ergänzt euren `knowledge_seed/*.md`-Workflow (Seeds = Bootstrap, mem0 = pro-Nutzer).
- Aufwand: **mittel**.

---

## TIER 3 — gezielte Tempo/Qualität, wenig Aufwand

### 9. Schnelleres STT: faster-whisper-Modell → **distil-large-v3.5** ✅ (MIT)
- Drop-in-Modelltausch, ~6× schneller bei ~1 % WER-Verlust, mehrsprachig (inkl. Deutsch).
  Reiner Config-Wechsel. Aufwand: **leicht**.

### 10. **RealtimeSTT** konsolidiert VAD+Weckwort+STT ✅ (MIT)
- https://github.com/KoljaB/RealtimeSTT — pairt symmetrisch mit RealtimeTTS (#2, selber Autor).
  Aufwand: **leicht–mittel**.

### 11. **MCP** (Model Context Protocol) für AEGIS-Tools ✅ (MIT)
- https://github.com/modelcontextprotocol/python-sdk — Embedding-Router lädt nur relevante Tools
  pro Anfrage (kein Context-Rot). Andockbar an das ganze MCP-Tool-Ökosystem. Aufwand: **mittel–hart**.

---

## Referenz-Projekt
**isair/jarvis** (https://github.com/isair/jarvis) ist AEGIS' direktes Pendant und validiert genau
diesen Stack: Ollama + Kokoro/Piper + Weckwort-überall + MCP-mit-Embedding-Router + Graph-Gedächtnis.
⚠️ **Open Interpreter (AGPL)** und **piper1-gpl (GPL)** nur als separaten Prozess isolieren, nicht linken.

## Neue UI (Vorschlag)
Die Qt6/Three.js-Cognition-Core-UI bleibt der Kern; darunter den Audio-/Konversations-Loop
(VAD→STT→LLM→TTS, Streaming, Unterbrechung) modernisieren (#2/#6/#7). Optional langfristig den
Voice-Loop auf **Pipecat** (BSD) heben und Qt nur als Front-End behalten.

## Empfohlene Reihenfolge (mein Vorschlag)
1) **#3 Multi-Backend** (entkoppelt LLM, schnell, sichtbar) → 2) **#2 Streaming-TTS** +
**#1 Kokoro offline** (fühlt sich schnell an, offline-robust) → 3) **#6 VAD/Turn-Taking** +
**#5 openWakeWord** (Reden ohne Knopf, lizenzsauber) → 4) **#4 Tool-Use** + **#8 mem0** (schlauer)
→ 5) **#9 schnelleres STT** (Feinschliff).

> ⚠️ **Wichtig — Datenschutz für ein Security-Tool:** edge-tts (online) und Cloud-LLMs senden Text
> an Dritte. Für AEGIS sind die **offline**-Optionen (Kokoro, lokale Modelle) die saubere Default-
> Empfehlung; Online nur opt-in + klar gekennzeichnet.
