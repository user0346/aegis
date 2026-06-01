# AEGIS — Assistent auf Jarvis-Niveau (Web-Recherche, Umsetzungs-Fahrplan)

Recherchiert mit Agent (early-2026), Quellen am Ende. Ziel: das Gespräch „deutlich besser"
machen — sortiert nach **Wirkung / Risiko**. Stack: Python, Ollama/OpenAI-kompatibel,
edge-tts/SAPI, faster-whisper.

## ✅ Sofort umgesetzt
- **Sprach-getunter System-Prompt** (`llm.py SYSTEM`): kurze gesprochene Sätze, KEINE
  Listen/Markdown/Emojis, Standard 1–3 Sätze (Tiefe nur auf Nachfrage), Zahlen/Daten/
  Abkürzungen ausgesprochen, eine Rückfrage statt Geschwafel, keine „Als KI"-Floskeln.
  Sicherheits-Regel („du plauderst nur, behauptest nie eine Aktion") bleibt. *Risiko: ~0.*

## Als Nächstes (getestet, einzeln deploybar)

### 1. Streaming + Satz-für-Satz-Sprechen — DER Hauptgewinn
LLM-Tokens streamen (`stream=True`), pro **vollständigem Satz** sofort sprechen, während der
Rest noch generiert. Senkt die gefühlte Wartezeit von „ganze Antwort abwarten" auf
~erster-Satz-Zeit. Lib: `stream2sentence` (robuste DE-Satzgrenzen: „z. B.", „Dr.", „1. Mai")
— nur für die Segmentierung, Wiedergabe bleibt edge-tts/SAPI. Non-Streaming als Fallback
behalten. *Mittel / niedrig-mittel Risiko / sehr hohe Wirkung.*

### 2. Sofort-Füllwort (Latenz verstecken)
Direkt nach der Eingabe ein kurzes „Moment.", „Schau ich nach.", „Klar." sprechen, BEVOR das
erste LLM-Token kommt (rotierend, nicht repetitiv). Lässt 1000 ms wie 500 ms wirken. *Leicht /
sehr niedriges Risiko / hohe Wirkung.*

### 3. Leichtes Gedächtnis (Mini-mem0, ohne Vektor-DB)
Rolling Summary (alte Turns zu einem wachsenden deutschen Absatz zusammenfassen) + kleine
`user_facts.json` (LLM extrahiert dauerhafte Fakten **asynchron**, blockt die Antwort nie),
beides in den System-Prompt injiziert („Was du über den Nutzer weißt: …"). *Mittel / niedrig.*

### 4. Barge-in (Unterbrechen beim Sprechen)
Während TTS läuft, mit VAD (Silero) + faster-whisper mithören; erkannte Sprache → `stop_event`
→ TTS-Stream killen → Mikro wieder auf. Setzt #1 voraus. *Mittel / mittel.*

### 5. Tool-Calling statt Regex (zuletzt, riskant)
Phase 1 (non-streaming) erkennt `tool_calls`, lokal ausführen (Allowlist + Arg-Validierung
BLEIBEN), Phase 2 streamt die gesprochene Antwort. Bei kleinen lokalen Modellen unzuverlässiger
→ als Fallback NEBEN dem Regex-Router, gut testen. *Mittel-hart / höchstes Risiko.*

## Reihenfolge
Prompt (✅) → Füllwort → Streaming → Gedächtnis → Barge-in → Tool-Calling.

## Quellen
RealtimeTTS https://github.com/KoljaB/RealtimeTTS · stream2sentence https://github.com/KoljaB/stream2sentence ·
AssemblyAI Voice-Pipeline https://www.assemblyai.com/blog/voice-agent-architecture ·
mem0 https://arxiv.org/html/2504.19413v1 · isair/jarvis https://github.com/isair/jarvis ·
Ollama Tools https://ollama.com/blog/tool-support · Voice-Prompt-Guide 2026
https://www.autointerviewai.com/blog/prompt-engineering-voice-ai-interruptions-latency-2026
