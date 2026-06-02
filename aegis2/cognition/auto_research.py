"""Autonome Hintergrund-Recherche — AEGIS lernt VON SELBST dazu und entwickelt sich stetig.

Periodisch (stark gedrosselt) nimmt sich AEGIS ein noch nicht gelerntes Sicherheits-/Technik-
Thema vor, schlaegt es nach (web_knowledge -> Wikipedia, ueber das Web-Suche-Toggle gated),
laesst das lokale LLM die Kernfakten auf Deutsch verdichten und legt sie in die durchsuchbare
Wissensbasis (knowledge_base.learn). So waechst AEGIS' Wissen mit der Zeit -> bessere Antworten.

Sicherheit/Datenschutz: OPT-IN (Setting 'auto_research_enabled', Default AUS) UND braucht
erlaubte Web-Suche. Nur lesende Wikipedia-Abrufe (allowlisted), keine Telemetrie nach aussen.
Sehr langsam (ein Thema pro Intervall), damit es niemanden stoert.
"""
from __future__ import annotations

import json

from ..shared.modules.base import Module
from ..shared.events import Severity, Category

# Kuratierte Themen, die AEGIS nach und nach selbst lernt (Wikipedia-Lemmata, Deutsch).
_TOPICS = [
    "Ransomware", "Phishing", "Trojanisches Pferd (Computerprogramm)", "Computervirus",
    "Computerwurm", "Rootkit", "Keylogger", "Spyware", "Adware", "Botnet",
    "Denial of Service", "Man-in-the-Middle-Angriff", "SQL-Injection", "Cross-Site-Scripting",
    "Exploit", "Zero-Day-Exploit", "Brute-Force-Methode", "Social Engineering (Sicherheit)",
    "Zwei-Faktor-Authentisierung", "Firewall", "Antivirenprogramm", "BitLocker",
    "Benutzerkontensteuerung", "Windows-Registrierungsdatenbank", "PowerShell",
    "Verschluesselung", "Virtual Private Network", "Transport Layer Security",
    "Public-Key-Infrastruktur", "Kryptologische Hashfunktion", "Sandbox", "Patch (Software)",
    "Sicherheitsluecke", "Advanced Persistent Threat", "Spear-Phishing", "Drive-by-Download",
    "Cryptojacking", "Pufferueberlauf", "Rechteausweitung", "DNS-Spoofing", "ARP-Spoofing",
    "Datenexfiltration", "Sicherungskopie", "Schadprogramm", "Spam", "Captcha",
    "Digitale Signatur", "Penetrationstest", "Honeypot",
    # --- nachgeladen, damit der Selbst-Lerner nicht trockenlaeuft (modernere/breitere Themen) ---
    "Emotet", "WannaCry", "Stuxnet", "Heartbleed", "Spectre (Sicherheitsluecke)",
    "Meltdown (Sicherheitsluecke)", "Tor (Netzwerk)", "Ende-zu-Ende-Verschluesselung",
    "Single Sign-on", "OAuth", "Datenschutz-Grundverordnung", "Datenpanne",
    "Intrusion Detection System", "Domain Name System", "Secure Shell", "Passwort-Manager",
    "Digitales Zertifikat", "Steganographie", "Deepfake", "HTTP-Cookie",
    "Hypertext Transfer Protocol Secure", "Zertifizierungsstelle (Digitale Zertifikate)",
    "Schwachstelle (Computersicherheit)", "Bug-Bounty-Programm", "Security Operations Center",
    "Zero Trust", "Multi-Faktor-Authentisierung", "Ransomware-as-a-Service",
]


class AutoResearch(Module):
    name = "AutoResearch"
    INTERVAL = 1200          # 20 Min pro Thema -> langsam & stetig
    FIRST_DELAY = 90         # nach Start kurz warten, dann erstes Thema

    def __init__(self, bus, db):
        super().__init__(bus)
        self.db = db

    def _enabled(self) -> bool:
        return bool(self.db.get_setting("auto_research_enabled", False))

    def _done(self) -> set:
        # set_setting/get_setting sind JSON-kodiert -> Liste direkt ablegen/lesen (kein doppeltes
        # json.dumps, das frueher das Tracking verschluckte). Toleriert auch alt-gespeicherte Strings.
        v = self.db.get_setting("auto_research_done", [])
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except Exception:  # noqa: BLE001
                v = []
        return set(v) if isinstance(v, (list, tuple)) else set()

    def _mark(self, topic: str) -> None:
        d = self._done()
        d.add(topic)
        try:
            self.db.set_setting("auto_research_done", sorted(d))
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _clean_topic(t) -> str:
        t = (t or "").strip()
        t = t.splitlines()[0].strip() if t else ""      # nur die erste Zeile
        return t.strip(" \"'«».:-")

    def _llm_topic(self, done: set):
        """Ist die kuratierte Liste durch, schlaegt das lokale LLM SELBST ein neues, noch
        unbekanntes Wikipedia-Lemma vor -> echtes, unbegrenztes Weiterlernen (kein Stillstand)."""
        try:
            from ..voice import llm
        except Exception:  # noqa: BLE001
            return None
        recent = ", ".join(sorted(done)[-45:])         # Ausschlussliste handhabbar halten
        schema = {"type": "object", "properties": {"topic": {"type": "string"}},
                  "required": ["topic"]}
        prompt = ("Du baust die Wissensbasis eines lokalen Schutz-/Sicherheits-Assistenten aus. "
                  "Nenne GENAU EIN konkretes deutsches Wikipedia-Lemma aus IT-Sicherheit, "
                  "Datenschutz, Netzwerk- oder Computertechnik, das noch fehlt und nuetzlich ist. "
                  "Es darf NICHT in dieser Liste stehen: " + recent +
                  ". Antworte als JSON {\"topic\": \"<Lemma>\"}.")
        try:
            r = llm.ask_json(prompt, schema=schema, num_predict=40) or {}
            t = self._clean_topic(r.get("topic"))
            if t and len(t) >= 3 and t not in done:
                return t
        except Exception:  # noqa: BLE001
            pass
        return None

    def _next_topic(self):
        """Naechstes zu lernendes Thema: erst die kuratierte Liste, dann LLM-generiert."""
        done = self._done()
        t = next((x for x in _TOPICS if x not in done), None)
        return t if t else self._llm_topic(done)

    def run(self) -> None:
        self._stop.wait(self.FIRST_DELAY)
        while not self._stop.is_set():
            try:
                if self._enabled():
                    self.learn_one()
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.SYSTEM, f"Auto-Recherche: {type(e).__name__}")
            self._stop.wait(self.INTERVAL)

    def learn_one(self) -> bool:
        """Ein Thema recherchieren + lernen. Returns True bei neuem Wissen. Auch direkt testbar."""
        # Web-Suche muss erlaubt sein — sonst diese Runde NICHTS tun (Thema nicht verbrauchen).
        try:
            from .gate import capability_enabled
            if not capability_enabled("websearch"):
                return False
        except Exception:  # noqa: BLE001
            pass
        topic = self._next_topic()
        if topic is None:
            return False                       # nichts Neues gefunden (z.B. LLM offline)
        try:
            from ..voice import web_knowledge, llm
            from ..shared import knowledge_base
        except Exception:  # noqa: BLE001
            return False
        info = web_knowledge.lookup(topic)
        if not info or not (info.get("extract") or "").strip():
            self._mark(topic)                  # kein Treffer -> nicht endlos wiederholen
            return False
        prompt = (f"Verdichte das Wichtigste ueber «{topic}» fuer eine Sicherheits-Wissensbasis "
                  f"auf 2-3 kurze, sachliche deutsche Saetze (nur Fakten, kein Vorwort):\n"
                  + info["extract"][:600])
        summary = llm.ask(prompt, num_predict=170)
        learned = False
        if summary and len(summary.strip()) > 20:
            try:
                learned = bool(knowledge_base.learn(f"{topic}: {summary.strip()}"))
            except Exception:  # noqa: BLE001
                learned = False
        if learned:
            self.emit(Severity.INFO, Category.SYSTEM, f"Selbst dazugelernt: {topic}")
        self._mark(topic)
        return learned
