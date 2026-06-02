"""Lokale Wissensbasis (semantisches RAG) — der Nutzer 'fuettert' AEGIS mit Wissen,
das bei passenden Fragen automatisch herangezogen wird. Alles lokal in ~/.aegis/,
verlaesst den PC nie.

Zwei Quellen:
  1. "lerne: <text>"  -> Eintraege in ~/.aegis/knowledge.json
  2. Dateien (*.txt / *.md) im Ordner ~/.aegis/knowledge/  -> plus mitgeliefertes
     Grundwissen aus dem Paket-Ordner knowledge_seed/ (Auto-Seed beim ersten Start).

Retrieval = SEMANTISCHE Vektor-Suche ueber lokale Embeddings (Ollama-Modell bge-m3,
mehrsprachig inkl. Deutsch). Versteht Bedeutung statt nur Stichwoerter -> findet auch
Paraphrasen. Bewusst KEIN Keyword-Fallback: ist das Embedding-Modell (noch) nicht da,
zieht AEGIS es im Hintergrund und die Suche greift, sobald es bereit ist. Die Vektoren
werden persistent in ~/.aegis/knowledge_vectors.json zwischengespeichert (inkrementell,
nur Neues wird neu eingebettet). Treffer gehen dem LLM als DATEN, nie als Anweisung.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

_DIR = Path.home() / ".aegis"
_JSON = _DIR / "knowledge.json"
_DOCS = _DIR / "knowledge"            # Nutzer legt hier .txt/.md ab
_SEED = Path(__file__).parent / "knowledge_seed"   # mitgeliefertes Grundwissen (Paket)
_VEC = _DIR / "knowledge_vectors.json"             # persistenter Embedding-Index
_LOCK = threading.Lock()
_seeded = False

# Lokales Embedding-Modell — AEGIS waehlt es AUTONOM nach Hardware (best_embed_model()):
# qwen3-embedding:0.6b (neueste Generation, mehrsprachig/Deutsch) bzw. die 4B-Variante bei
# viel VRAM. Laeuft lokal via Ollama, verlaesst den PC nie. Wechselt das Modell, wird der
# Vektor-Index automatisch neu aufgebaut (Vektoren verschiedener Modelle sind unvergleichbar).
_EMBED_FALLBACK = "qwen3-embedding:0.6b"
_EMBED_MODEL = None                   # lazy aus best_embed_model() ermittelt (s. _embed_model)
_OLLAMA = "http://127.0.0.1:11434"
_MIN_SCORE = 0.40                     # Cosine-Schwelle: darunter gilt als "nicht relevant"
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_embed_ready = None                   # None=ungeprueft, True=da, False=fehlt (Pull laeuft)


def _embed_model() -> str:
    """Das aktuell zu nutzende Embedding-Modell — Hardware-abhaengig, einmal ermittelt
    und gecached. AEGIS entscheidet selbst (kein Hardcode), faellt bei Problemen auf die
    schlanke, ueberall lauffaehige Variante zurueck."""
    global _EMBED_MODEL
    if _EMBED_MODEL is None:
        try:
            from ..voice.ollama_setup import best_embed_model
            _EMBED_MODEL = best_embed_model() or _EMBED_FALLBACK
        except Exception:  # noqa: BLE001
            _EMBED_MODEL = _EMBED_FALLBACK
    return _EMBED_MODEL


# ----------------------------------------------------------------- Speicher (JSON-Eintraege)
def _load_json() -> list:
    try:
        d = json.loads(_JSON.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else []
    except Exception:  # noqa: BLE001
        return []


def _save_json(items: list) -> None:
    try:
        _DIR.mkdir(parents=True, exist_ok=True)
        tmp = _JSON.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(_JSON)
    except Exception:  # noqa: BLE001
        pass


# ----------------------------------------------------------------- Mitgeliefertes Grundwissen
def seed_docs() -> int:
    """Kopiert mitgeliefertes Grundwissen (Paket-Ordner knowledge_seed/) nach
    ~/.aegis/knowledge/, sofern dort noch nicht vorhanden. Nutzer-eigene Dateien
    werden NIE ueberschrieben."""
    n = 0
    try:
        if not _SEED.is_dir():
            return 0
        _DOCS.mkdir(parents=True, exist_ok=True)
        for f in sorted(_SEED.glob("*.md")) + sorted(_SEED.glob("*.txt")):
            dst = _DOCS / f.name
            if not dst.exists():
                try:
                    dst.write_text(f.read_text(encoding="utf-8", errors="ignore"),
                                   encoding="utf-8")
                    n += 1
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        pass
    return n


def _ensure_seeded() -> None:
    """Einmal pro Prozess das Grundwissen sicherstellen (idempotent, billig)."""
    global _seeded
    if not _seeded:
        _seeded = True
        seed_docs()


def _doc_chunks() -> list:
    """Dokument-Absaetze fuers Retrieval aus ZWEI Quellen:
      (1) mitgeliefertes Grundwissen DIREKT aus dem Paket-Ordner knowledge_seed/ — immer die
          aktuelle Version. Bringt ein UPDATE neues/erweitertes Grundwissen mit, steht es
          bestehenden Nutzern sofort bereit (kommt also DAZU), ohne dass je etwas
          ueberschrieben wird.
      (2) die EIGENEN Dokumente des Nutzers aus ~/.aegis/knowledge/.
    Die gelernte Nutzer-Wissensbasis (~/.aegis/knowledge.json) bleibt voellig unberuehrt —
    Updates ergaenzen nur, loeschen/ueberschreiben nie. Frueher nach ~/.aegis/knowledge/
    kopierte Seed-Dateien werden NICHT doppelt gelesen (die Paket-Version ist massgeblich)."""
    _ensure_seeded()       # legt mitgelieferte Seed-Dateien fuer neue Nutzer sichtbar ab
    out = []
    seen: set = set()      # exakt gleiche Absaetze nur EINMAL (ehrlicher Wissens-Index)
    import re as _re

    def _add(files):
        for f in files:
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            for para in _re.split(r"\n\s*\n", txt):
                para = para.strip()[:1000]
                if len(para) >= 20 and para not in seen:
                    seen.add(para)
                    out.append({"text": para, "src": f.name})

    seed_names: set = set()
    try:
        if _SEED.is_dir():
            seed_files = sorted(_SEED.glob("*.md")) + sorted(_SEED.glob("*.txt"))
            seed_names = {f.name.lower() for f in seed_files}
            _add(seed_files)                       # (1) Grundwissen DIREKT aus dem Paket
    except Exception:  # noqa: BLE001
        pass
    try:
        if _DOCS.is_dir():
            user_files = [f for f in (sorted(_DOCS.glob("*.txt")) + sorted(_DOCS.glob("*.md")))
                          if f.name.lower() not in seed_names]
            _add(user_files)                       # (2) eigene Dokumente des Nutzers
    except Exception:  # noqa: BLE001
        pass
    return out


def _looks_like_garbage(text: str) -> bool:
    """True bei offensichtlichem Müll/Test-Spam — wiederholtes Einzelzeichen ('ääääää…',
    'aaaaaa…') oder dasselbe Wort x-fach ('wort wort wort…'). Solcher Unsinn ist kein Wissen
    und soll NICHT in die Wissensbasis (vermuellte sonst 'was hast du gelernt')."""
    import re as _re
    t = (text or "").strip()
    if not t:
        return True
    if _re.fullmatch(r"(.)\1{6,}", _re.sub(r"\s+", "", t)):          # 'ääääää…', 'aaaaaa…'
        return True
    words = _re.findall(r"[^\W\d_]+", t.lower())
    if len(words) >= 4 and len(set(words)) <= max(2, len(words) // 4):  # 'wort wort wort…'
        return True
    return False


def learn(text: str) -> bool:
    """Neues Wissen ablegen ('lerne: ...'). Returns True bei Erfolg/Duplikat.
    Der Vektor-Index wird beim naechsten search() inkrementell nachgezogen."""
    text = (text or "").strip()[:1000]
    if len(text) < 3 or _looks_like_garbage(text):
        return False
    with _LOCK:
        items = _load_json()
        if text.lower() in [i.get("text", "").lower() for i in items]:
            return True
        items.append({"text": text})
        _save_json(items[-200:])            # die letzten 200 Eintraege behalten
        return True


def _passages(text: str, size: int = 800) -> list:
    """Langen Fliesstext in ~size-Zeichen-Absaetze schneiden (an Satz-/Wortgrenzen). Noetig, weil
    der Doc-Chunker (_doc_chunks) an LEERZEILEN splittet und je [:1000] nimmt — kollabierter
    Webtext (eine Zeile) wuerde sonst bis auf das erste Stueck verloren gehen."""
    import re as _re
    text = _re.sub(r"\s+", " ", text or "").strip()
    out = []
    while text:
        if len(text) <= size:
            out.append(text)
            break
        cut = text.rfind(". ", size // 2, size)
        if cut < 0:
            cut = text.rfind(" ", size // 2, size)
        if cut < 0:
            cut = size
        out.append(text[:cut + 1].strip())
        text = text[cut + 1:].strip()
    return [p for p in out if len(p) >= 20]


def _safe_name(s: str) -> str:
    import re as _re
    s = _re.sub(r"[^a-z0-9]+", "-", (s or "web").lower()).strip("-")
    return (s or "web")[:40]


def learn_document(text: str, source: str = "web", url: str = "", title: str = "") -> int:
    """Einen GANZEN Text (z.B. eine ganze Webseite) als durchsuchbares Dokument ablegen — als
    .md in ~/.aegis/knowledge/, in Absaetze zerlegt. NICHT der 200-Eintrag-Grenze unterworfen
    (die gilt nur fuer knowledge.json); der Doc-Pfad chunkt/embedded/durchsucht es automatisch.
    Returns Anzahl abgelegter Absaetze (Chunks)."""
    paras = _passages(text)
    if not paras:
        return 0
    try:
        import hashlib as _h
        _DOCS.mkdir(parents=True, exist_ok=True)
        h = _h.sha1((url or source or title or "web").encode("utf-8", "ignore")).hexdigest()[:8]
        fname = f"web-{_safe_name(source)}-{h}.md"
        header = f"# Gelernt: {title or source}\n"
        if url:
            header += f"# Quelle: {url}\n"
        body = header + "\n" + "\n\n".join(paras) + "\n"
        tmp = (_DOCS / fname).with_suffix(".md.tmp")
        tmp.write_text(body, encoding="utf-8")
        tmp.replace(_DOCS / fname)
        return len(paras)
    except Exception:  # noqa: BLE001
        return 0


def reindex_async() -> None:
    """Stoesst den Embedding-Index im HINTERGRUND an: neu gelernte Dokumente werden so
    eingebettet, BEVOR der Nutzer das naechste Mal fragt — statt traege (und unter _LOCK)
    beim ersten search() nachzuziehen."""
    def _w():
        try:
            with _LOCK:
                _ensure_index()
        except Exception:  # noqa: BLE001
            pass
    try:
        threading.Thread(target=_w, daemon=True, name="KBReindex").start()
    except Exception:  # noqa: BLE001
        pass


# ----------------------------------------------------------------- Embeddings (lokal via Ollama)
def _normalize(v: list) -> list:
    n = sum(x * x for x in v) ** 0.5
    return [x / n for x in v] if n else v


def _dot(a: list, b: list) -> float:
    return sum(x * y for x, y in zip(a, b))    # beide normalisiert -> Cosine-Aehnlichkeit


def _embed(texts: list) -> list | None:
    """Embeddet Texte ueber das lokale Ollama-Modell. Returns Liste normalisierter
    Vektoren oder None (Modell fehlt / Ollama nicht erreichbar)."""
    if not texts:
        return []
    try:
        body = json.dumps({"model": _embed_model(), "input": texts}).encode("utf-8")
        req = urllib.request.Request(_OLLAMA + "/api/embed", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            d = json.loads(r.read().decode("utf-8"))
        embs = d.get("embeddings")
        if isinstance(embs, list) and len(embs) == len(texts) and embs and embs[0]:
            return [_normalize(e) for e in embs]
    except Exception:  # noqa: BLE001
        pass
    return None


def _pull_embed_model() -> None:
    """Zieht das Embedding-Modell einmalig (Hintergrund). Danach Status zuruecksetzen,
    damit der naechste Zugriff es erneut testet."""
    global _embed_ready
    try:
        subprocess.run(["ollama", "pull", _embed_model()], capture_output=True,
                       timeout=3600, creationflags=_NO_WINDOW)
    except Exception:  # noqa: BLE001
        pass
    _embed_ready = None        # neu testen lassen


def _ensure_embed_model() -> bool:
    """True, wenn das Embedding-Modell nutzbar ist. Fehlt es, wird es EINMAL im
    Hintergrund gezogen (kein Blockieren); bis dahin liefert die Suche nichts."""
    global _embed_ready
    if _embed_ready:
        return True
    if _embed(["bereit?"]):              # echter Mini-Test gegen Ollama
        _embed_ready = True
        return True
    if _embed_ready is None:             # erstes Fehlschlagen -> Hintergrund-Pull anstossen
        _embed_ready = False
        try:
            threading.Thread(target=_pull_embed_model, daemon=True).start()
        except Exception:  # noqa: BLE001
            pass
    return False


# ----------------------------------------------------------------- Vektor-Index (persistent)
def embed_ready() -> bool:
    """True, wenn das Such-Modell geladen + nutzbar ist -> Wissens-Suche aktiv.
    Loest KEINEN Pull aus (reiner Status), anders als _ensure_embed_model()."""
    return _embed(["status"]) is not None


def _all_chunks() -> list:
    """Alle Wissens-Stuecke: gelernte JSON-Eintraege + Dokument-Absaetze."""
    out = [{"text": i.get("text", ""), "src": "gelernt"}
           for i in _load_json() if i.get("text")]
    out += _doc_chunks()
    return out


def _load_index() -> dict:
    try:
        d = json.loads(_VEC.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _save_index(idx: dict) -> None:
    try:
        _DIR.mkdir(parents=True, exist_ok=True)
        tmp = _VEC.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(idx, ensure_ascii=False), encoding="utf-8")
        tmp.replace(_VEC)
    except Exception:  # noqa: BLE001
        pass


def _ensure_index() -> dict:
    """Haelt den Vektor-Index aktuell: bettet neue Chunks inkrementell ein, wirft entfernte
    raus. Persistiert {model, vectors:{sha1: {text, src, vec}}}. Wechselt das Embedding-
    Modell (z.B. bge-m3 -> qwen3-embedding), wird der Index KOMPLETT verworfen und neu
    aufgebaut — Vektoren verschiedener Modelle liegen in unvergleichbaren Raeumen, ein Mix
    wuerde die Suche verfaelschen. Returns das vectors-Dict (was search() braucht)."""
    chunks = _all_chunks()
    want = {hashlib.sha1(c["text"].encode("utf-8")).hexdigest(): c for c in chunks if c["text"]}
    model = _embed_model()
    raw = _load_index()
    model_changed = raw.get("model") != model        # auch True bei altem, modell-losen Index
    idx = {} if model_changed else (raw.get("vectors") or {})
    missing = [h for h in want if h not in idx]
    if missing:
        vecs = _embed([want[h]["text"] for h in missing])
        if vecs:
            for h, v in zip(missing, vecs):
                idx[h] = {"text": want[h]["text"], "src": want[h].get("src", ""), "vec": v}
    changed = bool(missing) or model_changed
    for h in list(idx):                  # entfernte Chunks aus dem Index nehmen
        if h not in want:
            del idx[h]
            changed = True
    if changed:
        _save_index({"model": model, "vectors": idx})
    return idx


# ----------------------------------------------------------------- oeffentliche API
def _tokenize(s: str) -> list:
    import re as _re
    return [w for w in _re.findall(r"[a-zäöüß0-9][a-zäöüß0-9._/\-]*", (s or "").lower())
            if len(w) >= 2]


def _bm25_rank(query: str, items: list, k1: float = 1.5, b: float = 0.75) -> list:
    """Lexikalisches BM25-Ranking ueber die Index-Items -> Liste von Item-Indizes,
    bestes zuerst. Faengt EXAKTE seltene Tokens (CVE-IDs, Dateipfade, Prozessnamen,
    Hashes), die die reine Bedeutungssuche verfehlen kann (wichtig fuer ein Security-Tool)."""
    import math
    docs = [_tokenize(it.get("text", "")) for it in items]
    n = len(docs)
    if not n:
        return []
    avgdl = sum(len(d) for d in docs) / n or 1.0
    df: dict = {}
    for d in docs:
        for t in set(d):
            df[t] = df.get(t, 0) + 1
    qtok = set(_tokenize(query))
    scored = []
    for i, d in enumerate(docs):
        if not d:
            continue
        tf: dict = {}
        for t in d:
            tf[t] = tf.get(t, 0) + 1
        s = 0.0
        for t in qtok:
            if t in tf:
                idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
                s += idf * (tf[t] * (k1 + 1)) / (tf[t] + k1 * (1 - b + b * len(d) / avgdl))
        if s > 0:
            scored.append((s, i))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [i for _, i in scored]


def _llm_rerank(query: str, cands: list) -> list:
    """Optionales Re-Ranking der Top-Kandidaten durch das vorhandene lokale Ollama-
    Modell (Query + Passage werden GEMEINSAM bewertet -> echte Relevanz statt nur
    Vektor-Naehe). KEINE neue Abhaengigkeit. Bei Fehler bleibt die RRF-Reihenfolge."""
    try:
        from ..voice import llm
        if not llm.available() or len(cands) < 2:
            return cands
        listing = "\n".join(f"[{i}] {c.get('text', '')[:300]}" for i, c in enumerate(cands))
        schema = {"type": "object",
                  "properties": {"order": {"type": "array", "items": {"type": "integer"}}},
                  "required": ["order"]}
        d = llm.ask_json(
            f"Frage: «{query}»\n\nPassagen:\n{listing}\n\nGib ein JSON-Objekt mit 'order' = "
            "Liste der Passagen-Indizes, sortiert von der für die Frage RELEVANTESTEN zur "
            "unwichtigsten. Lass Indizes weg, die nichts mit der Frage zu tun haben.",
            schema=schema, num_predict=64)
        order = d.get("order") if isinstance(d, dict) else None
        if isinstance(order, list) and order:
            picked = [cands[i] for i in order if isinstance(i, int) and 0 <= i < len(cands)]
            if picked:
                return picked
    except Exception:  # noqa: BLE001
        pass
    return cands


def search(query: str, k: int = 3) -> list:
    """Die k relevantesten Wissens-Stuecke — HYBRID + RE-RANKING.

    Pipeline: (1) DENSE semantische Suche (Embeddings, mit Relevanz-Schwelle fuers
    Grounding) + (2) SPARSE BM25 (exakte Tokens) -> (3) Reciprocal Rank Fusion ->
    (4) lokales LLM-Re-Ranking der Top-Kandidaten. KEIN Keyword-Fallback: fehlt das
    Embedding-Modell, kommt [] zurueck (AEGIS zieht es im Hintergrund). Findet sich
    nichts hinreichend Relevantes, kommt [] -> AEGIS raet dann nicht."""
    q = (query or "").strip()
    if not q:
        return []
    with _LOCK:
        if not _ensure_embed_model():
            return []
        idx = _ensure_index()
        qv = _embed([q])
    if not qv or not idx:
        return []
    qv = qv[0]
    items = list(idx.values())
    # (1) DENSE: Cosine-Ranking; dense_ok = nur semantisch hinreichend Passendes
    dense = []
    for n, it in enumerate(items):
        v = it.get("vec")
        if v and len(v) == len(qv):
            dense.append((_dot(qv, v), n))
    dense.sort(key=lambda x: x[0], reverse=True)
    dense_ok = {n for s, n in dense if s >= _MIN_SCORE}
    dense_rank = [n for _, n in dense]
    # (2) SPARSE: BM25 (exakte Tokens, z.B. CVE-IDs/Pfade)
    sparse_rank = _bm25_rank(q, items)
    # (3) FUSION: Reciprocal Rank Fusion (rangbasiert -> kein Skalen-Tuning noetig)
    rrf: dict = {}
    for r, n in enumerate(dense_rank):
        rrf[n] = rrf.get(n, 0.0) + 1.0 / (60 + r)
    for r, n in enumerate(sparse_rank):
        rrf[n] = rrf.get(n, 0.0) + 1.0 / (60 + r)
    # Grounding: nur Kandidaten, die semantisch passen ODER lexikalisch exakt matchen
    allowed = dense_ok | set(sparse_rank)
    fused = sorted((n for n in rrf if n in allowed), key=lambda n: rrf[n], reverse=True)
    if not fused:
        return []
    cands = [{"text": items[n]["text"], "src": items[n].get("src", "")}
             for n in fused[:max(k * 3, 8)]]
    # (4) RE-RANKING durch das lokale LLM, dann die besten k
    return _llm_rerank(q, cands)[:k]


def recent(n: int = 5) -> list:
    """Die zuletzt gelernten JSON-Eintraege (neueste zuerst) als Text-Liste — fuer
    'was hast du gelernt'. Dokumente/Seed werden bewusst NICHT mitgezaehlt (das ist
    Grundwissen, kein 'frisch Gelerntes')."""
    items = _load_json()
    return [i.get("text", "") for i in items[-n:][::-1] if i.get("text")]


def count() -> int:
    return len(_load_json()) + len(_doc_chunks())


def forget_matching(query: str) -> int:
    """Gelernte JSON-Eintraege loeschen, die den Suchtext enthalten (Teilstring ODER
    Wort-Ueberlappung). Dokumente im Ordner bleiben. Returns Anzahl. Der Vektor-Index
    wird beim naechsten search() automatisch abgeglichen (entfernte Chunks fliegen raus)."""
    import re as _re
    q = (query or "").strip().lower()
    if not q:
        return 0
    qwords = {w for w in _re.findall(r"[a-zäöüß0-9]{3,}", q)}
    with _LOCK:
        items = _load_json()
        kept, removed = [], 0
        for it in items:
            t = (it.get("text", "") or "").lower()
            twords = {w for w in _re.findall(r"[a-zäöüß0-9]{3,}", t)}
            if q in t or (qwords and len(qwords & twords) >= max(1, len(qwords) // 2)):
                removed += 1
            else:
                kept.append(it)
        if removed:
            _save_json(kept)
        return removed


def forget_all() -> int:
    """Gelerntes Wissen (JSON-Eintraege) loeschen — Dokumente im Ordner bleiben.
    Der Vektor-Index wird beim naechsten search() automatisch nachgezogen."""
    with _LOCK:
        n = len(_load_json())
        _save_json([])
        return n
