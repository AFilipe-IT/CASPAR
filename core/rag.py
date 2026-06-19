"""
core/rag.py
-----------
RAG sobre o CIS Benchmark PDF — sem LlamaIndex, sem dependências externas.

Porquê não LlamaIndex neste momento:
  - LlamaIndex requer pip install com rede, que não está disponível no sandbox.
  - O PDF do CIS Benchmark é texto puro (não é PDF renderizado), logo pdftotext
    não é necessário — basta ler o ficheiro como texto.
  - Para 87 secções e ~7600 linhas, TF-IDF simples em stdlib é suficiente
    e mais auditável do que um vector store opaco.

Quando LlamaIndex estiver disponível (produção):
  - Substituir BenchmarkIndex por LlamaIndexBackend (drop-in).
  - A interface RAGIndex.query() não muda — o resto do código não se toca.

Interface:
    index = BenchmarkIndex(pdf_path)
    sections = index.query("ServerTokens information disclosure", top_k=3)
    # -> list[Section(title, body, cis_section_id)]
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from collections import Counter
from pathlib import Path


# ------------------------------------------------------------------ #
# Data types                                                           #
# ------------------------------------------------------------------ #

@dataclass
class Section:
    """One CIS Benchmark recommendation section."""
    section_id: str       # e.g. "8.1"
    title: str            # e.g. "Ensure ServerTokens is Set to 'Prod'"
    level: str            # "Level 1" or "Level 2"
    description: str
    rationale: str
    remediation: str
    default_value: str
    full_text: str        # concatenation of all fields (for retrieval)
    directives: list[str] = field(default_factory=list)  # Apache directives mentioned


# ------------------------------------------------------------------ #
# CIS Benchmark parser                                                 #
# ------------------------------------------------------------------ #

_SECTION_RE = re.compile(
    r'^(\d+(?:\.\d+)+)\s+Ensure\s+(.+?)(?:\s*\((?:Automated|Manual)\))?$',
    re.MULTILINE,
)

_DIRECTIVE_RE = re.compile(
    r'\b(ServerTokens|ServerSignature|TraceEnable|SSLProtocol|SSLCipherSuite|'
    r'SSLCompression|SSLSessionTickets|SSLStapling|AllowOverride|Options|'
    r'User|Group|Listen|Timeout|KeepAlive|MaxKeepAliveRequests|KeepAliveTimeout|'
    r'LimitRequestLine|LimitRequestFields|LimitRequestFieldSize|LimitRequestBody|'
    r'LoadModule|LogLevel|FileETag|Order|Allow|Deny|Require|AuthType|'
    r'DirectoryIndex|UserDir|Header|RequestHeader|DocumentRoot|ScriptAlias)\b'
)


def _read_pdf(path: str) -> str:
    """
    Read text from a PDF file.

    Tries pdftotext first (handles real PDFs).
    Falls back to reading the file as plain text (handles the sandbox
    format where PDFs are actually plain text files).
    """
    import subprocess

    # Check if this is a real PDF (starts with %PDF)
    try:
        with open(path, "rb") as f:
            header = f.read(4)
        is_real_pdf = header == b"%PDF"
    except OSError:
        is_real_pdf = False

    if is_real_pdf:
        try:
            result = subprocess.run(
                ["pdftotext", "-layout", path, "-"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
            # pdftotext failed — try without -layout
            result = subprocess.run(
                ["pdftotext", path, "-"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        # Last resort: read raw bytes and decode (will have garbage but may work)
        return Path(path).read_bytes().decode("utf-8", errors="replace")

    # Plain text file (sandbox format)
    return Path(path).read_text(encoding="utf-8", errors="replace")


def parse_benchmark(path: str) -> list[Section]:
    """
    Parse the CIS Benchmark PDF into structured Section objects.

    Works with both real PDFs (via pdftotext) and plain text files.
    Sections are delimited by 'Profile Applicability:' markers.
    """
    content = _read_pdf(path)

    # Find section bodies via 'Profile Applicability:' marker
    boundaries = [m.start() for m in re.finditer(r'Profile Applicability:', content)]
    boundaries.append(len(content))  # sentinel

    sections = []
    for i, start in enumerate(boundaries[:-1]):
        end = boundaries[i + 1]
        chunk = content[max(0, start - 500) : end]

        # Extract section ID and title from the text before 'Profile Applicability:'
        pre = content[max(0, start - 500) : start]
        lines = [l.strip() for l in pre.split('\n') if l.strip() and not l.startswith('Page')]
        section_id, title = "", ""
        for line in reversed(lines):
            m = re.match(r'^(\d+(?:\.\d+)+)\s+Ensure\s+(.+)', line)
            if m:
                section_id = m.group(1)
                title_raw = m.group(2)
                # Clean up continuation artifacts
                title = re.sub(r'\s+\((?:Automated|Manual)\)', '', title_raw).strip()
                break

        if not section_id:
            continue  # skip non-recommendation sections

        body = content[start:end]

        # Extract structured fields
        level = _extract_field(body, 'Profile Applicability:', 'Description:')
        description = _extract_field(body, 'Description:', 'Rationale:')
        rationale = _extract_field(body, 'Rationale:', 'Audit:')
        remediation = _extract_field(body, 'Remediation:', 'Default Value:')
        default_value = _extract_field(body, 'Default Value:', 'References:')

        # Clean level
        level = re.sub(r'[•\s]+', ' ', level).strip()
        if 'Level 2' in level:
            level = 'Level 2'
        else:
            level = 'Level 1'

        # Find Apache directives mentioned
        full = f"{title} {description} {rationale} {remediation}"
        directives = list(set(_DIRECTIVE_RE.findall(full)))

        sections.append(Section(
            section_id=section_id,
            title=title,
            level=level,
            description=description.strip(),
            rationale=rationale.strip(),
            remediation=remediation.strip(),
            default_value=default_value.strip(),
            full_text=full,
            directives=directives,
        ))

    return sections


def _extract_field(text: str, start_marker: str, end_marker: str) -> str:
    """Extract text between two markers."""
    s = text.find(start_marker)
    if s == -1:
        return ""
    s += len(start_marker)
    e = text.find(end_marker, s)
    if e == -1:
        return text[s:s + 800]
    return text[s:e].strip()


# ------------------------------------------------------------------ #
# TF-IDF retrieval (stdlib, no numpy)                                  #
# ------------------------------------------------------------------ #

class BenchmarkIndex:
    """
    TF-IDF index over CIS Benchmark sections.

    Sufficient for retrieving the top-k most relevant sections for a
    given directive/keyword query. Replaces LlamaIndex for environments
    without pip access.
    """

    def __init__(self, pdf_path: str) -> None:
        self.sections = parse_benchmark(pdf_path)
        self._build_index()

    def _tokenize(self, text: str) -> list[str]:
        return re.findall(r'[a-zA-Z][a-zA-Z0-9]*', text.lower())

    def _build_index(self) -> None:
        """Pre-compute TF-IDF vectors for all sections."""
        N = len(self.sections)
        # Document frequency
        df: Counter = Counter()
        tfs = []
        for sec in self.sections:
            tokens = self._tokenize(sec.full_text)
            tf = Counter(tokens)
            tfs.append(tf)
            df.update(set(tokens))

        # IDF
        self._idf = {
            term: math.log((N + 1) / (count + 1)) + 1
            for term, count in df.items()
        }
        # TF-IDF vectors (normalised)
        self._vectors = []
        for tf in tfs:
            vec = {t: (1 + math.log(c)) * self._idf.get(t, 1) for t, c in tf.items()}
            norm = math.sqrt(sum(v ** 2 for v in vec.values())) or 1.0
            self._vectors.append({t: v / norm for t, v in vec.items()})

    def query(self, query: str, top_k: int = 3) -> list[Section]:
        """
        Return the top_k most relevant sections for the given query.

        Query can be a directive name, a description snippet, or a combination.
        """
        q_tokens = self._tokenize(query)
        q_tf = Counter(q_tokens)
        q_vec = {t: (1 + math.log(c)) * self._idf.get(t, 1) for t, c in q_tf.items()}
        q_norm = math.sqrt(sum(v ** 2 for v in q_vec.values())) or 1.0
        q_vec = {t: v / q_norm for t, v in q_vec.items()}

        scores = []
        for i, doc_vec in enumerate(self._vectors):
            # Cosine similarity
            sim = sum(q_vec.get(t, 0) * doc_vec.get(t, 0) for t in q_vec)
            scores.append((sim, i))

        scores.sort(reverse=True)
        return [self.sections[i] for _, i in scores[:top_k]]

    def get_by_section_id(self, section_id: str) -> Section | None:
        """Direct lookup by CIS section ID (e.g. '8.1')."""
        for sec in self.sections:
            if sec.section_id == section_id:
                return sec
        return None

    def get_by_directive(self, directive: str) -> list[Section]:
        """Return all sections that mention a specific Apache directive."""
        return [s for s in self.sections if directive in s.directives]
