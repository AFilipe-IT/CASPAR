"""
core/llm_client.py
------------------
Abstracção sobre o LLM local (Ollama) e a Claude API.

Interface única: LLMClient.complete(prompt, system) -> str

O caller não sabe se está a usar Ollama, Claude API, ou um stub de teste.
A escolha é feita uma vez na construção do cliente.

Modelos Ollama recomendados para este pipeline (por ordem de preferência):
  - qwen2.5:14b     — melhor raciocínio estruturado, JSON fiável, cabe em 8GB VRAM com Q4
  - llama3.1:8b     — rápido, bom para tarefas simples
  - mistral:7b      — alternativa leve
  - deepseek-r1:8b  — bom raciocínio, verbose

Para CUDA com boa VRAM (16GB+):
  - qwen2.5:32b-instruct-q4_K_M  — melhor qualidade possível localmente
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Base interface                                                        #
# ------------------------------------------------------------------ #

class LLMClient(ABC):

    @abstractmethod
    def complete(self, prompt: str, system: str = "") -> str:
        """Send a prompt and return the model's text response."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the backend is reachable."""


# ------------------------------------------------------------------ #
# Ollama client (HTTP, zero dependencies)                              #
# ------------------------------------------------------------------ #

class OllamaClient(LLMClient):
    """
    Talks to a local Ollama instance via its REST API.

    Ollama exposes an OpenAI-compatible endpoint at /api/chat.
    Uses only stdlib urllib — no httpx, no requests needed.

    Usage:
        client = OllamaClient(model="qwen2.5:14b")
        response = client.complete(prompt, system)
    """

    def __init__(
        self,
        model: str = "qwen2.5:14b",
        base_url: str = "http://localhost:11434",
        timeout: int = 120,
        temperature: float = 0.1,   # low = more deterministic JSON output
        max_retries: int = 3,
        retry_delay: float = 2.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def complete(self, prompt: str, system: str = "") -> str:
        """
        Call Ollama /api/chat and return the assistant's message content.
        Retries on connection errors with exponential backoff.
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": 1024,
            },
        }).encode("utf-8")

        url = f"{self.base_url}/api/chat"

        for attempt in range(self.max_retries):
            try:
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    return body["message"]["content"]

            except urllib.error.HTTPError as e:
                # A 4xx is a permanent client error — retrying is pointless and
                # only hides the cause. The most common one is 404: the server
                # is up but the model isn't pulled.
                if 400 <= e.code < 500:
                    if e.code == 404:
                        raise RuntimeError(
                            f"Ollama returned 404 for model '{self.model}'. The "
                            f"server is running but the model is not installed.\n"
                            f"Pull it:        ollama pull {self.model}\n"
                            f"Or use another: --model <name>  (e.g. one from "
                            f"`ollama list`)"
                        ) from e
                    raise RuntimeError(
                        f"Ollama rejected the request (HTTP {e.code}) for model "
                        f"'{self.model}': {e.reason}"
                    ) from e
                # 5xx — transient server error: fall through to the retry path.
                self._retry_or_raise(e, attempt, wait_label="server error")

            except urllib.error.URLError as e:
                self._retry_or_raise(e, attempt, wait_label="connection error")

    def _retry_or_raise(self, e: Exception, attempt: int, *, wait_label: str) -> None:
        """Back off and retry transient failures; raise a clear error when the
        attempts are exhausted."""
        if attempt < self.max_retries - 1:
            wait = self.retry_delay * (2 ** attempt)
            logger.warning("Ollama request failed (%s, attempt %d/%d): %s — retrying in %.1fs",
                           wait_label, attempt + 1, self.max_retries, e, wait)
            time.sleep(wait)
        else:
            raise RuntimeError(
                f"Ollama unreachable after {self.max_retries} attempts: {e}\n"
                f"Is Ollama running? Try: ollama serve"
            ) from e


# ------------------------------------------------------------------ #
# Stub client (testes e modo offline)                                   #
# ------------------------------------------------------------------ #

class StubLLMClient(LLMClient):
    """
    Devolve respostas pré-definidas ou um JSON mínimo válido.
    Usado em testes e quando o Ollama não está disponível.
    """

    def __init__(self, fixed_response: Optional[str] = None) -> None:
        self._fixed = fixed_response

    def is_available(self) -> bool:
        return True

    def complete(self, prompt: str, system: str = "") -> str:
        if self._fixed:
            return self._fixed
        # Minimal valid CCSS metric JSON so the pipeline doesn't break
        return json.dumps({
            "ac": "L",
            "c": "P",
            "i": "N",
            "a": "N",
            "gel": "M",
            "grl": "H",
            "justification": "Stub response — Ollama not available.",
            "recommendation": "Configure this directive according to CIS Benchmark guidance.",
            "cve_ids": [],
        })


# ------------------------------------------------------------------ #
# Factory                                                              #
# ------------------------------------------------------------------ #

def make_client(
    backend: str = "ollama",
    model: str = "qwen2.5:14b",
    base_url: str = "http://localhost:11434",
    fallback_to_stub: bool = True,
) -> LLMClient:
    """
    Build an LLMClient.

    If backend='ollama' and Ollama is unreachable, falls back to StubLLMClient
    when fallback_to_stub=True (useful for development without GPU).

    Args:
        backend:          'ollama' or 'stub'
        model:            Ollama model tag (e.g. 'qwen2.5:14b', 'llama3.1:8b')
        base_url:         Ollama server URL (default: http://localhost:11434)
        fallback_to_stub: If True, returns StubLLMClient when Ollama is down
    """
    if backend == "stub":
        logger.info("LLM backend: stub (no model calls)")
        return StubLLMClient()

    client = OllamaClient(model=model, base_url=base_url)

    if not client.is_available():
        msg = f"Ollama not reachable at {base_url}"
        if fallback_to_stub:
            logger.warning("%s — falling back to stub client", msg)
            return StubLLMClient()
        raise RuntimeError(
            f"{msg}\n"
            "Start Ollama with: ollama serve\n"
            f"Pull the model with: ollama pull {model}"
        )

    logger.info("LLM backend: Ollama model=%s at %s", model, base_url)
    return client
