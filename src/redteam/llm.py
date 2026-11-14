"""Choix du modèle : OpenRouter en priorité, Ollama local en repli, sinon mode hors-ligne."""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass
class ModelChoice:
    primary: object | None
    fallbacks: list
    label: str


def _ollama_up(host: str) -> bool:
    try:
        return httpx.get(f"{host}/api/tags", timeout=2).status_code == 200
    except Exception:
        return False


def choose_model(offline: bool = False) -> ModelChoice:
    if offline:
        return ModelChoice(None, [], "hors-ligne (narration par modèles de texte)")
    from agno.models.ollama import Ollama
    from agno.models.openrouter import OpenRouter

    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    key = os.getenv("OPENROUTER_API_KEY")
    if key:
        primary = OpenRouter(id=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"), api_key=key, max_tokens=1200, temperature=0.2)
        fallbacks = [Ollama(id=ollama_model, host=ollama_host)] if _ollama_up(ollama_host) else []
        return ModelChoice(primary, fallbacks, f"openrouter:{primary.id}" + (f" (+ repli ollama:{ollama_model})" if fallbacks else ""))
    if _ollama_up(ollama_host):
        return ModelChoice(Ollama(id=ollama_model, host=ollama_host, timeout=600), [], f"ollama:{ollama_model}")
    return ModelChoice(None, [], "hors-ligne (aucun LLM joignable)")
