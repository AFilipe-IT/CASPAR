"""
tests/test_chain_pipeline.py
------------------------------
Testes para a geração de chains via LLM.

Todos os testes correm sem Ollama — usam StubLLMClient com respostas pré-definidas.
"""

from __future__ import annotations

import json
import tempfile
import os

import pytest

from core.ccss import base_score, temporal_score
from core.llm_client import StubLLMClient
from core.models import AttackChain, Misconfiguration
from plugins.apache_httpd.chain_pipeline import (
    _build_chain_prompt,
    _extract_chains_json,
    _load_fallback_chains,
    _validate_chain,
    generate_chains,
)


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

def _make_misconfig(directive, bad_value, ac, c, i, a, gel="M", grl="H") -> Misconfiguration:
    bs = base_score("N", "N", ac, c, i, a)
    ts = temporal_score(bs, gel, grl)
    return Misconfiguration(
        target_name="apache-httpd",
        directive=directive,
        bad_value=bad_value,
        ac=ac, c=c, i=i, a=a,
        base_score=bs,
        temporal_score=ts,
        gel=gel, grl=grl,
    )


@pytest.fixture
def sample_misconfigs():
    return [
        _make_misconfig("User",          "root",        "L", "C", "C", "C"),
        _make_misconfig("ServerTokens",  "Full",        "L", "P", "N", "N"),
        _make_misconfig("ServerSignature","On",         "L", "P", "N", "N"),
        _make_misconfig("TraceEnable",   "On",          "M", "P", "P", "N"),
        _make_misconfig("AllowOverride", "All",         "M", "P", "P", "N"),
        _make_misconfig("Options",       "Indexes",     "L", "P", "P", "N"),
        _make_misconfig("Timeout",       "300",         "L", "N", "N", "P"),
        _make_misconfig("SSLProtocol",   "All",         "L", "P", "N", "N"),
        _make_misconfig("LoadModule",    "dav_module",  "L", "P", "C", "P"),
    ]


VALID_LLM_RESPONSE = json.dumps([
    {
        "chain_id": "recon-to-rce",
        "misconfig_directives": ["ServerTokens", "LoadModule", "AllowOverride"],
        "amplification": 1.6,
        "justification": "ServerTokens exposes version (recon), dav_module enables file upload (access), AllowOverride All allows .htaccess to execute code (RCE). Full path: fingerprint → upload → execute.",
        "cross_target": False,
    },
    {
        "chain_id": "info-disclosure-chain",
        "misconfig_directives": ["ServerTokens", "ServerSignature"],
        "amplification": 1.3,
        "justification": "Both directives expose version details, compounding information disclosure risk.",
        "cross_target": False,
    },
    {
        "chain_id": "root-privilege-escalation",
        "misconfig_directives": ["User", "AllowOverride"],
        "amplification": 1.7,
        "justification": "AllowOverride All allows .htaccess execution; User=root means any executed code runs as root — immediate full system compromise.",
        "cross_target": False,
    },
])


# ------------------------------------------------------------------ #
# Prompt builder                                                        #
# ------------------------------------------------------------------ #

class TestPromptBuilder:

    def test_prompt_contains_all_directives(self, sample_misconfigs):
        prompt = _build_chain_prompt(sample_misconfigs)
        for m in sample_misconfigs:
            assert m.directive in prompt, f"Missing directive: {m.directive}"

    def test_prompt_contains_scores(self, sample_misconfigs):
        prompt = _build_chain_prompt(sample_misconfigs)
        # At least one score should appear
        assert "10.0" in prompt or "9." in prompt or "5." in prompt

    def test_prompt_sorted_by_score_descending(self, sample_misconfigs):
        prompt = _build_chain_prompt(sample_misconfigs)
        # User=root (10.0) should appear before ServerTokens (5.0)
        user_pos = prompt.find("User")
        tokens_pos = prompt.find("ServerTokens")
        assert user_pos < tokens_pos

    def test_prompt_not_empty(self, sample_misconfigs):
        prompt = _build_chain_prompt(sample_misconfigs)
        assert len(prompt) > 200

    def test_empty_misconfigs_produces_prompt(self):
        prompt = _build_chain_prompt([])
        assert "Total: 0" in prompt


# ------------------------------------------------------------------ #
# JSON extraction                                                       #
# ------------------------------------------------------------------ #

class TestExtractChainsJSON:

    def test_plain_json_array(self):
        data = [{"chain_id": "test", "misconfig_directives": ["A", "B"], "amplification": 1.3}]
        result = _extract_chains_json(json.dumps(data))
        assert result is not None
        assert len(result) == 1

    def test_markdown_fenced(self):
        data = [{"chain_id": "test", "misconfig_directives": ["A", "B"], "amplification": 1.3}]
        md = f"```json\n{json.dumps(data)}\n```"
        result = _extract_chains_json(md)
        assert result is not None

    def test_json_with_preamble(self):
        data = [{"chain_id": "test", "misconfig_directives": ["A", "B"], "amplification": 1.3}]
        text = f"Here are the chains I found:\n\n{json.dumps(data)}\n\nHope that helps!"
        result = _extract_chains_json(text)
        assert result is not None

    def test_empty_array(self):
        result = _extract_chains_json("[]")
        assert result == []

    def test_invalid_returns_none(self):
        assert _extract_chains_json("not json") is None
        assert _extract_chains_json("{ not an array }") is None

    def test_object_not_array_returns_none(self):
        # LLM returning object instead of array
        result = _extract_chains_json('{"chain_id": "test"}')
        assert result is None


# ------------------------------------------------------------------ #
# Chain validation                                                      #
# ------------------------------------------------------------------ #

class TestValidateChain:

    KNOWN = {"ServerTokens", "User", "AllowOverride", "TraceEnable", "LoadModule",
             "Options", "KeepAlive", "MaxKeepAliveRequests"}  # full set for normalisation tests

    def test_valid_chain_accepted(self):
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["ServerTokens", "User"],
            "amplification": 1.5,
            "justification": "Test justification.",
            "cross_target": False,
        }
        chain = _validate_chain(raw, self.KNOWN)
        assert chain is not None
        assert chain.chain_id == "test-chain"
        assert chain.amplification == 1.5

    def test_unknown_directives_filtered(self):
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["ServerTokens", "FakeDirective"],
            "amplification": 1.3,
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        # Only 1 valid directive → rejected (need >= 2)
        assert chain is None

    def test_only_one_valid_directive_rejected(self):
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["ServerTokens", "NotReal", "AlsoFake"],
            "amplification": 1.3,
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        assert chain is None

    def test_amplification_clamped_low(self):
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["ServerTokens", "User"],
            "amplification": 0.5,  # below 1.1
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        assert chain is not None
        assert chain.amplification >= 1.1

    def test_amplification_clamped_high(self):
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["ServerTokens", "User"],
            "amplification": 5.0,  # above 1.8
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        assert chain is not None
        assert chain.amplification <= 1.8

    def test_missing_chain_id_rejected(self):
        raw = {
            "misconfig_directives": ["ServerTokens", "User"],
            "amplification": 1.3,
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        assert chain is None

    def test_directive_with_value_normalised(self):
        """LLM writes 'Options Indexes' instead of 'Options' — must be normalised."""
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["Options Indexes", "AllowOverride All"],
            "amplification": 1.4,
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        assert chain is not None, "Should accept after normalising directive names"
        assert "Options" in chain.misconfig_directives
        assert "AllowOverride" in chain.misconfig_directives

    def test_loadmodule_with_value_normalised(self):
        """LLM writes 'LoadModule status_module' instead of 'LoadModule'."""
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["LoadModule status_module", "TraceEnable"],
            "amplification": 1.3,
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        assert chain is not None
        assert "LoadModule" in chain.misconfig_directives

    def test_keepalive_with_value_normalised(self):
        """LLM writes 'KeepAlive Off' instead of 'KeepAlive'."""
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["KeepAlive Off", "TraceEnable"],
            "amplification": 1.3,
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        assert chain is not None
        assert "KeepAlive" in chain.misconfig_directives

    def test_deduplication_after_normalisation(self):
        """If normalisation produces duplicates, they are deduplicated."""
        raw = {
            "chain_id": "test-chain",
            "misconfig_directives": ["Options Indexes", "Options FollowSymLinks"],
            "amplification": 1.3,
            "justification": "Test.",
        }
        chain = _validate_chain(raw, self.KNOWN)
        # Both normalise to "Options" → only 1 unique directive → rejected (< 2)
        assert chain is None


# ------------------------------------------------------------------ #
# Fallback loading                                                      #
# ------------------------------------------------------------------ #

class TestFallbackChains:

    def test_fallback_loads_chains_json(self):
        chains = _load_fallback_chains()
        assert len(chains) >= 5
        assert all(isinstance(c, AttackChain) for c in chains)

    def test_fallback_chains_have_valid_fields(self):
        chains = _load_fallback_chains()
        for c in chains:
            assert c.chain_id
            assert len(c.misconfig_directives) >= 2
            assert 1.0 <= c.amplification <= 2.0
            assert c.target_name == "apache-httpd"


# ------------------------------------------------------------------ #
# End-to-end generate_chains                                            #
# ------------------------------------------------------------------ #

class TestGenerateChains:

    def test_valid_llm_response_produces_chains(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm)
        assert len(chains) == 3

    def test_chain_ids_are_present(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm)
        ids = {c.chain_id for c in chains}
        assert "recon-to-rce" in ids
        assert "root-privilege-escalation" in ids

    def test_amplification_values_in_range(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm)
        for c in chains:
            assert 1.1 <= c.amplification <= 1.8

    def test_bad_llm_falls_back_to_chains_json(self, sample_misconfigs):
        """LLM que devolve lixo → fallback para chains.json."""
        llm = StubLLMClient(fixed_response="I cannot identify any chains, sorry.")
        chains = generate_chains(sample_misconfigs, llm, max_retries=1)
        # Should have fallen back to chains.json
        assert len(chains) >= 5
        fallback_ids = {c.chain_id for c in _load_fallback_chains()}
        chain_ids = {c.chain_id for c in chains}
        assert len(chain_ids & fallback_ids) > 0

    def test_empty_llm_array_falls_back(self, sample_misconfigs):
        """LLM que devolve [] (sem chains) → fallback."""
        llm = StubLLMClient(fixed_response="[]")
        chains = generate_chains(sample_misconfigs, llm, max_retries=1)
        assert len(chains) >= 5  # from fallback

    def test_merge_with_fallback_adds_missing(self, sample_misconfigs):
        """merge_with_fallback=True adiciona chains.json que o LLM não gerou."""
        # LLM só gera 1 chain
        one_chain = json.dumps([{
            "chain_id": "unique-llm-chain",
            "misconfig_directives": ["ServerTokens", "User"],
            "amplification": 1.4,
            "justification": "LLM chain.",
            "cross_target": False,
        }])
        llm = StubLLMClient(fixed_response=one_chain)
        chains = generate_chains(sample_misconfigs, llm, merge_with_fallback=True)
        ids = {c.chain_id for c in chains}
        # LLM chain + fallback chains (sem duplicados)
        assert "unique-llm-chain" in ids
        assert len(chains) > 1

    def test_no_duplicate_chain_ids(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm, merge_with_fallback=True)
        ids = [c.chain_id for c in chains]
        assert len(ids) == len(set(ids)), "Duplicate chain IDs found"

    def test_directives_are_subset_of_known(self, sample_misconfigs):
        """LLM não pode inventar directivas que não estão nas misconfigs."""
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm)
        known = {m.directive for m in sample_misconfigs}
        for chain in chains:
            for d in chain.misconfig_directives:
                assert d in known, f"Chain '{chain.chain_id}' references unknown directive: {d}"

    def test_empty_misconfigs_returns_empty(self):
        llm = StubLLMClient(fixed_response="[]")
        chains = generate_chains([], llm)
        assert chains == []

    def test_markdown_fenced_response_parsed(self, sample_misconfigs):
        """LLM que envolve JSON em markdown fences."""
        md_response = f"```json\n{VALID_LLM_RESPONSE}\n```"
        llm = StubLLMClient(fixed_response=md_response)
        chains = generate_chains(sample_misconfigs, llm)
        assert len(chains) == 3
