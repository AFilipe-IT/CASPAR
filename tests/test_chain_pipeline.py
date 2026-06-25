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

from config_assessment.core.ccss import base_score, temporal_score
from config_assessment.build.llm_client import StubLLMClient
from config_assessment.core.models import AttackChain, Misconfiguration
from pathlib import Path

from config_assessment.build.chain_pipeline import (
    _build_chain_prompt,
    _extract_chains_json,
    _load_curated_chains,
    _validate_chain,
    generate_chains,
)

# Sentinel path with no chains.json → forces the LLM bootstrap path.
# (generate_chains is JSON-first: a real chains.json short-circuits the LLM.)
_NO_JSON = Path("/nonexistent/__no_chains__.json")
_APACHE_JSON = Path(__file__).resolve().parents[1] / "config_assessment" / "plugins" / "apache_httpd" / "chains.json"


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

class TestCuratedChains:

    def test_curated_loads_apache_chains_json(self):
        chains = _load_curated_chains(_APACHE_JSON)
        assert len(chains) == 11  # curated set (see chains.json)
        assert all(isinstance(c, AttackChain) for c in chains)

    def test_curated_chains_have_valid_fields(self):
        chains = _load_curated_chains(_APACHE_JSON)
        for c in chains:
            assert c.chain_id
            assert len(c.misconfig_directives) >= 2
            assert 1.0 <= c.amplification <= 2.0
            assert c.target_name == "apache-httpd"

    def test_curated_missing_file_returns_empty(self):
        assert _load_curated_chains(_NO_JSON) == []


# ------------------------------------------------------------------ #
# End-to-end generate_chains                                            #
# ------------------------------------------------------------------ #

class TestGenerateChainsJsonFirst:
    """JSON-first semantics: a curated chains.json is the source of truth and
    the LLM is never called when it exists (deterministic, reproducible)."""

    def test_curated_json_used_and_llm_ignored(self, sample_misconfigs):
        # Stub LLM returns junk; it must be ignored because the JSON exists.
        llm = StubLLMClient(fixed_response="garbage, no chains here")
        chains = generate_chains(sample_misconfigs, llm, chains_json_path=_APACHE_JSON)
        ids = {c.chain_id for c in chains}
        # Curated chains whose directives are a subset of sample_misconfigs.
        assert "info-disclosure-chain" in ids        # ServerTokens, ServerSignature
        assert "directory-traversal-chain" in ids    # Options, AllowOverride
        assert chains, "Curated JSON should yield chains"

    def test_curated_chains_filtered_by_known_directives(self, sample_misconfigs):
        # sample_misconfigs lacks e.g. Group/Timeout-trio, so chains needing
        # absent directives are dropped — same validity rule as the LLM path.
        llm = StubLLMClient(fixed_response="[]")
        chains = generate_chains(sample_misconfigs, llm, chains_json_path=_APACHE_JSON)
        known = {m.directive for m in sample_misconfigs}
        for c in chains:
            assert set(c.misconfig_directives) <= known, (
                f"Chain '{c.chain_id}' references directives absent from the bank"
            )

    def test_no_duplicate_chain_ids(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response="[]")
        chains = generate_chains(sample_misconfigs, llm, chains_json_path=_APACHE_JSON)
        ids = [c.chain_id for c in chains]
        assert len(ids) == len(set(ids)), "Duplicate chain IDs found"


class TestGenerateChainsLLMBootstrap:
    """LLM-bootstrap path: only reached when there is no curated chains.json
    (e.g. a brand-new target). Forced here with a nonexistent JSON path."""

    def test_valid_llm_response_produces_chains(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm, chains_json_path=_NO_JSON)
        assert len(chains) == 3

    def test_chain_target_name_from_misconfigs(self):
        """Regression: LLM-bootstrapped chains must carry the misconfigs' target,
        not a hardcoded 'apache-httpd' (that bug sent PostgreSQL chains to the
        wrong target, so they vanished from get_attack_chains('postgresql'))."""
        import json
        from config_assessment.core.models import Misconfiguration
        ms = [
            Misconfiguration(target_name="postgresql", directive="ssl",
                             bad_value="off", good_value="on", ac="L", c="P",
                             i="N", a="N", base_score=5.0, temporal_score=5.0),
            Misconfiguration(target_name="postgresql", directive="log_connections",
                             bad_value="off", good_value="on", ac="L", c="P",
                             i="N", a="N", base_score=5.0, temporal_score=5.0),
        ]
        resp = json.dumps([{
            "chain_id": "pg-chain",
            "misconfig_directives": ["ssl", "log_connections"],
            "amplification": 1.4, "justification": "x", "cross_target": False,
        }])
        chains = generate_chains(ms, StubLLMClient(fixed_response=resp),
                                 chains_json_path=_NO_JSON)
        assert chains and all(c.target_name == "postgresql" for c in chains)

    def test_chain_ids_are_present(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm, chains_json_path=_NO_JSON)
        ids = {c.chain_id for c in chains}
        assert "recon-to-rce" in ids
        assert "root-privilege-escalation" in ids

    def test_bootstrap_writes_chains_json_for_review(self, sample_misconfigs, tmp_path):
        # Correção 3: an LLM-bootstrapped build must persist chains.json so the
        # next build is deterministic and the human can review it.
        out = tmp_path / "plugins" / "demo" / "chains.json"
        assert not out.exists()
        chains = generate_chains(sample_misconfigs,
                                 StubLLMClient(fixed_response=VALID_LLM_RESPONSE),
                                 chains_json_path=out)
        assert chains and out.exists()

        # The written file round-trips and a second build is JSON-first (offline).
        reloaded = _load_curated_chains(out)
        assert {c.chain_id for c in reloaded} == {c.chain_id for c in chains}
        # Second call with a StubLLM that would error proves JSON short-circuits.
        again = generate_chains(sample_misconfigs,
                                StubLLMClient(fixed_response="garbage no json"),
                                chains_json_path=out)
        assert {c.chain_id for c in again} == {c.chain_id for c in chains}

    def test_amplification_values_in_range(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm, chains_json_path=_NO_JSON)
        for c in chains:
            assert 1.1 <= c.amplification <= 1.8

    def test_bad_llm_no_json_returns_empty(self, sample_misconfigs):
        """LLM lixo + sem chains.json → vazio (nada a que recorrer)."""
        llm = StubLLMClient(fixed_response="I cannot identify any chains, sorry.")
        chains = generate_chains(
            sample_misconfigs, llm, max_retries=1, chains_json_path=_NO_JSON
        )
        assert chains == []

    def test_empty_llm_array_no_json_returns_empty(self, sample_misconfigs):
        llm = StubLLMClient(fixed_response="[]")
        chains = generate_chains(
            sample_misconfigs, llm, max_retries=1, chains_json_path=_NO_JSON
        )
        assert chains == []

    def test_directives_are_subset_of_known(self, sample_misconfigs):
        """LLM não pode inventar directivas que não estão nas misconfigs."""
        llm = StubLLMClient(fixed_response=VALID_LLM_RESPONSE)
        chains = generate_chains(sample_misconfigs, llm, chains_json_path=_NO_JSON)
        known = {m.directive for m in sample_misconfigs}
        for chain in chains:
            for d in chain.misconfig_directives:
                assert d in known, f"Chain '{chain.chain_id}' references unknown directive: {d}"

    def test_empty_misconfigs_returns_empty(self):
        llm = StubLLMClient(fixed_response="[]")
        chains = generate_chains([], llm, chains_json_path=_NO_JSON)
        assert chains == []

    def test_markdown_fenced_response_parsed(self, sample_misconfigs):
        """LLM que envolve JSON em markdown fences."""
        md_response = f"```json\n{VALID_LLM_RESPONSE}\n```"
        llm = StubLLMClient(fixed_response=md_response)
        chains = generate_chains(sample_misconfigs, llm, chains_json_path=_NO_JSON)
        assert len(chains) == 3
