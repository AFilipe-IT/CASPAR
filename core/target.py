"""
core/target.py
--------------
Abstract interface that every plugin must implement.
The framework core is completely agnostic to the target; plugins provide
all target-specific knowledge through these 4 methods.

Design rules:
  - Adding a new target = create plugins/<name>/ with 4 files.
  - Zero modifications to this file or any other core module.
  - If a plugin cannot implement these 4 methods cleanly, the abstraction
    needs revision — not the plugin.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from core.models import Directive, SystemProfile, TargetMetadata


# ------------------------------------------------------------------ #
# Shared confidence levels for detection_confidence()                  #
# ------------------------------------------------------------------ #
# Use these constants in every plugin that overrides detection_confidence()
# so that comparisons are between *evidence types*, not arbitrary numbers.
# A plugin that returns CONFIDENCE_EXACT_FILENAME beats one that returns
# CONFIDENCE_SYNTAX_MARKER regardless of registration order.
CONFIDENCE_EXACT_FILENAME: int = 90  # Filename unambiguously identifies the target (nginx.conf, httpd.conf)
CONFIDENCE_SYNTAX_MARKER:  int = 70  # Content contains syntax only this target uses (<VirtualHost, server {)
CONFIDENCE_DIRECTORY:      int = 60  # File lives in a directory associated with this target (conf.d/, nginx/)
CONFIDENCE_WEAK:           int = 20  # Weak heuristic — generic keyword that may appear in comments


class Target(ABC):
    """
    Plugin contract.  Every plugin registers exactly one subclass of this.

    Lifecycle (called by the framework in this order):
      1. detect()       — is this plugin the right one for this input?
      2. parse_config() — extract normalised directives from the config.
      3. get_profile()  — infer AV and Au (worst-case, system-global).
      4. metadata()     — static info about this plugin.
    """

    # ------------------------------------------------------------------ #
    # 1. Detection                                                         #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def detect(self, path: str) -> bool:
        """
        Return True if this plugin can handle the file/directory at *path*.

        Must be deterministic and side-effect-free.  The framework calls
        detect() on every registered plugin and selects all that return True.
        If more than one plugin matches, the framework uses the one with the
        highest detection_confidence(path).
        """

    def detection_confidence(self, path: str) -> int:
        """
        Return how confident this plugin is that *path* belongs to it.

        Called only on plugins that already returned True from detect().
        The framework selects the candidate with the highest value; ties are
        broken by registration order (first registered wins).

        Use the CONFIDENCE_* constants defined in this module so that the
        comparison is between evidence types, not arbitrary numbers:
          CONFIDENCE_EXACT_FILENAME = 90  (e.g. nginx.conf, httpd.conf)
          CONFIDENCE_SYNTAX_MARKER  = 70  (e.g. <VirtualHost, server {)
          CONFIDENCE_DIRECTORY      = 60  (e.g. conf.d/, sites-available/)
          CONFIDENCE_WEAK           = 20  (single generic keyword in content)

        Default returns metadata().priority — backward-compatible for plugins
        that do not override this method.  Plugins SHOULD override if they
        share directory layouts or generic filenames with other plugins.
        """
        return self.metadata().priority

    # ------------------------------------------------------------------ #
    # 2. Configuration parsing                                             #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def parse_config(self, path: str) -> list[Directive]:
        """
        Read the configuration file(s) at *path* and return a flat list of
        normalised Directive objects.

        Each Directive captures one (name, value) pair.  Include-files and
        virtual-host blocks should be flattened into the same list; the
        directive's *context* field distinguishes where it was found.

        The parser must NOT perform any security evaluation here — that is
        the runtime engine's job.
        """

    # ------------------------------------------------------------------ #
    # 3. System profiling                                                  #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def get_profile(self, directives: list[Directive]) -> SystemProfile:
        """
        Infer the global AV and Au values for the system described by
        *directives*.

        Rules are deterministic (no LLM).  Examples:
          - If any Listen directive references a non-loopback address →
            AV = "Network".
          - If any endpoint lacks authentication → Au = "None".

        Worst-case principle: the returned values must reflect the most
        exposed state observable in the directive set.
        """

    # ------------------------------------------------------------------ #
    # 4. Plugin metadata                                                   #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def metadata(self) -> TargetMetadata:
        """
        Return static metadata describing this plugin.

        Called once during plugin registration.  Must not perform I/O.
        """
