"""AEGIS V2 — Autonomous Endpoint Guardian Intelligence System.

V2 splits the previous monolith into:
  - service/  : headless Windows-Service core (LocalSystem, boot-start)
  - ui/       : Qt + QtWebEngine companion (user process, login-start)
  - voice/    : Porcupine wake-word + Cloud-STT pipeline (in UI proc)
  - shared/   : code that both Service and UI need
  - setup/    : installer scripts (service registration, scheduled task)
"""

__version__ = "2.4.1"
__all__ = ["__version__"]
