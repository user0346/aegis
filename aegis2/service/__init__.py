"""Service layer — runs as Windows Service under LocalSystem.

Entrypoint via bin/aegis_core.py. Hosts:
  - Orchestrator (all watcher modules)
  - IPC Named-Pipe Server
  - TamperGuard (self-restart watchdog)
  - IntegrityVerifier (hash-pin checker)
"""
