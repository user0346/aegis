"""Watcher modules — all share the same Module base from .base.

V2 changes vs V1:
  - No PyQt or UI dependencies anywhere in this layer.
  - Each module emits Events to a passed-in EventBus.
  - Modules support both poll-based and event-based loops.
"""
