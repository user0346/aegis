"""Shared layer — code that runs in both the Service-Core AND the UI-Shell.

Anything that has a hard PyQt or audio dependency does NOT belong here.
Pure-Python only (sqlite3, stdlib, psutil, requests, watchdog).
"""
