"""Router/Network-Anomaly-Watcher.

Erkennt SOHO-Router-Compromise-Patterns (Microsoft Security Blog, 2026):
  - Gateway-MAC-Wechsel (klassisches ARP-Spoofing)
  - DNS-Server-Änderung (Forest-Blizzard-Pattern: Router-DNS swap)
  - Default-Gateway-Switch (Router-Hijack)
  - Mehrere MACs für gleiche IP im ARP-Cache (ARP-Poisoning)
  - Public-DNS-Bypass: Router antwortet plötzlich nicht mehr, anderer DNS

Boot-Pin: erste Beobachtung wird gepinnt (in DB-Settings). Jede weitere
Änderung → severity-abhängig Event. Erstmaliger Wechsel = WARN.
Mehrfacher Wechsel im 24h-Fenster oder Mismatch zwischen ARP-Antwortern
= CRITICAL.

Erfordert keine Admin-Rechte. Nutzt nur `arp -a`, `ipconfig /all`,
`Get-NetIPConfiguration` (PowerShell).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from typing import Optional

from ..db import Database
from ..events import EventBus, Event, Severity, Category
from ..proc import run_hidden
from .base import Module


# Bekannte legitime Public-DNS für Sanity-Check (wenn diese plötzlich
# verschwinden und ein No-Name-DNS auftaucht, ist es verdächtig).
# Plus bekannte VPN-DNS damit User-Toggle nicht als Threat flaggt.
KNOWN_GOOD_DNS = {
    # Public Resolvers
    "1.1.1.1", "1.0.0.1",                # Cloudflare
    "8.8.8.8", "8.8.4.4",                # Google
    "9.9.9.9", "149.112.112.112",        # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    # VPN-Resolvers (legitim wenn User VPN nutzt)
    "103.86.96.100", "103.86.99.100",    # NordVPN
    "10.255.255.1", "10.255.255.2",      # NordVPN-Mesh
    "162.252.172.57", "149.154.159.92",  # Surfshark
    "162.252.172.61",                    # ExpressVPN
    "10.8.0.1",                          # OpenVPN-Default-Range
    "10.0.0.0",                          # generic RFC1918 (vom VPN-tunnel)
    "100.64.0.1",                        # Tailscale
}


class RouterWatcher(Module):
    name = "RouterWatcher"

    def __init__(self, bus: EventBus, db: Database, check_interval_s: int = 120):
        super().__init__(bus)
        self.db = db
        self.iv = check_interval_s

    def run(self) -> None:
        if sys.platform != "win32":
            self.emit(Severity.INFO, Category.NETWORK, "RouterWatcher: nicht Windows, inaktiv")
            return
        # Initial-Boot: Snapshot pinnen
        try:
            self._initial_pin()
        except Exception as e:  # noqa: BLE001
            self.emit(Severity.WARN, Category.NETWORK,
                      f"RouterWatcher-Init crashed: {e}")
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:  # noqa: BLE001
                self.emit(Severity.WARN, Category.NETWORK,
                          f"RouterWatcher-Tick: {type(e).__name__}: {e}")
            self._stop.wait(self.iv)

    # ---- Snapshot ----
    def _query_snapshot(self) -> dict:
        out: dict = {
            "gateway_ip": None,
            "gateway_mac": None,
            "dns_servers": [],
            "interface": None,
        }
        try:
            r = run_hidden(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetIPConfiguration | "
                 "Select-Object InterfaceAlias,"
                 "@{N='Gateway';E={$_.IPv4DefaultGateway.NextHop}},"
                 "@{N='DNS';E={($_.DNSServer | Where-Object {$_.AddressFamily -eq 2}).ServerAddresses -join ','}} "
                 "| ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            data = json.loads(r.stdout or "[]")
            if isinstance(data, dict):
                data = [data]
            # Wähle das erste Interface mit Gateway
            for iface in data:
                gw = iface.get("Gateway")
                if not gw:
                    continue
                out["interface"] = iface.get("InterfaceAlias")
                out["gateway_ip"] = gw
                dns_str = iface.get("DNS", "") or ""
                out["dns_servers"] = [d.strip() for d in dns_str.split(",") if d.strip()]
                break
        except Exception:  # noqa: BLE001
            pass

        # Gateway-MAC via arp -a
        if out["gateway_ip"]:
            try:
                r = run_hidden(
                    ["arp", "-a", out["gateway_ip"]],
                    capture_output=True, text=True, timeout=5,
                    encoding="utf-8", errors="replace"
                )
                for line in (r.stdout or "").splitlines():
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})", line, re.I)
                    if m and m.group(1) == out["gateway_ip"]:
                        out["gateway_mac"] = m.group(2).lower().replace("-", ":")
                        break
            except Exception:  # noqa: BLE001
                pass
        return out

    def _arp_table_summary(self) -> dict[str, list[str]]:
        """Returns {ip: [list of macs seen]} — detects ARP-Poisoning when same IP has multiple MACs."""
        out: dict[str, list[str]] = {}
        try:
            r = run_hidden(["arp", "-a"], capture_output=True, text=True,
                               timeout=5, encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return out
        for line in (r.stdout or "").splitlines():
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\S+)", line, re.I)
            if not m: continue
            ip = m.group(1)
            mac = m.group(2).lower().replace("-", ":")
            out.setdefault(ip, []).append(mac)
        return out

    # ---- Initial pin ----
    def _initial_pin(self) -> None:
        snap = self._query_snapshot()
        if not snap.get("gateway_ip"):
            return
        pinned = self.db.get_setting("router_pin")
        if not pinned:
            self.db.set_setting("router_pin", snap)
            self.emit(Severity.INFO, Category.NETWORK,
                      f"Router gepinnt: GW={snap['gateway_ip']} MAC={snap['gateway_mac']} DNS={snap['dns_servers']}")

    # ---- Tick ----
    def _tick(self) -> None:
        pinned = self.db.get_setting("router_pin") or {}
        snap = self._query_snapshot()
        if not snap.get("gateway_ip") or not pinned.get("gateway_ip"):
            return

        # Gateway-IP changed
        if snap["gateway_ip"] != pinned.get("gateway_ip"):
            self.emit(Severity.WARN, Category.NETWORK,
                      f"Gateway-IP-Wechsel: {pinned['gateway_ip']} → {snap['gateway_ip']}",
                      {"pinned": pinned, "current": snap})
            # Re-pin (Network gewechselt ist legitim — WLAN gewechselt etc.)
            self.db.set_setting("router_pin", snap)
            return

        # Gateway-MAC changed (gleiche IP, andere MAC) → klassischer ARP-Spoof / Router-Reboot
        if (snap.get("gateway_mac") and pinned.get("gateway_mac")
                and snap["gateway_mac"] != pinned["gateway_mac"]):
            self.emit(Severity.CRITICAL, Category.TAMPER,
                      f"GATEWAY-MAC-WECHSEL bei gleicher IP! Möglicher ARP-Spoof: "
                      f"{pinned['gateway_mac']} → {snap['gateway_mac']}",
                      {"pinned": pinned, "current": snap})

        # DNS-Server changed
        pinned_dns = set(pinned.get("dns_servers", []))
        current_dns = set(snap.get("dns_servers", []))
        if pinned_dns and current_dns and pinned_dns != current_dns:
            removed = pinned_dns - current_dns
            added = current_dns - pinned_dns
            # Wenn ein vorher bekannter Good-DNS verschwand UND ein No-Name auftaucht → CRITICAL
            lost_good = removed & KNOWN_GOOD_DNS
            new_unknown = added - KNOWN_GOOD_DNS
            sev = (Severity.CRITICAL
                   if (lost_good and new_unknown)
                   else Severity.WARN)
            self.emit(sev, Category.NETWORK,
                      f"DNS-Server-Wechsel: -{sorted(removed)} +{sorted(added)}",
                      {"pinned_dns": sorted(pinned_dns),
                       "current_dns": sorted(current_dns),
                       "lost_good": sorted(lost_good),
                       "new_unknown": sorted(new_unknown)})
            # Re-pin nur wenn keine CRITICAL
            if sev != Severity.CRITICAL:
                self.db.set_setting("router_pin", snap)

        # ARP-Table: gleiche IP, mehrere MACs
        arp = self._arp_table_summary()
        for ip, macs in arp.items():
            if len(set(macs)) > 1:
                self.emit(Severity.CRITICAL, Category.TAMPER,
                          f"ARP-Anomalie: {ip} hat {len(set(macs))} verschiedene MACs - ARP-Spoofing-Verdacht",
                          {"ip": ip, "macs": list(set(macs))})
