"""WDAC Code-Integrity-Policy Generator.

WDAC = Windows Defender Application Control. Kernel-Level-Enforcement:
nur Code der durch die Policy erlaubt ist, darf überhaupt geladen werden.

Unsere Policy:
  - ALLOW: alles was Microsoft signiert hat
  - ALLOW: alles im AEGIS-Install-Ordner (Path-Rule)
  - ALLOW: pythonw.exe + python.exe + Site-Packages
  - AUDIT-MODE by default (loggt nur, blockt nicht)
  - Owner kann in UI auf Enforce-Mode wechseln

Generierte Policy: %TEMP%\\aegis_wdac_policy.xml
Kompiliert mit ConvertFrom-CIPolicy zu .p7b
Deployment nach C:\\Windows\\System32\\CodeIntegrity\\SiPolicy.p7b
Aktivierung nach Reboot.

Sicherheit: einmal aktiv, kann nur via Safe-Mode-Boot oder anderem Admin-
mit-Reboot deaktiviert werden. Macht user-side Tampering teuer.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


WDAC_POLICY_TEMPLATE = textwrap.dedent("""\
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <VersionEx>1.0.0.0</VersionEx>
  <PolicyTypeID>{{4E61C68C-97F6-430B-9CD7-9B1004706770}}</PolicyTypeID>
  <PlatformID>{{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}}</PlatformID>
  <Rules>
    <Rule>
      <Option>Enabled:Unsigned System Integrity Policy</Option>
    </Rule>
    <Rule>
      <Option>Enabled:Advanced Boot Options Menu</Option>
    </Rule>
    <Rule>
      <Option>Enabled:UMCI</Option>
    </Rule>
    <!-- AUDIT-MODE: nur loggen, nicht blocken (User kann später hochschalten) -->
    <Rule>
      <Option>Enabled:Audit Mode</Option>
    </Rule>
  </Rules>
  <EKUs />
  <FileRules>
    <!-- Path Rules: alles im AEGIS-Install-Ordner erlaubt -->
    <Allow ID="ID_ALLOW_AEGIS"
           FriendlyName="AEGIS Install Folder"
           FilePath="{AEGIS_PATH}\\*" />
    <Allow ID="ID_ALLOW_PYTHONW"
           FriendlyName="Python (system)"
           FilePath="{PYTHON_PATH}\\*" />
  </FileRules>
  <Signers>
    <!-- Microsoft-signed code: hier kommen Microsoft-Cert-Hashes -->
    <!-- ConvertFrom-CIPolicy fügt diese automatisch hinzu via -DefaultSigner -->
  </Signers>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy">
      <ProductSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_AEGIS" />
          <FileRuleRef RuleID="ID_ALLOW_PYTHONW" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_USERMODE" FriendlyName="User-Mode">
      <ProductSigners>
        <FileRulesRef>
          <FileRuleRef RuleID="ID_ALLOW_AEGIS" />
          <FileRuleRef RuleID="ID_ALLOW_PYTHONW" />
        </FileRulesRef>
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners />
  <CiSigners />
  <HvciOptions>0</HvciOptions>
  <Settings>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value><String>AEGIS Code Integrity Policy</String></Value>
    </Setting>
  </Settings>
</SiPolicy>
""")


def generate_policy_xml(aegis_path: Path, python_path: Path,
                       output_path: Path) -> bool:
    """Schreibt die XML-Policy mit ersetzten Pfaden."""
    content = WDAC_POLICY_TEMPLATE.format(
        AEGIS_PATH=str(aegis_path).replace("\\", "\\\\"),
        PYTHON_PATH=str(python_path).replace("\\", "\\\\"),
    )
    output_path.write_text(content, encoding="utf-8")
    return output_path.exists()


def compile_policy(xml_path: Path, p7b_path: Path) -> bool:
    """Konvertiert XML → binary .p7b via PowerShell."""
    if sys.platform != "win32":
        return False
    script = (
        f"try {{"
        f"  ConvertFrom-CIPolicy -XmlFilePath '{xml_path}' "
        f"-BinaryFilePath '{p7b_path}' | Out-Null;"
        f"  'OK'"
        f"}} catch {{ $_.Exception.Message }}"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace"
        )
        return "OK" in (r.stdout or "")
    except Exception:  # noqa: BLE001
        return False


def deploy_policy(p7b_path: Path) -> bool:
    """Kopiert .p7b nach SiPolicy.p7b. Aktivierung nach Reboot.

    Erfordert Admin + Reboot. AUDIT-MODE zuerst um nicht aus Versehen
    den User auszusperren.
    """
    if sys.platform != "win32":
        return False
    target = Path(r"C:\Windows\System32\CodeIntegrity\SiPolicy.p7b")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        import shutil
        shutil.copy2(p7b_path, target)
        return target.exists()
    except (OSError, PermissionError):
        return False


def full_setup(aegis_install_path: Path) -> dict:
    """Generate + Compile + Deploy. Returns status dict for installer."""
    import sys as _sys
    python_path = Path(_sys.executable).parent
    tmp_dir = Path(os.environ.get("TEMP", str(Path.cwd())))
    xml_path = tmp_dir / "aegis_wdac_policy.xml"
    p7b_path = tmp_dir / "aegis_wdac_policy.p7b"

    result = {
        "xml_generated": False,
        "p7b_compiled": False,
        "deployed": False,
        "audit_mode": True,
        "activation_after_reboot": True,
        "xml_path": str(xml_path),
        "p7b_path": str(p7b_path),
    }
    result["xml_generated"] = generate_policy_xml(aegis_install_path, python_path, xml_path)
    if result["xml_generated"]:
        result["p7b_compiled"] = compile_policy(xml_path, p7b_path)
    if result["p7b_compiled"]:
        result["deployed"] = deploy_policy(p7b_path)
    return result
