<#
.SYNOPSIS
    AEGIS - Ein-Zeilen-Installer fuer Windows (ohne SmartScreen/Smart-App-Control-Block).

.DESCRIPTION
    Holt das neueste signierte AEGIS-Release von GitHub, installiert die Pakete,
    richtet Autostart + Verknuepfung ein und startet AEGIS.

    Als In-Memory-Skript (irm | iex) ausgefuehrt entsteht KEINE Datei mit
    "Mark-of-the-Web" -> Windows Smart App Control / SmartScreen blockt NICHT.
    Das ist der saubere Weg, solange die .exe noch nicht Authenticode-signiert ist.

    Ein-Zeiler (in PowerShell):
      irm https://raw.githubusercontent.com/user0346/aegis/main/install.ps1 | iex

    Schalter (Umgebungsvariablen, da `iex` keine Parameter durchreicht):
      $env:AEGIS_HOME    = 'D:\Pfad'   # Installationsort (Default %LOCALAPPDATA%\Programs\AEGIS)
      $env:AEGIS_NOSTART = '1'         # nach dem Setup NICHT automatisch starten
#>

$ErrorActionPreference = 'Stop'
$RepoApi = 'https://api.github.com/repos/user0346/aegis/releases/latest'

function _i   ($m) { Write-Host "[AEGIS]  $m" -ForegroundColor Cyan }
function _ok  ($m) { Write-Host "[ok]     $m" -ForegroundColor Green }
function _fail($m) { Write-Host "[fehler] $m" -ForegroundColor Red; exit 1 }

_i "AEGIS-Installer startet ..."

# 1) ---------- Windows-Check ----------
if ($PSVersionTable.Platform -and $PSVersionTable.Platform -ne 'Win32NT') {
    _fail "Dieser Installer ist fuer Windows. (Linux/macOS: siehe README im Repo.)"
}
$build = [Environment]::OSVersion.Version.Build
if ($build -lt 17763) { _fail "Windows 10 1809 (Build 17763) oder neuer noetig. Erkannt: $build." }
_ok "Windows Build $build"

# 2) ---------- Python 3.11+ (py-Launcher bevorzugt, sonst via winget) ----------
function _resolve_python {
    # Sammelt KONKRETE python.exe-Kandidaten, OHNE die Microsoft-Store-Alias-Stubs
    # (WindowsApps) aufzurufen -- die oeffnen sonst den "Wie moechten Sie 'python'
    # oeffnen?"-Dialog und liefern nichts.
    $cands = @()

    # 1) py-Launcher (kennt alle registrierten Pythons) -- auf PATH oder an Standard-Orten.
    $pyLauncher = $null
    $g = Get-Command py -ErrorAction SilentlyContinue
    if ($g -and $g.Source -and (Test-Path $g.Source)) { $pyLauncher = $g.Source }
    if (-not $pyLauncher) {
        foreach ($p in @("$env:WINDIR\py.exe", "$env:LOCALAPPDATA\Programs\Python\Launcher\py.exe")) {
            if (Test-Path $p) { $pyLauncher = $p; break }
        }
    }
    if ($pyLauncher) {
        try {
            $e = (& $pyLauncher -3 -c "import sys;print(sys.executable)" 2>$null)
            if ($e) { $cands += "$e".Trim() }
        } catch { }
    }

    # 2) python/python3 auf PATH -- ABER die Store-Alias-Stubs (WindowsApps) auslassen.
    foreach ($n in @('python', 'python3')) {
        foreach ($c in (Get-Command $n -All -ErrorAction SilentlyContinue)) {
            if ($c.Source -and ($c.Source -notmatch 'WindowsApps') -and (Test-Path $c.Source)) {
                $cands += $c.Source
            }
        }
    }

    # 3) Bekannte Installationsorte direkt absuchen (falls nichts auf PATH liegt).
    $globs = @(
        "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
        "$env:PROGRAMFILES\Python3*\python.exe",
        "${env:ProgramFiles(x86)}\Python3*\python.exe"
    )
    foreach ($gl in $globs) {
        foreach ($f in (Get-ChildItem -Path $gl -ErrorAction SilentlyContinue)) { $cands += $f.FullName }
    }

    # Kandidaten pruefen: echte python.exe, Version >= 3.11 (hoechste zuerst).
    foreach ($exe in ($cands | Where-Object { $_ } | Select-Object -Unique | Sort-Object -Descending)) {
        if (($exe -match 'WindowsApps') -or -not (Test-Path $exe)) { continue }
        try {
            $ver = (& $exe -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null)
            if ($ver -match '^3\.(\d+)$' -and [int]$Matches[1] -ge 11) { return $exe }
        } catch { }
    }
    return $null
}

_i "Suche Python 3.11+ ..."
$pyExe = _resolve_python
if (-not $pyExe) {
    _i "Python 3.11+ nicht gefunden - versuche winget ..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        & winget install --id Python.Python.3.13 --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $userPath    = [Environment]::GetEnvironmentVariable('Path', 'User')
        $env:Path = [Environment]::ExpandEnvironmentVariables("$machinePath;$userPath")
        $pyExe = _resolve_python
    }
    if (-not $pyExe) {
        _fail ("Python 3.11+ nicht gefunden und Auto-Installation fehlgeschlagen. " +
               "Installiere von https://www.python.org/downloads/ ('Add python.exe to PATH' anhaken), " +
               "dann erneut: irm https://raw.githubusercontent.com/user0346/aegis/main/install.ps1 | iex")
    }
}
_ok "Python: $pyExe"

# 3) ---------- Neuestes Release holen + entpacken (KEIN Mark-of-the-Web) ----------
$target = if ($env:AEGIS_HOME) { $env:AEGIS_HOME } else { Join-Path $env:LOCALAPPDATA 'Programs\AEGIS' }

_i "Hole neuestes AEGIS-Release von GitHub ..."
$rel = Invoke-RestMethod -Uri $RepoApi -Headers @{ 'User-Agent' = 'AEGIS-Installer' }
$asset = $rel.assets | Where-Object { $_.name -eq 'AEGIS.zip' } | Select-Object -First 1
if (-not $asset) { _fail "Kein 'AEGIS.zip' im neuesten Release ($($rel.tag_name)) gefunden." }

$tmpZip = Join-Path $env:TEMP "AEGIS_$($rel.tag_name).zip"
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tmpZip -UseBasicParsing
_ok "Geladen: $($rel.tag_name) ($([math]::Round((Get-Item $tmpZip).Length / 1MB, 1)) MB)"

$stage = Join-Path $env:TEMP ("AEGIS_stage_" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
Expand-Archive -Path $tmpZip -DestinationPath $stage -Force
# ZIP hat evtl. einen Top-Level-Ordner -> den Ordner mit bin\aegis_app.py finden.
$root = if (Test-Path (Join-Path $stage 'bin\aegis_app.py')) {
    $stage
} else {
    (Get-ChildItem $stage -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'bin\aegis_app.py') } |
        Select-Object -First 1).FullName
}
if (-not $root) { _fail "AEGIS-Quellen (bin\aegis_app.py) im ZIP nicht gefunden." }

New-Item -ItemType Directory -Force -Path $target | Out-Null
_i "Platziere AEGIS nach $target ..."
Copy-Item -Path (Join-Path $root '*') -Destination $target -Recurse -Force
Remove-Item $tmpZip, $stage -Recurse -Force -ErrorAction SilentlyContinue
_ok "AEGIS liegt unter $target"

# 4) ---------- Pakete ----------
Push-Location $target
try {
    _i "Installiere benoetigte Pakete (beim ersten Mal ein paar Minuten) ..."
    & $pyExe -m pip install --disable-pip-version-check -r requirements_v2.txt
    if ($LASTEXITCODE -ne 0) { _fail "Paket-Installation fehlgeschlagen. Pruefe die Internetverbindung und starte erneut." }
    _ok "Pakete installiert"

    # 5) ---------- Einrichten (Autostart, Verknuepfung, Integritaets-Basis) ----------
    _i "Richte AEGIS ein (Autostart, Verknuepfung, Integritaets-Basis) ..."
    & $pyExe "bin\aegis_app.py" --setup

    # 6) ---------- Starten (still via pythonw, falls vorhanden) ----------
    if (-not $env:AEGIS_NOSTART) {
        $pyw = Join-Path (Split-Path $pyExe) 'pythonw.exe'
        if (-not (Test-Path $pyw)) { $pyw = $pyExe }
        _i "Starte AEGIS ..."
        Start-Process -FilePath $pyw -ArgumentList (Join-Path $target 'bin\aegis_app.py') -WindowStyle Hidden
    }
} finally {
    Pop-Location
}

Write-Host ""
_ok "Fertig - AEGIS laeuft und startet ab jetzt automatisch mit Windows."
Write-Host "         Ordner: $target" -ForegroundColor Green
Write-Host "         Ueber das Tray-Icon kannst du es oeffnen oder den Schutz stoppen." -ForegroundColor Green
Write-Host "         Sprachsteuerung + lokale KI aktivierst du in der App unter Einstellungen." -ForegroundColor Green
