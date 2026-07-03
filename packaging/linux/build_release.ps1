param(
    [string]$Version = "0.1.54-beta",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

$PackagingDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentRoot = Resolve-Path (Join-Path $PackagingDir "..\..")
$PackagingRoot = Resolve-Path (Join-Path $PackagingDir "..")
if (-not $OutputDir) {
    $OutputDir = Join-Path $AgentRoot "dist"
}

$BuildRoot = Join-Path $PackagingRoot "build\linux"
Remove-Item -Recurse -Force $BuildRoot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $BuildRoot, $OutputDir | Out-Null

$Python = Get-Command py -ErrorAction SilentlyContinue
if ($Python) {
    $PythonExe = "py"
    $PythonArgs = @("-3")
} else {
    $Python = Get-Command python -ErrorAction SilentlyContinue
    $BundledPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
    if ($Python) {
        $PythonExe = "python"
        $PythonArgs = @()
    } elseif (Test-Path $BundledPython) {
        $PythonExe = $BundledPython
        $PythonArgs = @()
    } else {
        throw "Python 3 is required to create Debian archives with Unix permissions."
    }
}

$PackageId = "pbxpulse-agent"
$ServiceName = "pbxpulse-agent"
$SourcePackageName = "PBXPulseAgent-$Version-linux-source-installer"
$AgentEntries = @(
    "pbxpulse_agent",
    "scripts",
    "requirements.txt",
    ".env.example",
    "README.md",
    "CONNECTORS.md",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.lan.yml",
    "docker-compose.parent-example.yml"
)

function Copy-AgentPayload([string]$DestinationRoot) {
    New-Item -ItemType Directory -Force -Path $DestinationRoot | Out-Null
    foreach ($Entry in $AgentEntries) {
        $Source = Join-Path $AgentRoot $Entry
        if (-not (Test-Path $Source)) {
            continue
        }
        $Destination = Join-Path $DestinationRoot $Entry
        if ((Get-Item $Source).PSIsContainer) {
            Copy-Item -Recurse -Force $Source $Destination
        } else {
            Copy-Item -Force $Source $Destination
        }
    }

    Get-ChildItem -Path $DestinationRoot -Recurse -Directory -Filter "__pycache__" |
        Remove-Item -Recurse -Force
    Get-ChildItem -Path $DestinationRoot -Recurse -File -Include "*.pyc", "*.pyo" |
        Remove-Item -Force
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Write-ArEntry($Stream, [string]$Name, [byte[]]$Bytes) {
    $NameField = ($Name + "/").PadRight(16).Substring(0, 16)
    $Timestamp = "0".PadRight(12)
    $Owner = "0".PadRight(6)
    $Group = "0".PadRight(6)
    $Mode = "100644".PadRight(8)
    $Size = ([string]$Bytes.Length).PadRight(10)
    $Header = "$NameField$Timestamp$Owner$Group$Mode$Size``n"
    $Header = $Header.Substring(0, 58) + [char]0x60 + [char]0x0A
    $HeaderBytes = [System.Text.Encoding]::ASCII.GetBytes($Header)
    $Stream.Write($HeaderBytes, 0, $HeaderBytes.Length)
    $Stream.Write($Bytes, 0, $Bytes.Length)
    if (($Bytes.Length % 2) -ne 0) {
        $Stream.WriteByte(10)
    }
}

function New-DebArchive([string]$DebPath, [string]$DebianBinaryPath, [string]$ControlTarPath, [string]$DataTarPath) {
    $Signature = [System.Text.Encoding]::ASCII.GetBytes("!<arch>`n")
    $DebianBinary = [System.IO.File]::ReadAllBytes($DebianBinaryPath)
    $ControlTar = [System.IO.File]::ReadAllBytes($ControlTarPath)
    $DataTar = [System.IO.File]::ReadAllBytes($DataTarPath)
    $Stream = [System.IO.File]::Create($DebPath)
    try {
        $Stream.Write($Signature, 0, $Signature.Length)
        Write-ArEntry $Stream "debian-binary" $DebianBinary
        Write-ArEntry $Stream "control.tar.gz" $ControlTar
        Write-ArEntry $Stream "data.tar.gz" $DataTar
    } finally {
        $Stream.Dispose()
    }
}

function New-TarGzArchive([string]$RootPath, [string]$ArchivePath, [string]$Kind) {
    $ScriptPath = Join-Path $BuildRoot "create_tar_gz.py"
    Write-Utf8NoBom $ScriptPath @'
from __future__ import annotations

import os
import sys
import tarfile
from pathlib import Path

root = Path(sys.argv[1]).resolve()
archive_path = Path(sys.argv[2]).resolve()
kind = sys.argv[3]
executable_control_scripts = {"postinst", "prerm", "postrm", "preinst"}
executable_source_scripts = {"scripts/install_linux.sh"}

with tarfile.open(archive_path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
    for current_root, directories, files in os.walk(root):
        directories.sort()
        files.sort()
        current = Path(current_root)

        entries = [(name, current / name, True) for name in directories]
        entries.extend((name, current / name, False) for name in files)

        for name, path, is_directory in entries:
            relative = path.relative_to(root).as_posix()
            arcname = f"./{relative}"
            info = archive.gettarinfo(str(path), arcname=arcname)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 0
            if is_directory:
                info.mode = 0o755
                archive.addfile(info)
                continue

            if kind == "control" and name in executable_control_scripts:
                info.mode = 0o755
            elif kind == "source" and relative in executable_source_scripts:
                info.mode = 0o755
            else:
                info.mode = 0o644

            with path.open("rb") as handle:
                archive.addfile(info, handle)
'@

    & $PythonExe @PythonArgs $ScriptPath $RootPath $ArchivePath $Kind
}

function New-SourceInstallerArchive {
    $StageRoot = Join-Path $BuildRoot $SourcePackageName
    Copy-AgentPayload $StageRoot

    Write-Utf8NoBom (Join-Path $StageRoot "INSTALL.txt") @"
PBXPulse Agent $Version
Target: generic Linux source installer

Use this archive for non-Debian Linux systems, manual installs, or systems
where you prefer the transparent installer script over a native package.

Install:
  cd $SourcePackageName
  sudo ./scripts/install_linux.sh

The installer creates a Python virtual environment on the target machine and
registers the systemd service.
"@

    Write-Utf8NoBom (Join-Path $StageRoot "RELEASE-MANIFEST.txt") @"
name=PBXPulse Agent
version=$Version
target=linux-source-installer
format=source-installer
installer=scripts/install_linux.sh
service=pbxpulse-agent
requires=python3,python3-venv,python3-pip,systemd
"@

    $ArchivePath = Join-Path $OutputDir "$SourcePackageName.tar.gz"
    Remove-Item -Force $ArchivePath -ErrorAction SilentlyContinue
    New-TarGzArchive $StageRoot $ArchivePath "source"
    Write-Host "Built $ArchivePath"
}

function New-DebPackage([string]$Architecture) {
    $PackageName = "PBXPulseAgent-$Version-debian-$Architecture"
    $PackageRoot = Join-Path $BuildRoot $PackageName
    $DataRoot = Join-Path $PackageRoot "data"
    $ControlRoot = Join-Path $PackageRoot "control"
    $InstallRoot = Join-Path $DataRoot "opt\pbxpulse-agent"
    $SystemdRoot = Join-Path $DataRoot "lib\systemd\system"
    $EtcRoot = Join-Path $DataRoot "etc"

    New-Item -ItemType Directory -Force -Path $ControlRoot, $InstallRoot, $SystemdRoot, $EtcRoot | Out-Null
    Copy-AgentPayload $InstallRoot

    Copy-Item -Force (Join-Path $AgentRoot ".env.example") (Join-Path $EtcRoot "pbxpulse-agent.env.example")
    Copy-Item -Force (Join-Path $AgentRoot ".env.example") (Join-Path $EtcRoot "pbxpulse-agent.env")

    Write-Utf8NoBom (Join-Path $SystemdRoot "$ServiceName.service") @"
[Unit]
Description=PBXPulse Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=pbxpulse
Group=pbxpulse
WorkingDirectory=/opt/pbxpulse-agent
Environment=PBXPULSE_AGENT_PORT=8765
EnvironmentFile=/etc/pbxpulse-agent.env
ExecStart=/opt/pbxpulse-agent/.venv/bin/uvicorn pbxpulse_agent.main:app --host 0.0.0.0 --port `$`{PBXPULSE_AGENT_PORT`}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"@

    Write-Utf8NoBom (Join-Path $ControlRoot "control") @"
Package: $PackageId
Version: $Version
Section: net
Priority: optional
Architecture: $Architecture
Maintainer: PBXPulse <support@pbxpulse.local>
Depends: python3, python3-venv, python3-pip, systemd
Description: Calm PBX companion Agent for PBXPulse
 PBXPulse Agent observes a PBX and translates PBX activity into calm,
 meaningful Signals for the PBXPulse app.
"@

    Write-Utf8NoBom (Join-Path $ControlRoot "conffiles") @"
/etc/pbxpulse-agent.env
"@

    Write-Utf8NoBom (Join-Path $ControlRoot "postinst") @'
#!/bin/sh
set -e

SERVICE_USER="pbxpulse"
INSTALL_DIR="/opt/pbxpulse-agent"
ENV_FILE="/etc/pbxpulse-agent.env"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/pbxpulse-agent --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p /var/lib/pbxpulse-agent /var/log/pbxpulse-agent
chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/pbxpulse-agent /var/log/pbxpulse-agent "$INSTALL_DIR"

if [ ! -f "$ENV_FILE" ]; then
  cp /etc/pbxpulse-agent.env.example "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  chown root:root "$ENV_FILE"
fi

python3 "$INSTALL_DIR/scripts/ensure_token.py" "$ENV_FILE"

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/.venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/.venv"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable pbxpulse-agent.service >/dev/null 2>&1 || true
  systemctl restart pbxpulse-agent.service >/dev/null 2>&1 || true
fi

exit 0
'@

    Write-Utf8NoBom (Join-Path $ControlRoot "prerm") @'
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop pbxpulse-agent.service >/dev/null 2>&1 || true
    systemctl disable pbxpulse-agent.service >/dev/null 2>&1 || true
  fi
fi

exit 0
'@

    Write-Utf8NoBom (Join-Path $ControlRoot "postrm") @'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
'@

    $ScriptNames = @("postinst", "prerm", "postrm")
    foreach ($ScriptName in $ScriptNames) {
        $ScriptPath = Join-Path $ControlRoot $ScriptName
        $Bytes = [System.IO.File]::ReadAllBytes($ScriptPath)
        $Text = [System.Text.Encoding]::UTF8.GetString($Bytes).Replace("`r`n", "`n")
        [System.IO.File]::WriteAllText($ScriptPath, $Text, (New-Object System.Text.UTF8Encoding($false)))
    }

    $DebianBinaryPath = Join-Path $PackageRoot "debian-binary"
    Write-Utf8NoBom $DebianBinaryPath "2.0`n"

    $ControlTarPath = Join-Path $PackageRoot "control.tar.gz"
    $DataTarPath = Join-Path $PackageRoot "data.tar.gz"

    New-TarGzArchive $ControlRoot $ControlTarPath "control"
    New-TarGzArchive $DataRoot $DataTarPath "data"

    $DebPath = Join-Path $OutputDir "$PackageName.deb"
    Remove-Item -Force $DebPath -ErrorAction SilentlyContinue
    New-DebArchive $DebPath $DebianBinaryPath $ControlTarPath $DataTarPath
    Write-Host "Built $DebPath"
}

New-SourceInstallerArchive
New-DebPackage "i386"
New-DebPackage "amd64"
New-DebPackage "arm64"
