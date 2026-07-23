param(
    [string]$Version = "0.5.19-beta",
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
        throw "Python 3 is required to create Linux archives with Unix permissions."
    }
}

$SourcePackageName = "PBXSenseAgent-$Version-linux-source-installer"
$JtapiClass = Join-Path $AgentRoot "jtapi_bridge\classes\PBXSenseJtapiBridge.class"
if (-not (Test-Path $JtapiClass)) {
    throw "Compiled Java 8 JTAPI bridge is missing. Run scripts/build_jtapi_bridge.sh first."
}
$AgentEntries = @(
    "pbxsense_agent",
    "jtapi_bridge",
    "scripts",
    "docs",
    "requirements.txt",
    ".env.example",
    "CODEX.md",
    "README.md",
    "docker"
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

    # Release archives are frequently built on Windows and installed on Linux.
    # Keep /bin/sh scripts in Unix form even when the source checkout uses CRLF.
    foreach ($Script in @("scripts/install_common.sh", "scripts/install_debian.sh", "scripts/install_fedora.sh", "scripts/setup_docker.sh", "scripts/uninstall_linux.sh")) {
        $ScriptPath = Join-Path $DestinationRoot $Script
        if (-not (Test-Path $ScriptPath)) {
            continue
        }
        $Content = [System.IO.File]::ReadAllText($ScriptPath)
        $Content = $Content.Replace("`r`n", "`n").Replace("`r", "`n")
        Write-Utf8NoBom $ScriptPath $Content
    }
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
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
executable_agent_scripts = {"scripts/install_debian.sh", "scripts/install_fedora.sh", "scripts/setup_docker.sh", "scripts/uninstall_linux.sh"}

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
            elif kind in {"source", "data"} and relative in executable_agent_scripts:
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
PBXSense Agent $Version
Target: Debian-family and Fedora-family Linux source installer

Use the entry point for the target distribution. Both installers share the
same PBXSense configuration and hardened systemd service setup.

Debian/Ubuntu/Raspberry Pi OS:
  cd $SourcePackageName
  sudo sh ./scripts/install_debian.sh

Fedora/RHEL family:
  sudo sh ./scripts/install_fedora.sh

The installer creates a Python virtual environment on the target machine and
registers the systemd service.
"@

    Write-Utf8NoBom (Join-Path $StageRoot "RELEASE-MANIFEST.txt") @"
name=PBXSense Agent
version=$Version
channel=breeze
target=linux-source-installer
format=source-installer
debian_installer=scripts/install_debian.sh
fedora_installer=scripts/install_fedora.sh
service=pbxsense-agent
requires=python3,python3-venv,python3-pip,systemd
"@

    $ArchivePath = Join-Path $OutputDir "$SourcePackageName.tar.gz"
    Remove-Item -Force $ArchivePath -ErrorAction SilentlyContinue
    New-TarGzArchive $StageRoot $ArchivePath "source"
    Write-Host "Built $ArchivePath"
}

New-SourceInstallerArchive
Remove-Item -Recurse -Force (Join-Path $PackagingRoot "build") -ErrorAction SilentlyContinue
