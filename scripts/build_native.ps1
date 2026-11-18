# Build the compiled core (native/ulpf_core) into ulpf/ulpf_core.pyd.
# Needs Rust (rustup) with the MSVC or GNU host toolchain. No maturin and no
# Python headers: the module links python3.dll (stable ABI, Python >= 3.10).
# On MSVC, an embeddable Python ships no python3.lib, so an import library is
# generated from python3.dll's exports with the MSVC dumpbin/lib tools.
# The batch engine (native lane) is used automatically once built;
# ULPF_NATIVE_LANE=0 turns it off. See docs/STATUS.md, Phase 4.
param([string]$Python = "python")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = (Get-Command $Python).Source
$pyDir = Split-Path -Parent $py
$ver = & $py -c "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"
$crate = Join-Path $root "native\ulpf_core"
$target = Join-Path $crate "target"
New-Item -ItemType Directory -Force $target | Out-Null

$host_triple = (& rustc -vV | Select-String "^host:").ToString().Split(" ")[1]
$libDir = $pyDir
if ($host_triple -like "*msvc*") {
    $libDir = Join-Path $pyDir "libs"
    if (-not (Test-Path (Join-Path $libDir "python3.lib"))) {
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        $tools = (Get-ChildItem "$vs\VC\Tools\MSVC\*\bin\HostX64\x64" | Sort-Object Name | Select-Object -Last 1).FullName
        $libDir = Join-Path $target "pylibs"
        New-Item -ItemType Directory -Force $libDir | Out-Null
        $names = & "$tools\dumpbin.exe" /exports (Join-Path $pyDir "python3.dll") | ForEach-Object {
            if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+(?:[0-9A-F]{8}\s+)?(\S+)') { $matches[1] } } | Where-Object { $_ -notmatch '^\(' }
        @("LIBRARY python3", "EXPORTS") + $names | Set-Content (Join-Path $libDir "python3.def") -Encoding ascii
        & "$tools\lib.exe" /nologo /def:"$libDir\python3.def" /machine:x64 /out:"$libDir\python3.lib" | Out-Null
    }
}

$cfg = Join-Path $target "pyo3-build-config.txt"
@"
implementation=CPython
version=$ver
shared=true
abi3=true
lib_name=python3
lib_dir=$libDir
executable=$py
pointer_width=64
build_flags=
suppress_build_script_link_lines=false
"@ | Set-Content -Path $cfg -Encoding ascii
$env:PYO3_CONFIG_FILE = $cfg
Push-Location $crate
try { cargo build --release } finally { Pop-Location }
Copy-Item (Join-Path $target "release\ulpf_core.dll") (Join-Path $root "ulpf\ulpf_core.pyd") -Force
& $py -c "from ulpf import ulpf_core; print('ulpf_core', ulpf_core.version(), 'built; batch engine:', hasattr(ulpf_core, 'Engine'))"
