# Makes a clean hand-off zip: the files git tracks (plus new files that are not ignored), never build
# output. Use this instead of zipping the working folder.
#
#   .\scripts\pack.ps1                  -> ..\silk-rust-src.zip (includes .git, so history comes along)
#   .\scripts\pack.ps1 -Out my.zip
#   .\scripts\pack.ps1 -NoGit
param([string]$Out = "..\silk-rust-src.zip", [switch]$NoGit)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$root = (Get-Location).Path
git rev-parse --git-dir *> $null
if ($LASTEXITCODE -ne 0) { throw 'not a git checkout: nothing says what is source' }
if (-not [IO.Path]::IsPathRooted($Out)) { $Out = Join-Path $root $Out }
$Out = [IO.Path]::GetFullPath($Out)
if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out }

$files = @(git ls-files -co --exclude-standard | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
if (-not $NoGit) {
    $files += Get-ChildItem -LiteralPath .git -Recurse -File -Force |
        ForEach-Object { $_.FullName.Substring($root.Length + 1) }
}

# Entry names use '/', which Compress-Archive in Windows PowerShell 5.1 does not do.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::Open($Out, 'Create')
try {
    foreach ($f in $files) {
        $full = Join-Path $root $f
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $full, ($f -replace '\\', '/'), 'Optimal')
    }
} finally { $zip.Dispose() }
'{0}: {1:N1} MB, {2} files' -f $Out, ((Get-Item -LiteralPath $Out).Length / 1MB), $files.Count
