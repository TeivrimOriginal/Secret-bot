# Wrapper: all build logic lives in build.py (Python); this only calls it.
# Kept ASCII-only because Windows PowerShell 5.1 mishandled non-ASCII scripts.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
python (Join-Path $here 'build.py')
exit $LASTEXITCODE
