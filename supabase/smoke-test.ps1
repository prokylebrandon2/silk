<#
.SYNOPSIS
  Checks the real Firebase -> Supabase Storage path with your own account. Run it from the repository root.

.DESCRIPTION
  Reads SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY from android\local.properties and the Firebase Web API
  key from android\app\src\main\res\values\firebase.xml. Asks for your Firebase email and password
  (the password is typed hidden and goes only to Google's sign-in endpoint). Nothing is printed that
  could be used to sign in: the token itself is never shown.

  Default (read-only):
    1. signs in and shows what your token says about itself (role, uid, expiry);
    2. tries to read your keyslot.skvk.
  -Write (also changes your cloud folder, then cleans up):
    only if step 2 found nothing there, it creates a 32-byte random test object as keyslot.skvk, reads it
    back, replaces it, deletes it, and tries (and should fail) to write into someone else's folder.
    It refuses to run if you already have a vault in the cloud.

  Until the `role: authenticated` claim exists on your Firebase user the token check will say so and the
  script stops: that is the expected result before the claim is provisioned.

  This is a manual integration check, separate from the mocked Rust tests. It was written without
  access to a live project; if a line fails, send me the output (it contains no secrets).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\supabase\smoke-test.ps1
  powershell -ExecutionPolicy Bypass -File .\supabase\smoke-test.ps1 -Write
#>
param([switch]$Write)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = (Get-Location).Path
$propsPath = Join-Path $root 'android\local.properties'
$xmlPath = Join-Path $root 'android\app\src\main\res\values\firebase.xml'
if (-not (Test-Path $propsPath)) { throw "Missing $propsPath (see docs/ARCHITECTURE.md, Setting up the cloud)." }
if (-not (Test-Path $xmlPath)) { throw "Missing $xmlPath. Run this from the repository root." }

function Get-Prop($name) {
    $line = Get-Content $propsPath | Where-Object { $_ -match "^\s*$name\s*=" } | Select-Object -First 1
    if (-not $line) { throw "$name is not set in android\local.properties" }
    return ($line -replace "^\s*$name\s*=\s*", '').Trim()
}

$supabaseUrl = (Get-Prop 'SUPABASE_URL').TrimEnd('/')
$publishableKey = Get-Prop 'SUPABASE_PUBLISHABLE_KEY'
$xml = Get-Content $xmlPath -Raw
if ($xml -notmatch 'name="firebase_api_key"[^>]*>([^<]+)<') { throw 'firebase_api_key not found in firebase.xml' }
$firebaseKey = $Matches[1].Trim()

if ($supabaseUrl -notmatch '^https://[a-z0-9]+\.supabase\.co$') { throw 'SUPABASE_URL must look like https://<project>.supabase.co' }
if ($publishableKey -like 'sb_secret_*') { throw 'That is a SECRET key. Use the publishable key, and rotate the secret key in the dashboard.' }
if ($firebaseKey -like 'YOUR_*' -or $publishableKey -like 'YOUR_*') { throw 'A value is still a YOUR_ placeholder.' }

function Read-ErrorBody($err) {
    if ($err.ErrorDetails -and $err.ErrorDetails.Message) { return $err.ErrorDetails.Message }
    try {
        $stream = $err.Exception.Response.GetResponseStream()
        return (New-Object IO.StreamReader($stream)).ReadToEnd()
    } catch { return '' }
}

# Sends a request; never throws on an HTTP error, returns Status, Body (text) and Bytes.
function Send($method, $uri, $headers, $body, $contentType) {
    $req = @{ Method = $method; Uri = $uri; Headers = $headers; UseBasicParsing = $true }
    if ($null -ne $body) { $req['Body'] = $body }
    if ($contentType) { $req['ContentType'] = $contentType }
    try {
        $r = Invoke-WebRequest @req
        $ms = New-Object IO.MemoryStream
        $r.RawContentStream.CopyTo($ms)
        return @{ Status = [int]$r.StatusCode; Body = ''; Bytes = $ms.ToArray() }
    } catch {
        $status = 0
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        return @{ Status = $status; Body = (Read-ErrorBody $_); Bytes = @() }
    }
}

function Decode-Jwt($jwt) {
    $p = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    while ($p.Length % 4) { $p += '=' }
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
}

# ---- 1. sign in ----
$email = Read-Host 'Firebase account email'
$secure = Read-Host 'Firebase account password' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
$signIn = Send 'POST' "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$firebaseKey" @{} `
    (@{ email = $email; password = $plain; returnSecureToken = $true } | ConvertTo-Json) 'application/json'
$plain = $null
if ($signIn.Status -ne 200) { throw "Firebase sign-in failed (HTTP $($signIn.Status)): $($signIn.Body)" }
$idToken = ([Text.Encoding]::UTF8.GetString($signIn.Bytes) | ConvertFrom-Json).idToken

$claims = Decode-Jwt $idToken
$uid = $claims.sub
Write-Host ''
Write-Host '== Your Firebase token says ==' -ForegroundColor Cyan
Write-Host ("  uid (sub): {0}" -f $uid)
Write-Host ("  role     : {0}" -f $(if ($claims.role) { $claims.role } else { '(none)' }))
Write-Host ("  issuer   : {0}" -f $claims.iss)
Write-Host ("  expires  : {0}" -f ([DateTimeOffset]::FromUnixTimeSeconds([long]$claims.exp).LocalDateTime))
if ($claims.role -ne 'authenticated') {
    Write-Host ''
    Write-Host 'The token has no role = "authenticated" claim, so Supabase treats it as anonymous and Storage' -ForegroundColor Yellow
    Write-Host 'will refuse it. That is expected until the claim is provisioned. Stopping here.' -ForegroundColor Yellow
    return
}

$headers = @{ apikey = $publishableKey; Authorization = "Bearer $idToken" }
function Object-Url($uidPart, $authenticatedRead) {
    $mid = if ($authenticatedRead) { 'authenticated/' } else { '' }
    return "$supabaseUrl/storage/v1/object/$mid" + "silk-vaults/vaults/$uidPart/keyslot.skvk"
}
function Show($label, $r) {
    $b = if ($r.Body) { $r.Body } else { "$($r.Bytes.Length) bytes" }
    Write-Host ("  {0,-34} HTTP {1}  {2}" -f $label, $r.Status, $b)
}

# ---- 2. read ----
Write-Host ''
Write-Host '== Storage ==' -ForegroundColor Cyan
$read = Send 'GET' (Object-Url $uid $true) $headers $null $null
Show 'read your keyslot.skvk' $read
$nothingThere = ($read.Status -eq 404) -or ($read.Status -eq 400 -and $read.Body -match 'not_found|Object not found')
if ($read.Status -eq 200) { Write-Host '  You already have a keyslot in the cloud: reads work.' -ForegroundColor Green }
elseif ($nothingThere) { Write-Host '  Nothing stored yet (or hidden by policy). Normal for a new account.' -ForegroundColor Green }
else { Write-Host '  Unexpected answer: send me this line.' -ForegroundColor Yellow }

if (-not $Write) { Write-Host ''; Write-Host 'Read-only check done. Add -Write to test upload, replace and delete.'; return }

# ---- 3. write test ----
if (-not $nothingThere) { throw 'Refusing -Write: a keyslot already exists (or the read failed). Nothing was changed.' }
$a = New-Object byte[] 32; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($a)
$b = New-Object byte[] 32; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b)
try {
    $create = Send 'POST' (Object-Url $uid $false) ($headers + @{ 'cache-control' = 'max-age=0' }) $a 'application/octet-stream'
    Show 'create (POST)' $create
    $back = Send 'GET' (Object-Url $uid $true) $headers $null $null
    Show 'read it back' $back
    Write-Host ("  same bytes: {0}" -f (($back.Bytes -join ',') -eq ($a -join ',')))
    $again = Send 'POST' (Object-Url $uid $false) $headers $b 'application/octet-stream'
    Show 'create again (should be refused)' $again
    $replace = Send 'PUT' (Object-Url $uid $false) ($headers + @{ 'cache-control' = 'max-age=0' }) $b 'application/octet-stream'
    Show 'replace (PUT)' $replace
    $back2 = Send 'GET' (Object-Url $uid $true) $headers $null $null
    Write-Host ("  replaced bytes read back   : {0}" -f (($back2.Bytes -join ',') -eq ($b -join ',')))
    $other = Send 'POST' (Object-Url 'not-my-uid' $false) $headers $a 'application/octet-stream'
    Show "write to someone else's folder" $other
    Write-Host '  (the last one must NOT be HTTP 200)' -ForegroundColor Yellow
} finally {
    $del = Send 'DELETE' (Object-Url $uid $false) $headers $null $null
    Show 'cleanup: delete test object' $del
    $gone = Send 'GET' (Object-Url $uid $true) $headers $null $null
    Show 'cleanup: confirm it is gone' $gone
}
Write-Host ''
Write-Host 'Done. Paste the output above if anything looks wrong; it contains no secrets.'
