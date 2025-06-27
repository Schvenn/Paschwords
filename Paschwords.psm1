function paschwords ($database, $keyfile, [switch]$noclip, [switch]$notime) {# Password Manager.

#---------------------------------------------PRE-LAUNCH-------------------------------------------

function initialize {# Set preliminary environment variables.
# Set module variables
$script:powershell = Split-Path $profile
$script:failedmaster = 0; $script:lockoutmaster = $false
$script:keypasscount = Get-Random -Minimum 3 -Maximum 50

# Test & import configuration settings
$script:basemodulepath = Join-Path $script:powershell "Modules\Paschwords"; $script:configpath = Join-Path $script:basemodulepath "Paschwords.psd1"
if (!(Test-Path $script:configpath)) {throw "Config file not found at $script:configpath"}
$config = Import-PowerShellDataFile -Path $configpath

# Change directories.
$script:startingdirectory = "$pwd"; sl $script:basemodulepath

# KeyDir & DefaultKey
$script:keydir = $config.PrivateData.keydir; $script:defaultkey = $config.PrivateData.defaultkey; $script:keydir = $script:keydir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $script:defaultkey = Join-Path $script:keydir $script:defaultkey

# DatabaseDir & DefaultDatabase
$script:databasedir = $config.PrivateData.databasedir; $script:defaultdatabase = $config.PrivateData.defaultdatabase; $script:databasedir = $script:databasedir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $script:defaultdatabase = Join-Path $script:databasedir $script:defaultdatabase

# PrivilegeDir & LogDir
$script:privilegedir = $config.PrivateData.privilegedir; $script:privilegedir = $script:privilegedir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $script:logdir = $config.PrivateData.logdir; $script:logdir = $script:logdir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell)

# Default User Registry
$basename = [IO.Path]::GetFileNameWithoutExtension($script:defaultkey); $script:defaultregistry = Join-Path $privilegedir "$basename.db"

# Create all necessary directories, if they don't already exist.
if (-not (Test-Path $script:keydir)) {New-Item -ItemType Directory -Path $script:keydir -Force | Out-Null}
if (-not (Test-Path $script:databasedir)) {New-Item -ItemType Directory -Path $script:databasedir -Force | Out-Null}
if (-not (Test-Path $script:privilegedir)) {New-Item -ItemType Directory -Path $script:privilegedir -Force | Out-Null}
if (-not (Test-Path $script:logdir)) {New-Item -ItemType Directory -Path $script:logdir -Force | Out-Null}

# Import PSD1 settings.
$script:version = $config.ModuleVersion

$script:delayseconds = $config.PrivateData.delayseconds

$script:timeoutseconds = $config.PrivateData.timeoutseconds
if ([int]$script:timeoutseconds -gt 5940 -or [int]$script:timeoutseconds -lt 0) {$script:timeoutseconds = 5940}

$script:timetobootlimit = $config.PrivateData.timetobootlimit
if ([int]$script:timetobootlimit -gt 120 -or [int]$script:timetobootlimit -lt 0) {$script:timetobootlimit = 120}

$script:expirywarning = $config.PrivateData.expirywarning
if ([int]$script:expirywarning -gt 365 -or [int]$script:expirywarning -lt 0) {$script:expirywarning = 365}

$script:logretention = $config.PrivateData.logretention
if ([int]$script:logretention -lt 30) {$script:logretention = 30}

$script:dictionaryfile = $config.PrivateData.dictionaryfile; $script:dictionaryfile = Join-Path $script:basemodulepath $script:dictionaryfile

$script:backupfrequency = $config.PrivateData.backupfrequency
$script:archiveslimit = $config.PrivateData.archiveslimit

$script:useragent = $config.PrivateData.useragent

# Initialize privilege settings.
$script:rootkeyFile = "$privilegedir\root.key"; $script:rootkey = $null; $script:hashFile = "$privilegedir\password.hash"

# Obtain verify hashes.
$encodedscript = Resolve-Path 'Paschwords.enc' -ea SilentlyContinue; $modulescript = Resolve-Path 'Paschwords.psm1' -ea SilentlyContinue
$thisscript = if ($script:basemodulepath -and (Test-Path $modulescript -ea SilentlyContinue)) {$modulescript} elseif (Test-Path $encodedscript -ea SilentlyContinue) {$encodedscript}
else {Write-Host -f red "`nNo valid script file found in order to validate hash.`n"}
$script:thisscript = (Get-FileHash -Algorithm SHA256 -Path $thisscript).Hash; $hashcheck = $true; $script:ntpscript = (Get-FileHash -Algorithm SHA256 -Path $script:basemodulepath\CheckNTPTime.ps1).Hash

# Initialize menu variables.
$script:sessionstart = Get-Date; $script:lastrefresh = 1000; $script:timetoboot = $null; $script:noclip = $noclip; $script:disablelogging = $false
$script:management = $false; $script:quit = $false
$script:message = $null; $script:warning = $null

neuralizer}

function setdefaults {# Set Key and Database defaults.
# Infer values from paramaters.
if ($database -and -not $keyfile -and $database -notmatch "(?i)\.(KEY|PWDB)$") {$keyfile = "$database.key"; $database = "$database.pwdb"}
elseif ($database -and -not $keyfile) {$basename = [IO.Path]::GetFileNameWithoutExtension($database); $keyfile = "$basename.key"}
elseif ($keyfile -and -not $database) {$basename = [IO.Path]::GetFileNameWithoutExtension($keyfile); $database = "$basename.pwdb"}

# Correct database, if necessary.
if ($database) {if (-not [System.IO.Path]::GetExtension($database)) {$database += '.pwdb'}
if (-not [System.IO.Path]::IsPathRooted($database)) {$script:database = Join-Path $script:databasedir $database}}
if (-not $script:database -or -not (Test-Path $script:database -ea SilentlyContinue)) {$script:database = $script:defaultdatabase}

# Check key validity, but allow the menu to load, even if there is no default key.
$script:keyexists = $true
if ($keyfile) {if (-not [System.IO.Path]::GetExtension($keyfile)) {$keyfile += '.key'}
if (-not [System.IO.Path]::IsPathRooted($keyfile)) {$script:keyfile = Join-Path $script:keydir $keyfile}}
if (-not $script:keyfile -or -not (Test-Path $script:keyfile -ea SilentlyContinue)) {$script:keyfile = $script:defaultkey}

# Set user registry to the keyfile basename, if it exists.
if (-not $keyfile) {$script:registryfile = $script:defaultregistry}
if ($keyfile) {$providedkeyname = [IO.Path]::GetFileNameWithoutExtension($keyfile); $script:registryfile = Join-Path $privilegedir "$providedkeyname.db"}

# Set to null if nothing if neither exists.
if (-not (Test-Path $script:keyfile -ea SilentlyContinue) -and -not (Test-Path $script:defaultkey -ea SilentlyContinue)) {$script:keyexists = $false; $script:keyfile = $null; $script:registryfile = $null; $script:database = $null}}

function verify {# Check the current time and current file hash against all valid versions.
$hashfile = Join-Path $script:privilegedir 'validhashes.sha256'

if (-not (Test-Path $hashfile -ea SilentlyContinue)) {Write-Host -f red "`n`t  WARNING: " -n; Write-Host -f white "Hash file not found. Cannot`n`t  verify script integrity. Unless this`n`t  is a fresh install, do not proceed.`n`n`t  For safety reasons, please download`n`t  and copy the validhashes.sha256 file`n`t  into your privilege directory."; Write-Host -f red "`n`t  First stage of validation failed."}

else {$validHashes = Get-Content $hashfile | ForEach-Object {$_.Trim()} | Where-Object {$_ -ne ''}
if ($validHashes -notcontains $script:thisscript) {Write-Host -f red "`nWARNING: " -n; Write-Host -f yellow "This script has been tampered with. Do not trust it!`n"; return $false}
if ($validHashes -notcontains $script:ntpscript) {Write-Host -f red "`nWARNING: " -n; Write-Host -f yellow "The NTP script used to validate the current time has been tampered with. Do not trust it!`n"; return $false}
else {Write-Host -f green "`n`t  First stage of validation passed."}}

if ($notime) {# Validate via Master password, if -notime has been chosen.
if (masterlockout) {Write-Host -f red "`n`t  Bypassing system time validation action is currently prohibited.`n"; return}

else {Write-Host -f green "`n`t  👑 In order to bypass system time validation, enter the master password " -n; $masterSecure = Read-Host -AsSecureString
if (-not (verifymasterpassword $masterSecure)) {$script:failedmaster++; if (masterlockout) {Write-Host -f red "`n`t  Bypassing system time validation action is currently prohibited.`n"; return}; $remaining = 4-$script:failedmaster; Write-Host -f red "`t  ❌ Wrong master password. $remaining attempts remain before lockout.`n"; return}

else {resetmasterfailures; Write-Host -f green "`t  Permission granted.`n"; $timecheck = $true}}}

if (-not $notime) {if (Test-Path $script:basemodulepath\CheckNTPTime.ps1 -ea SilentlyContinue) {$timecheck = & "$script:basemodulepath\CheckNTPTime.ps1"}
else {$timecheck = $false}}

if ($timecheck) {Write-Host -f green "`t  Second stage of validation passed."}
elseif (-not $timecheck) {if (Test-Path $hashfile -ea SilentlyContinue) {Write-Host -f red "`nAborting due to untrusted system clock.`n"; return $false}
else {Write-Host -f red "`nNeither the hashfile nor NTP server to system clock comparison passed validation. Aborting.`n"; return $false}}

return $true}

function resizewindow {# Attempt to set window size if it's too small and the environment is not running inside Terminal.
$minWidth = 130; $minHeight = 50; $buffer = $Host.UI.RawUI.BufferSize; $window = $Host.UI.RawUI.WindowSize
if ($env:WT_SESSION -and ($window.Width -lt $minWidth -or $window.Height -lt $minHeight)) {Write-Host -f red "`nWarning:" -n; Write-Host -f white " You are running PowerShell inside Windows Terminal and this module is therefore unable to resize the window. Please manually resize it to at least $minWidth by $minHeight for best performance. Your current window size is $($window.Width) by $($window.Height)."; return}
if ($buffer.Width -lt $minWidth) {$buffer.Width = $minWidth}
if ($buffer.Height -lt $minHeight) {$buffer.Height = $minHeight}
$Host.UI.RawUI.BufferSize = $buffer
try {if ($window.Width -lt $minWidth) {$window.Width = $minWidth}
if ($window.Height -lt $minHeight){$window.Height = $minHeight}
$Host.UI.RawUI.WindowSize = $window}
catch {Write-Host -f red "`nWarning:" -n; Write-Host -f white " Unable to resize window. Please manually resize to at least $minWidth x $minHeight."}
$window = $Host.UI.RawUI.WindowSize
if ($window.Width -lt $minWidth -or $window.Height -lt $minHeight) {Write-Host -f red "`nWarning:" -n; Write-Host -f white " This module works best when the screen size is at least $minWidth characters wide by $minHeight lines.`n Current window size is $($window.Width) x $($window.Height). Output may wrap or scroll unexpectedly.`n"}}


#---------------------------------------------AUTHENTICATION---------------------------------------

function login {# Display initial login screen.
initialize; setdefaults; logcleanup; resizewindow
if (-not (verify)) {return}

$script:sessionstart = Get-Date; $script:key = $null; Write-Host -f yellow "`n`t+-------------------------------------+`n`t|  🔑  Secure Paschwords Manager  🔒  |`n`t|-------------------------------------|" -n

# Unlock the database and authenticate the user in order to allow access, if the environment is already established.
if (-not $script:keyexists -and -not (Test-Path $script:registryfile -ea SilentlyContinue)) {start-sleep 3; loggedin}
elseif (-not $script:keyexists) {Write-Host -f white "`n`t`tNo database key present.`n`t"; loginfailed}
elseif ($script:keyexists) {decryptkey $script:keyfile
if ($script:key) {if (authenticateuser) {loggedin}}
else {loginfailed}}}

function authenticateuser {# User authentication and lockout.
$maxFailures = 3; $lockoutDuration = [TimeSpan]::FromMinutes(30); $attemptsFilePrefix = ".locked.flag"; $script:standarduser = $false

loadregistry

if (-not $script:users -or $script:users.Count -eq 0) {Write-Host -f red "`t    No users found in registry."; return $false}

while ($true) {Write-Host -f green "`t 👤 Username: " -n; $username = Read-Host
if (-not $username) {Write-Host -f red "`t    Username required."; continue}
$userEntry = $script:users | Where-Object {$_.data.Username -eq $username}
if (-not $userEntry) {Write-Host -f red "`t    User not found."; continue}

# Check account active and expiration date
$expiresDate = [datetime]::ParseExact($userEntry.data.Expires, 'yyyy-MM-dd', $null); $nowDate = (Get-Date).ToUniversalTime().Date
if (-not $userEntry.data.Active -or $nowDate -gt $expiresDate) {Write-Host -f red "`t    Account expired or inactive.`n"; return $false}

# Lock file path
$lockFile = Join-Path $privilegedir "$username$attemptsFilePrefix"

# Check lockout
if (Test-Path $lockFile) {$lastWrite = (Get-Item $lockFile).LastWriteTimeUtc; $elapsed = (Get-Date).ToUniversalTime() - $lastWrite
if ($elapsed -lt $lockoutDuration) {$remaining = $lockoutDuration - $elapsed; Write-Host -f red "`t    Account locked.`n`t    Try again in $([int]$remaining.TotalMinutes) minutes."; return $false}
else {Remove-Item $lockFile -ea SilentlyContinue}}

# Track login attempts count
$failCount = 0
if (Test-Path $lockFile) {$failCount = [int](Get-Content $lockFile -ea SilentlyContinue)}

while ($true) {Write-Host -f green "`t 🔐 Password: " -n; $securePass = Read-Host -AsSecureString
if (-not $securePass -or $securePass.Length -eq 0) {Write-Host -f red "`t    Password required."; continue}
try {$plainPass = [System.Net.NetworkCredential]::new("", $securePass).Password
if (-not $plainPass) {Write-Host -f red "`t    Password required."; continue}}
catch {Write-Host -f red "`t    Invalid password input."; continue}

$saltAndHash = [Convert]::FromBase64String($userEntry.data.Password); $salt = $saltAndHash[0..15]; $storedHash = $saltAndHash[16..($saltAndHash.Length - 1)]; $derived = [byte[]](derivekeyfrompassword $plainPass $salt); $sha256 = [Security.Cryptography.SHA256]::Create(); $computedHash = $sha256.ComputeHash($derived); $sha256.Dispose()

$match = ($computedHash.Length -eq $storedHash.Length) -and (-not (Compare-Object $computedHash $storedHash))
if ($match) {if (Test-Path $lockFile) {Remove-Item $lockFile -ea SilentlyContinue}
$script:standarduser = ($userEntry.data.Role -eq 'standard'); $script:message = "✅ Authentication successful for user '$username'."; $script:loggedinuser = $username; nowarning; return $true}

$failCount++; Set-Content -Path $lockFile -Value $failCount; (Get-Item $lockFile).LastWriteTimeUtc = (Get-Date).ToUniversalTime(); $remainingAttempts = $maxFailures - $failCount
if ($remainingAttempts -le 0) {Write-Host -f red "`t    Account locked.`n`t    Try again in 30 minutes."; return $false}
Write-Host -f red "`t    Invalid password. $remainingAttempts attempt(s) remaining."}}}

function loginfailed {# Login failed.
Write-Host -f yellow "`t|-------------------------------------|`n`t|" -n; Write-Host -f red "   😲  Access Denied! ABORTING! 🔒   " -n; Write-Host -f yellow "|`n`t+-------------------------------------+`n"; return}

function logoff {# Exit screen.
sl $script:startingdirectory; nowarning; nomessage; Write-Host -f red "Securing the environment..."; neuralizer; $choice=$null; rendermenu; Write-Host -f white "`n`t`t    ____________________`n`t`t   |  ________________  |`n`t`t   | |                | |`n`t`t   | |   🔒 "-n; Write-Host -f red "Locked." -n; Write-Host -f white "   | |`n`t`t   | |                | |`n`t`t   | |________________| |`n`t`t   |____________________|`n`t`t    _____|_________|_____`n`t`t   / * * * * * * * * * * \`n`t`t  / * * * * * * * * * * * \`n`t`t ‘-------------------------’`n"; return}

#---------------------------------------------SUPPORT FUNCTIONS------------------------------------

function clearclipboard ($delayseconds = 30) {# Fill the clipboard with junk and then clear it after a delay.
Start-Job -ScriptBlock {param($delay, $length); Start-Sleep -Seconds $delay; $junk = -join ((33..126) | Get-Random -Count $length | ForEach-Object {[char]$_}); Set-Clipboard -Value $junk; Start-Sleep -Milliseconds 500; Set-Clipboard -Value $null} -ArgumentList $delayseconds, 64 | Out-Null}

function nowarning {# Set global warning field to null.
$script:warning = $null}

function nomessage {# Set global message field to null.
$script:message = $null}

function comparebytearrays ([byte[]]$a, [byte[]]$b) {# HMAC verification.
if ($a.Length -ne $b.Length) {return $false}
$diff = 0; for ($i = 0; $i -lt $a.Length; $i++) {$diff = $diff -bor ($a[$i] -bxor $b[$i])}; return ($diff -eq 0)}

function comparesecurestring ($a, $b) {# Returns true if two SecureStrings match.
if ($a.Length -ne $b.Length) {return $false}
$plainA = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
$plainB = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
$result = $plainA -eq $plainB
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
return $result}

function wordwrap ($field, [int]$maximumlinelength = 66) {# Modify fields sent to it with proper word wrapping.
if ($null -eq $field -or $field.Length -eq 0) {return $null}
$breakchars = ',.;?!\/ '; $wrapped = @()

foreach ($line in $field -split "`n") {if ($line.Trim().Length -eq 0) {$wrapped += ''; continue}
$remaining = $line.Trim()
while ($remaining.Length -gt $maximumlinelength) {$segment = $remaining.Substring(0, $maximumlinelength); $breakIndex = -1

foreach ($char in $breakchars.ToCharArray()) {$index = $segment.LastIndexOf($char)
if ($index -gt $breakIndex) {$breakChar = $char; $breakIndex = $index}}
if ($breakIndex -lt 0) {$breakIndex = $maximumlinelength - 1; $breakChar = ''}
$chunk = $segment.Substring(0, $breakIndex + 1).TrimEnd(); $wrapped += $chunk; $remaining = $remaining.Substring($breakIndex + 1).TrimStart()}

if ($remaining.Length -gt 0) {$wrapped += $remaining}}
return ($wrapped -join "`n")}

function indent ($field, $colour = 'white', [int]$indent = 2) {# Set a default indent for a field.
if ($field.length -eq 0) {return}
$prefix = (' ' * $indent)
foreach ($line in $field -split "`n") {Write-Host -f $colour "$prefix$line"}}

function helptext {# Detailed help.

function scripthelp ($section) {# (Internal) Generate the help sections from the comments section of the script.
Write-Host -f yellow ("-" * 100); $pattern = "(?ims)^## ($section.*?)(##|\z)"; $match = [regex]::Match($scripthelp, $pattern); $lines = $match.Groups[1].Value.TrimEnd() -split "`r?`n", 2; Write-Host $lines[0] -f yellow; Write-Host -f yellow ("-" * 100)

if ($lines.Count -gt 1) {$text = wordwrap $lines[1] 100 | Out-String; $text = $text.TrimEnd("`r", "`n"); Write-Host $text}; Write-Host -f yellow ("-" * 100)}

$scripthelp = (Get-Command paschwordshelpdialogue).ScriptBlock.ToString(); $sections = [regex]::Matches($scripthelp, "(?im)^## (.+?)(?=\r?\n)"); $selection = $null
do {cls; Write-Host "Paschwords Help Sections:`n" -f cyan; for ($i = 0; $i -lt $sections.Count; $i++) {"{0}: {1}" -f ($i + 1), $sections[$i].Groups[1].Value}
if ($selection) {scripthelp $sections[$selection - 1].Groups[1].Value}
Write-Host -f white "`nEnter a section number to view " -n; $input = Read-Host
if ($input -match '^\d+$') {$index = [int]$input
if ($index -ge 1 -and $index -le $sections.Count) {$selection = $index}
else {$selection = $null}} else {return}}
while ($true); return}

#---------------------------------------------HOUSE CLEANING---------------------------------------

function corruptdatabase {# JSON Database overwriting.
$databasepasscount = Get-Random -Minimum 3 -Maximum 10;
if (-not ($script:jsondatabase -and $script:jsondatabase.Count -gt 0)) {return}
for ($i = 0; $i -lt $databasepasscount; $i++) {foreach ($entry in $script:jsondatabase) {foreach ($property in $entry.PSObject.Properties) {$original = "$($property.Value)"
if ([string]::IsNullOrEmpty($original)) {continue}
$originalLength = $original.Length; $multiplier = Get-Random -Minimum 1.1 -Maximum 3.9; $roundingMethod = Get-Random -InputObject 'Floor','Ceiling','Round'; $targetLength = [Math]::$roundingMethod($originalLength * $multiplier); $junkBytes = New-Object byte[] $targetLength; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($junkBytes); $trimmed = $junkBytes[0..($originalLength - 1)]; $asciiJunk = ($trimmed | ForEach-Object {[char](($_ % 94) + 33)}) -join ''; $property.Value = $asciiJunk}}}; $script:jsondatabase = $null}

function wipe ([ref]$data) {# Byte variable overwriting and wiping.
if ($data.Value -is [byte[]] -and $data.Value.Length -gt 0) {$length = $data.Value.Length
for ($i = 0; $i -lt $script:keypasscount; $i++) {$multiplier = Get-Random -Minimum 1.1 -Maximum 3.9; $roundingMethod = Get-Random -InputObject 'Floor','Ceiling','Round'; $targetLength = [Math]::$roundingMethod($length * $multiplier); $junk = New-Object byte[] $targetLength; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($junk); [Array]::Copy($junk, 0, $data.Value, 0, $length)}
$data.Value = $null}
elseif ($data.Value -is [SecureString]) {$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($data.Value); [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $data.Value = $null}
$data = $null}

function scramble ([ref]$reference) {# String overwriting.
if ([string]::IsNullOrEmpty($reference.Value)) {return}
$length = $reference.Value.Length
for ($i = 0; $i -lt $script:keypasscount; $i++) {$multiplier = Get-Random -Minimum 1.1 -Maximum 3.9; $roundingMethod = Get-Random -InputObject 'Floor','Ceiling','Round'
$targetLength = [Math]::$roundingMethod($length * $multiplier); $junk = -join ((33..126) | Get-Random -Count $targetLength | ForEach-Object {[char]$_}); $reference.Value = $junk}
$reference.Value = $null; [GC]::Collect(); [GC]::WaitForPendingFinalizers()}

function neuralizer {# Wipe key and database from memory.
$script:unlocked = $false; $choice = $null; $script:timetoboot = Get-Date

if ($script:noclip -eq $false) {clearclipboard 0 64}

$stopwatch_corrupt = [System.Diagnostics.Stopwatch]::StartNew()
corruptdatabase
$stopwatch_corrupt.Stop()

$wipearray = @($aeskey, $bytes, $bytes1, $bytes2, $cipherbytes, $ciphertext, $compressedbytes, $decrypted, $decryptedbytes, $decryptedkey, $derivedkey, $enc, $encRoot, $enckey, $encryptedbytes, $encryptedkey, $entries, $entry, $entrymatches, $filtered, $finalbytes, $hash, $hmacbytes, $hmacdata, $hmackey, $imported, $iv, $jsonbytes, $key, $keywithmarker, $marker, $matches, $newentry, $newwrapkey, $newwrapsalt, $output, $pass, $password, $plain, $plainbytes, $plainpwd, $plaintext, $protectedbytes, $protectkey, $raw, $real, $refparsedchoice, $rootkey, $salt, $script:key, $secure, $secure1, $secure2, $securemaster, $str1, $str2, $unwrapped, $verifKey, $verifSalt, $verifkey, $verifsalt, $wrapSalt, $wrapkey, $wrapsalt)
$stopwatch_wipe = [System.Diagnostics.Stopwatch]::StartNew()
foreach ($item in $wipearray) {if ($item) {wipe ([ref]$item)}}
$stopwatch_wipe.Stop()

$scramblearray = @($bstr, $chars, $computedhash, $coreparts, $encroot, $encryptedpassword, $existing, $expected, $gen, $getdatabase, $getkey, $input, $invalidentry, $joined, $json, $jsontext, $keep, $key, $master, $newpwd, $newpwd2, $oldpwd, $passplain, $password, $passwordhistory, $passwordplain, $plain, $plainpassword, $plaintext, $pwchars, $result, $selected.password, $selected.username, $storedhash, $str, $updatepass, $username, $value, $wipecsv)
$stopwatch_scramble = [System.Diagnostics.Stopwatch]::StartNew()
foreach ($item in $scramblearray) {if ($item) {scramble ([ref]$item)}}
$stopwatch_scramble.Stop()

if ($script:quit) {scramble ([ref]$script:message); scramble ([ref]$script:warning); $securymemorytime = ([math]::Round($stopwatch_wipe.Elapsed.TotalSeconds, 2)) + ([math]::Round($stopwatch_scramble.Elapsed.TotalSeconds, 2)) + ([math]::Round($stopwatch_corrupt.Elapsed.TotalSeconds, 2)); $script:message += "Clearing the database and memory artifacts took $securymemorytime seconds."}}


#---------------------------------------------LOGGING----------------------------------------------

function logchoices ($choice, $message, $warning){# Log user actions.
# Do not log if the user has turned off logging.
if ($script:disablelogging) {return}

# Redact sensitive lines from message
if ($message) {$logmessage = ($message -replace '🔐 Password:.*', '🔐 Password: [REDACTED]' -replace '🔗 URL: .*', '🔗 URL:      [REDACTED]' -replace '🆔 UserName:.*', '🆔 UserName: [REDACTED]') -split '(?m)^[-]{10,}' | Select-Object -First 1}

# Map keys to descriptions.
$map = @{'R' = '[R]etrieve an entry.';
'A' = '[A]dd a new entry.';
'C' = '[C]hange an existing entry.';
'X' = 'Remove an entry.';
'B' = '[B]rowse all entries.';
'E' = '[E]xpired entries view.';
'S' = '[S]earch entries.';
'N' = '[N]etwork IPs.';
'V' = '[V]alid URLs.';
'I' = '[I]nvalid URLs.';
'M' = '[M]anagement Menu.';
'Z' = 'Toggle clipboard.'}

$managementmap = @{'N' = 'Create a [N]ew password database.';
'S' = '[S]anitize a PWDB file, correcting IV collisions.';
'I' = '[I]mport a CSV plaintext password database.';
'E' = '[E]xport database to CSV, but encryption remains intact.';
'F' = '[F]ull database export with unencrypted passwords.';
'P' = '[P]assword change for database access key.';
'J' = '[J]oin the database to a Master key.';
'W' = '[W]rite a new Master password.';
'G' = '[G]rant Master key privileges.';
'B' = '[B]ackup current database, key and privilege directory.';
'R' = '[R]estore a backup.';
'V' = '[V]iew the user registry.';
'A' = '[A]dd a user.';
'C' = '[C]hange user details.';
'Z' = 'New workspace setup Wi[Z]ard.';
'X' = 'Remove a user.';
'M' = '[M]ain Menu.'
'F4' = 'Toggle logging.';
'F10' = 'Modify configuration.';
'F12' = 'Save and sort database.'}

$sharedmap = @{'D' = 'Select a different password [D]atabase. ';
'K' = 'Select a different password encryption [K]ey.';
'L' = '[L]ock Session.';
'U' = '[U]nlock session.';
'F1' = '[H]elp.';
'H' = '[H]elp.';
'ESCAPE' = 'Quit.';
'Q' = 'Quit.';
'BACKSPACE' = 'Clear message center.';
'ENTER' = 'Clear message center.';
'T' = '[T]imer reset.';
'O' = 'L[O]ad defaults.';
'F9' = 'View configuration.'}

# Choose which keys are relevant.
$activemap = if ($script:management) {@{} + $managementmap + $sharedmap} else {@{} + $map + $sharedmap}

# Create directory, if it doesn't exist.
if (-not (Test-Path $script:logdir)) {New-Item $script:logdir -ItemType Directory -Force | Out-Null}

# Cleanup old logs (older than the number of days set in logretention, with the minimum set to 30 days).
Get-ChildItem -Path $script:logdir -Filter 'log - *.log' | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-[int]$script:logretention)} | Remove-Item -Force

# Create base file each session.
if (-not $script:logfile) {$timestamp = (Get-Date).ToString('MM-dd-yy @ HH_mm_ss'); $script:logfile = Join-Path $script:logdir "log - $timestamp.log"}

# Map unknown keys.
if (-not $activemap.ContainsKey($choice)) {Add-Content -Path $script:logfile -Value "$(Get-Date -Format 'HH:mm:ss') - UNRECOGNIZED: $choice"; return}

# Compile entry information.
$timestamp = Get-Date -Format 'HH:mm:ss'; $info = "$(if ($message) {" - MESSAGE: $logmessage"})$(if ($warning) {" - WARNING: $warning"})"; $entry = "$timestamp - $script:loggedinuser - $($activemap[$choice])$info`n" + ("-" * 100)

# Ensure log gets written by retrying 5 times for every log, to avoid race conditions.
$retries = 5
for ($i = 0; $i -lt $retries; $i++) {try {$fs = [System.IO.File]::Open($script:logfile, 'Append', 'Write', 'ReadWrite'); $sw = New-Object System.IO.StreamWriter($fs)
$sw.WriteLine($entry); $sw.Close(); $fs.Close(); break}
catch {Start-Sleep -Milliseconds 100}}}

function logcleanup {# Compress log files.

function gziplog ($inputFile, $outputFile = "$inputFile.gz") {$inputStream = [System.IO.File]::OpenRead($inputFile); $outputStream = [System.IO.File]::Create($outputFile); $gzipStream = New-Object System.IO.Compression.GZipStream($outputStream, [System.IO.Compression.CompressionMode]::Compress); $inputStream.CopyTo($gzipStream); $gzipStream.Close(); $inputStream.Close(); $outputStream.Close()}

$today = (Get-Date).Date; Get-ChildItem -Path $script:logdir -Filter 'log - *.log' | Where-Object {$_.Name -match '^log - (\d{2})-(\d{2})-(\d{2}) @'} | Group-Object {if ($_.Name -match '^log - (\d{2})-(\d{2})-(\d{2})') {$mm = $matches[1]; $dd = $matches[2]; $yy = $matches[3]; $fileDate = Get-Date "$mm-$dd-20$yy"
if ($fileDate -lt $today) {"$mm-$dd-$yy"} else {$null}}} | Where-Object {$_.Name} | ForEach-Object {$date = $_.Name; $output = Join-Path $script:logdir "log - $date.log"; $_.Group | Sort-Object LastWriteTime | ForEach-Object {Get-Content $_.FullName | Add-Content -Path $output}
$_.Group | ForEach-Object {Remove-Item $_.FullName -Force}
gziplog $output; Remove-Item $output -Force}}


#---------------------------------------------MASTER PASSWORD FUNCTIONS----------------------------

function initializeprivilege ([byte[]]$Key, [string]$Master) {# Generate root.key from child key and protect it with a master password.
if ($Key -and $Key.GetType().Name -ne 'Byte[]') {$script:warning += "❌ Key is not a byte array. Received: $($Key.GetType().FullName) "; nomessage; return}

if (-not $Key) {if (-not (Test-Path $script:keyfile)) {$script:warning += "Cannot initialize privileges: $script:keyfile does not exist. "; nomessage; return}

# Load and decrypt the existing .key file.
$loaded = [IO.File]::ReadAllBytes($script:keyfile); $salt = [byte[]]($loaded[0..15]); $protected = [byte[]]($loaded[16..($loaded.Length - 1)]); $protectKey = derivekeyfrompassword -Password $Master -Salt $salt; $plainKey = unprotectbytesaeshmac $protected $protectKey

if (-not ([System.Text.Encoding]::UTF8.GetString($plainKey[0..3]) -eq "SCHV")) {$script:warning += "Invalid key marker. Possible corruption. "; nomessage; return}
$Key = $plainKey[4..35]}
if ($Key.Length -eq 36 -and ([System.Text.Encoding]::UTF8.GetString($Key[0..3]) -eq "SCHV")) {$Key = $Key[4..35]}

# Prompt for the master password.
if (-not $Master) {Write-Host -f green "`n`n👑 Create a master password " -n; $secure1 = Read-Host -AsSecureString; $str = [System.Net.NetworkCredential]::new("", $secure1).Password

# Check the password against minimum password requirements.
if ($str -notmatch '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$') {$script:warning += "❌ The password must be at least 8 characters long and include upper-case and lower-case letters, digits and symbols. "; nomessage; return}

# Verify the password.
Write-Host -f green "👑 Confirm the master password " -n; $secure2 = Read-Host -AsSecureString
if (-not (comparesecurestring $secure1 $secure2)) {$script:warning += "Passwords do not match. "; nomessage; return}
$Master = [System.Net.NetworkCredential]::new("", $secure1).Password}

if (Test-Path $rootKeyFile) {$script:warning += "Privilege system already initialized. "; nomessage; return}

# Wrap the child key into root.key using a new random salt.
$wrapSalt = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($wrapSalt); $wrapKey = derivekeyfrompassword -Password $Master -Salt $wrapSalt; $encRoot = protectbytesaeshmac $Key $wrapKey; New-Item -ItemType Directory -Force -Path $privilegedir | Out-Null

[IO.File]::WriteAllBytes($rootKeyFile, $wrapSalt + $encRoot)

# Generate verification hash to validate the master password.
$verifSalt = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($verifSalt); $verifKey = derivekeyfrompassword -Password $Master -Salt $verifSalt; $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($verifKey); [System.IO.File]::WriteAllBytes($hashFile, $verifSalt + $hash)

# Confirm the root.key is functional.
if (-not (verifymasterpassword $Master)) {$script:warning += "❌ Initialization failed: unable to verify the master password after creation. "; nomessage; return}

$script:message += "Master password and privilege key initialized with random salt."; nomessage; rendermenu; return}

function verifymasterpassword ($Password) {# Verify the master password.
$script:switchtomaster = $false
try {$script:rootkey = loadprivilegekey $Password
if (-not $script:rootkey) {return $false}
if ($script:rootkey.Length -lt 32) {return $false}

# Normalize to exact 32 bytes (strip leading 0 if present)
$real = New-Object byte[] 32; [Array]::Copy($script:rootkey, $script:rootkey.Length - 32, $real, 0, 32); $script:rootkey = $real
if ($script:rootkey.Length -ne 32) {return $false}
return $true}
catch {return $false}}

function loadprivilegekey ($Password) {# Load the privileged key.
try {[byte[]]$enc = [IO.File]::ReadAllBytes($script:rootkeyFile); [byte[]]$wrapSalt = $enc[0..15]; [byte[]]$encRoot = $enc[16..($enc.Length - 1)]; $wrapKey = derivekeyfrompassword -Password $Password -Salt $wrapSalt; [byte[]]$unwrapped = unprotectbytesaeshmac $encRoot $wrapKey
if ($script:switchtomaster) {Write-Host -f yellow "   Press [Enter] to clear memory buffers. " -n; Read-Host}
if (-not $unwrapped -or $unwrapped.Length -lt 32) {return $null}
return $unwrapped}
catch {return $null}}

function derivekeyfrompassword ([object]$Password, [byte[]]$Salt) {# Returns the derived key for HMAC.
if ($Password -is [string]) {$secure = ConvertTo-SecureString $Password -AsPlainText -Force}
elseif ($Password -is [SecureString]) {$secure = $Password}
else {throw "The Password must be a string or SecureString."}

$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)}
finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)}

$pbkdf2 = [Security.Cryptography.Rfc2898DeriveBytes]::new($plain, $Salt, 100000, [Security.Cryptography.HashAlgorithmName]::SHA256)

try {return $pbkdf2.GetBytes(64)}
finally {$pbkdf2.Dispose()}}

function masterlockout {# Master password failure lockout.
$flagfile = Join-Path $script:privilegedir 'masterfailed.flag'; $failcount = 0; $lastfail = $null

if (Test-Path $flagfile) {$data = Get-Content $flagfile -Raw | ConvertFrom-Json -ea SilentlyContinue; $failcount = $data.failures; $lastfail = Get-Date $data.lastfail

if ((Get-Date) - $lastfail -gt [TimeSpan]::FromMinutes(30)) {Remove-Item $flagfile -Force; $failcount = 0; $lastfail = $null; $script:failedmaster = 0}}

if ($script:failedmaster -gt 0) {$failcount ++; $script:failedmaster = $failcount; $lastfail = Get-Date
@{failures = $failcount; lastfail = $lastfail.ToString("o")} | ConvertTo-Json | Set-Content -Path $flagfile -Encoding UTF8}

# If user is now locked out
if ($failcount -gt 3 -and $lastfail -and ((Get-Date) - $lastfail -lt [TimeSpan]::FromMinutes(30))) {$script:lockoutmaster = $true; $script:warning = "❌ Too many failed attempts. Access locked for 30 minutes."; nomessage; if ($script:loggedinuser) {rendermenu}; return $true}

$script:lockoutmaster = $false; return $false}

function resetmasterfailures {# Reset Master password failures after successful verification.
$script:failedmaster = 0; $flagfile = Join-Path $script:privilegedir 'masterfailed.flag'
if (Test-Path $flagfile) {Remove-Item $flagfile -Force}}


#---------------------------------------------BACKEND PRIVILEGE FUNCTIONS--------------------------

function decryptkey ($keyfile = $script:keyfile) {# Decrypt a keyfile and start session.
nomessage; nowarning
if (-not (Test-Path $keyfile -ea SilentlyContinue)) {$script:warning = "Encrypted key file not found."; nomessage; $script:key = $null; $script:keyfile = $null; $script:database = $null; return}

# Load raw key file
$raw = [IO.File]::ReadAllBytes($keyfile)
if ($raw.Length -lt 112) {$script:warning = "Key file is too short or malformed."; $script:key = $null; $script:keyfile = $null; $script:database = $null; nomessage; return}

# Split into salt and encrypted key blob
[byte[]]$salt = $raw[0..15]; [byte[]]$encKey = $raw[16..($raw.Length - 1)]

# Prompt for password
Write-Host -ForegroundColor Green "`n`t 🔐 Database Password: " -n; $secureMaster = Read-Host -AsSecureString; $plainMaster = [System.Net.NetworkCredential]::new("", $secureMaster).Password; $secureMaster.Dispose()

try {$wrapKey = derivekeyfrompassword -Password $plainMaster -Salt $salt; [byte[]]$decrypted = unprotectbytesaeshmac $encKey $wrapKey
if (-not $decrypted -or $decrypted.Length -lt 36) {$script:warning = "Decryption failed or the result was too short."; $script:key = $null; $script:keyfile = $null; $script:database = $null; nomessage; return}
$marker = [System.Text.Encoding]::UTF8.GetString($decrypted[0..3])
if ($marker -ne "SCHV") {$script:warning = "Invalid key marker. Possibly the wrong password."; $script:key = $null; $script:keyfile = $null; $script:database = $null; nomessage; return}
$script:key = $decrypted[4..35]; $script:unlocked = $true; $script:sessionstart = Get-Date; $script:timetoboot = $null}

catch {$script:warning = "Incorrect database password or corrupted key file. Clearing key and database settings."; $script:key = $null; $script:keyfile = $null; $script:database = $null; $script:unlocked = $false; nomessage; return}}

function createperentryhmac ([object]$entry, [byte[]]$key) {# Individual Entry HMAC.
$json = $entry | ConvertTo-Json -Compress -Depth 5; $bytes = [System.Text.Encoding]::UTF8.GetBytes($json); $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
try {$hash = $hmac.ComputeHash($bytes); $result = [Convert]::ToBase64String($hash)}
finally {$hmac.Dispose()}
return $result}

function verifyentryhmac ([object]$entry) {# Verify individual entry HMAC.
if (-not $entry.data -or -not $entry.hmac) {return $false}
$expected = createperentryhmac -entry $entry.data -key $script:key; return (comparebytearrays ([Convert]::FromBase64String($entry.hmac)) ([Convert]::FromBase64String($expected)))}

function protectbytesaeshmac ([byte[]]$Data, [byte[]]$Key) {# Derived from password, split into encryption & HMAC keys.
$aesKey = $Key[0..31]; $hmacKey = $Key[32..63]; $iv = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv); $aes = [System.Security.Cryptography.Aes]::Create(); $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; $aes.Key = $aesKey; $aes.IV = $iv; $encryptor = $aes.CreateEncryptor(); $cipherText = $encryptor.TransformFinalBlock($Data, 0, $Data.Length); $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey); $hmacData = $iv + $cipherText; $hmacBytes = $hmac.ComputeHash($hmacData); $encryptor.Dispose(); $aes.Dispose(); $hmac.Dispose(); return $hmacBytes + $hmacData}

function unprotectbytesaeshmac ([byte[]]$ProtectedBytes, [byte[]]$Key) {# Decrypt from password, split into encryption & HMAC keys.
[byte[]]$aesKey = $Key[0..31]; [byte[]]$hmacKey = $Key[32..63]; [byte[]]$hmacBytes = $ProtectedBytes[0..31]; [byte[]]$iv = $ProtectedBytes[32..47]; [byte[]]$cipherText = $ProtectedBytes[48..($ProtectedBytes.Length - 1)]; $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey); $hmacData = $iv + $cipherText; [byte[]]$computedHmac = $hmac.ComputeHash($hmacData); $hmac.Dispose()
if (-not [System.Linq.Enumerable]::SequenceEqual($hmacBytes, $computedHmac)) {$script:warning = "`nHMAC validation failed. Data may have been tampered with or corrupted. Proceed with caution!"; nomessage; return}
$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; $aes.Key = $aesKey; $aes.IV = $iv; $decryptor = $aes.CreateDecryptor(); $plainBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length); $decryptor.Dispose(); $aes.Dispose(); return [byte[]]$plainBytes}

function encryptpassword ($plaintext) {# Encrypt using AES-HMAC and Base64
$bytes = [Text.Encoding]::UTF8.GetBytes($plaintext); return [Convert]::ToBase64String((protectbytesaeshmac $bytes $script:key))}

function decryptpassword ($base64) {# Decrypt AES-HMAC Base64 password
$bytes = unprotectbytesaeshmac ([Convert]::FromBase64String($base64)) $script:key; 
return [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0x00..[char]0x1F)}


#---------------------------------------------LOAD & SAVE FUNCTIONS--------------------------------

function loadjson {# Load and decrypt the database.
if (-not (Test-Path $script:database -ea SilentlyContinue)) {$script:warning = "Database file not found: $script:database"; nomessage; return}
if (-not (Test-Path $script:keyfile -ea SilentlyContinue)) {$script:warning += "Keyfile not found: $script:keyfile"; nomessage; return}
if (-not $script:key) {$script:warning = "A key must be loaded before the database."; nomessage; return}

try {$bytes = [System.IO.File]::ReadAllBytes($script:database); $hmacStored = $bytes[-32..-1]; $ivPlusCipher = $bytes[0..($bytes.Length - 33)]; $hmac = [System.Security.Cryptography.HMACSHA256]::new($script:key); $hmacActual = $hmac.ComputeHash($ivPlusCipher)

if (-not (comparebytearrays $hmacStored $hmacActual)) {$script:warning = "⚠️  HMAC verification failed. The file may have been modified."; nomessage; return}

# Extract IV and Ciphertext.
$iv = $ivPlusCipher[0..15]; $cipherBytes = $ivPlusCipher[16..($ivPlusCipher.Length - 1)]

# AES decrypt.
$aes = [System.Security.Cryptography.Aes]::Create()
try {$aes.Key = $script:key; $aes.IV = $iv; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; $decryptor = $aes.CreateDecryptor(); $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length); $decryptor.Dispose()}
finally {$aes.Dispose()}

# Decompress.
$ms = [System.IO.MemoryStream]::new($decryptedBytes); $gzip = [System.IO.Compression.GzipStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress); $reader = [System.IO.StreamReader]::new($gzip); $jsonText = $reader.ReadToEnd(); $reader.Close()

$script:jsondatabase = $jsonText | ConvertFrom-Json; $script:message = "📑 Database loaded. "; nowarning; return}
catch {$script:warning = "Failed to load the database: $_"; nomessage; return}}

function loadregistry {# Load the user registry.
if ($script:keyfile) {$providedkeyname = [IO.Path]::GetFileNameWithoutExtension($script:keyfile); $script:registryfile = Join-Path $privilegedir "$providedkeyname.db"; if (-not ($script:users -is [System.Collections.IEnumerable])) {$script:users = @()}}
if (-not (Test-Path $script:registryfile -ea SilentlyContinue)) {$script:users = @(); $script:warning = "User registry not found."; nomessage return}
if (-not $script:key) {$script:registryfile = $null; $script:users = @(); $script:warning = "You must have a key loaded, in order to load a user registry."; nomessage; return}

try {[byte[]]$raw = [IO.File]::ReadAllBytes($script:registryfile); $decrypted = unprotectbytesaeshmac $raw $script:key
if (-not $decrypted) {throw "Decryption failed or null."}
$json = [System.Text.Encoding]::UTF8.GetString($decrypted); $parsed = ConvertFrom-Json $json -ea Stop
if (-not $parsed) {throw "Invalid JSON."}
$script:users = if ($parsed -is [System.Collections.IEnumerable]) {$parsed} else {@($parsed)}}
catch {$script:warning = "❌ Failed to load or decrypt the user registry: $_"; $script:users = @(); nomessage; return}}

function savetodisk {# Save database to disk (Serialize JSON → Compress → Encrypt → Append HMAC)
try {$jsonText = ,$script:jsondatabase | ConvertTo-Json -Depth 5 -Compress; if (-not $jsonText) {$jsonText = "[]"}; $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonText)

# Compress
$ms = [System.IO.MemoryStream]::new(); $gzip = [System.IO.Compression.GzipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress); $gzip.Write($jsonBytes, 0, $jsonBytes.Length); $gzip.Close(); $compressedBytes = $ms.ToArray()

# Encrypt
$aes = [System.Security.Cryptography.Aes]::Create()
try {$aes.Key = $script:key; $aes.GenerateIV(); $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; $encryptor = $aes.CreateEncryptor()
try {$cipherBytes = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length)}
finally {$encryptor.Dispose()}

$ivPlusCipher = $aes.IV + $cipherBytes

# Compute HMAC
$hmac = [System.Security.Cryptography.HMACSHA256]::new($script:key); $hmacBytes = $hmac.ComputeHash($ivPlusCipher)

# Final bytes = IV + Cipher + HMAC
$finalBytes = $ivPlusCipher + $hmacBytes}
finally {$aes.Dispose()}

# Write file
[System.IO.File]::WriteAllBytes($script:database, $finalBytes); $script:message = "✅ Updated database saved successfully to disk."; nowarning; return}
catch {$script:warning = "❌ Failed to save updated database: $_"; nomessage; return}}

function saveregistry {# Save the user registry.
if (-not ($script:users -is [System.Collections.IEnumerable])) {$script:users = @()}
if (-not $script:key) {$script:registryfile = $null; script:users = @(); $script:warning = "You must have a key loaded, in order to modify a user registry."; nomessage; return}
if ($script:keyfile) {$providedkeyname = [IO.Path]::GetFileNameWithoutExtension($script:keyfile); $script:registryfile = Join-Path $privilegedir "$providedkeyname.db"}

if (-not $script:users) {$script:users = @()}
try {$json = $script:users | ConvertTo-Json -Depth 5 -Compress; $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$encrypted = protectbytesaeshmac $bytes $script:key; [IO.File]::WriteAllBytes($script:registryfile, $encrypted)}
catch {$script:warning = "❌ Failed to save or encrypt the user registry: $_"; nomessage; return}}


#---------------------------------------------MAIN MENU--------------------------------------------

function retrieveentry ($database = $script:jsondatabase, $keyfile = $script:keyfile, $searchterm, $noclip) {

# Validate minimum search length.
if (-not $searchterm -or $searchterm.Length -lt 3) {$script:warning = "Requested match is too small. Aborting search."; nomessage; return}

# Ensure key is loaded, but use the cached key if unlocked.
if ($script:unlocked -eq $true) {$key = $script:realKey}
else {$key = decryptkey $keyfile; nomessage; nowarning
if (-not $key) {$script:warning = "🔑 No key loaded. " + $script:warning; nomessage; return}}

# Case-insensitive match on Title, URL, Tags, or Notes.
$entrymatches = @(); $script:warning = $null
foreach ($entry in $script:jsondatabase) {if ($entry.data.Title -match $searchterm -or $entry.data.Username -match $searchterm -or $entry.data.URL -match $searchterm -or $entry.data.Tags -match $searchterm -or $entry.data.Notes -match $searchterm) {if (-not (verifyentryhmac $entry)) {$script:warning += "Entry $($entry.data.title) has an invalid HMAC and will be ignored. "; nomessage; continue}
$entrymatches += $entry}}
$total = $entrymatches.Count

# Handle no matches or too many matches.
if ($total -eq 0) {$script:warning = "🔐 No entry found matching '$searchterm'"; nomessage; return}
elseif ($total -gt 15) {$script:warning = "Too many matches ($total). Please enter a more specific search."; nomessage; return}

# If exactly one match, select it directly.
if ($total -eq 1) {$selected = $entrymatches[0]}

# Between 2 and 15 matches, display menu for user selection.
else {$invalidentry = "`n"
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $total; $i++) {$m = $entrymatches[$i]
$notesAbbrev = if ($m.data.Notes.Length -gt 40) {$m.data.Notes.Substring(0, 37) + "..."} else {$m.data.Notes}
$notesAbbrev = $notesAbbrev -replace "\r?\n", ""
$urlAbbrev = if ($m.data.URL.Length -gt 45) {$m.data.URL.Substring(0, 42) + "..."} else {$m.data.URL}
$tagsAbbrev = if ($m.data.Tags.Length -gt 42) {$m.data.Tags.Substring(0, 39) + "..."} else {$m.data.Tags}
Write-Host -f Cyan ("{0}. " -f ($i + 1)).PadRight(4) -n; Write-Host -f Yellow "📜 Title: " -n; Write-Host -f White ($m.data.Title).PadRight(38) -n; Write-Host -f Yellow " 🆔 User: " -n; Write-Host -f White ($m.data.Username).PadRight(30) -n; Write-Host -f Yellow " 🔗 URL: " -n; Write-Host -f White $urlAbbrev.PadRight(46) -n; Write-Host -f Yellow "🏷️ Tags:  " -n; Write-Host -f White $tagsAbbrev.PadRight(42) -n; Write-Host -f Yellow " 📝 Notes: " -n; Write-Host -f White $notesAbbrev; Write-Host -f Gray ("-" * 100)}; Write-Host -f Red $invalidentry; Write-Host -f Yellow "🔍 Select an entry to view or Enter to cancel: " -n; $choice = Read-Host
if ($choice -eq "") {$script:warning = "Password retrieval cancelled by user."; nomessage; return}

$parsedChoice = 0; $refParsedChoice = [ref]$parsedChoice
if ([int]::TryParse($choice, $refParsedChoice) -and $refParsedChoice.Value -ge 1 -and $refParsedChoice.Value -le $total) {$selected = $entrymatches[$refParsedChoice.Value - 1]; break}
else {$invalidentry = "`nInvalid entry. Try again."}}
while ($true)}

# Decrypt password field safely.
$passwordplain = "🚫 <no password saved> 🚫"
if ($selected.data.Password -and $selected.data.Password -ne "") {try {$passwordplain = decryptpassword $selected.data.Password}
catch {$passwordplain = "⚠️ <unable to decrypt password> ⚠️"}}

# Copy to clipboard unless -noclip switch is set.
if (-not $noclip.IsPresent) {try {$passwordplain | Set-Clipboard; clearclipboard} 
catch {}}

# Compose formatted output message.
$script:message = "`n🗓️ Created:  $($selected.data.Created)`n⌛ Expires:  $($selected.data.Expires)`n📜 Title:    $($selected.data.Title)`n🆔 UserName: $($selected.data.Username)`n🔐 Password: $passwordplain`n🔗 URL:      $($selected.data.URL)`n🏷️ Tags:     $($selected.data.Tags)`n------------------------------------`n📝 Notes:`n`n$($selected.data.Notes)"; nowarning; return}

function newentry ($database = $script:database, $keyfile = $script:keyfile) {# Create a new entry.
$answer = $null; $confirmDup = $null

# Prompt for fields.
Write-Host -f yellow "`n`n📜 Enter Title: " -n; $title = Read-Host
if (-not $title) {$script:warning = "Every entry must have a Title, as well as a Username and URL. Aborted."; nomessage; return}
Write-Host -f yellow "🆔 Username: " -n; $username = Read-Host
if (-not $username) {$script:warning = "Every entry must have a Username, as well as a Title and URL. Aborted."; nomessage; return}

# Paschword generator.
Write-Host -f yellow "`nDo you want to use the Paschword generator? (Y/N) " -n; $generator = Read-Host
if ($generator -match '^[Yy]') {$password = paschwordgenerator; Write-Host -f yellow "Accept password? (Y/N) " -n; $accept = Read-Host
if ($accept -match '^[Nn]') {do {$password = paschwordgenerator -regenerate; Write-Host -f yellow "Accept password? (Y/N) " -n; $accept = Read-Host} while ($accept -match '^[Nn]')}; ""}
else {Write-Host -f yellow "🔐 Password: " -n; $password = Read-Host -AsSecureString; ""}

Write-Host -f yellow "🔗 URL: " -n; $url = Read-Host
if (-not $url) {$script:warning = "Every entry must have a URL, as well as a Title and Username. Aborted."; nomessage; return}
Write-Host -f yellow "⏳ How many days before this password should expire? (Default = 365): " -n; $expireInput = Read-Host; $expireDays = 365
if ([int]::TryParse($expireInput, [ref]$null)) {$expireDays = [int]$expireInput
if ($expireDays -gt 365) {$expireDays = 365}
if ($expireDays -lt -365) {$expireDays = -365}}
$expires = (Get-Date).AddDays($expireDays).ToString("yyyy-MM-dd")
Write-Host -f yellow "🏷️ Tags: " -n; $tags = Read-Host; $tags = ($tags -split ',') | ForEach-Object {$_.Trim()} | Where-Object {$_} | Join-String -Separator ', '
Write-Host -f yellow "📝 Notes (Enter, then CTRL-Z + Enter to end): " -n; $notes = [Console]::In.ReadToEnd()

# Decrypt key if needed
if ($script:unlocked -eq $false) {decryptkey $script:keyfile}

# Convert SecureString to plain and then encrypt.
if ($password -is [SecureString]) {try {$passwordPlain = [System.Net.NetworkCredential]::new("", $password).Password} catch {$passwordPlain = ""}}
else {$passwordPlain = $password}
if ([string]::IsNullOrWhiteSpace($passwordPlain)) {$secure = ""} else {$secure = encryptpassword $passwordPlain}

# Initialize or load in-memory database object.
if (-not $script:jsondatabase) {$script:jsondatabase = @()}

# Check for existing entry by Username and URL.
$existing = $script:jsondatabase | Where-Object {$_.Username -eq $username -and $_.URL -eq $url}

if ($existing) {Write-Host -f yellow "`n🔁 An entry already exists for '$username' at '$url'."; Write-Host -f yellow "`nDuplicate it? (Y/N) " -n; $answer = Read-Host

if ($answer -notmatch '^[Yy]') {Write-Host -f yellow "`nPlease update the entry:`n"; Write-Host -f yellow "📜 Enter Title ($($existing.Title)): " -n; $titleNew = Read-Host
if ([string]::IsNullOrEmpty($titleNew)) {$titleNew = $existing.Title} else {$title = $titleNew}
Write-Host -f yellow "🆔 Username ($($existing.Username)): " -n; $usernameNew = Read-Host
if ([string]::IsNullOrEmpty($usernameNew)) {$usernameNew = $existing.Username} else {$username = $usernameNew}
""; Write-Host -f yellow ("-" * 72)
indent "⚠️ WARNING! ⚠️" red 29
$nohistory = "By updating the entry this way, you will not be able to save a password history. If you wish to keep a history of old passwords, albeit in plaintext, abandon adding this as a new entry and choose the Update option, instead. Simply hit enter at the next prompt in order to abandon adding this entry.️"
$nohistory = wordwrap $nohistory
indent $nohistory white 2
Write-Host -f yellow ("-" * 72); ""
Write-Host -f green "🔐 Do you want to keep the original password or use the new one you just entered? (new/old) " -n; $keep = Read-Host
if ($keep -match "^(?i)old$") {$secure = $existing.Password}
elseif ($keep -match "^(?i)new$") {}
else {$script:warning = "Invalid choice. Aborting."; nomessage; return}
Write-Host -f yellow "🔗 URL ($($existing.URL)): " -n; $urlNew = Read-Host
if ([string]::IsNullOrEmpty($urlNew)) {$urlNew = $existing.URL} else {$url = $urlNew}
Write-Host -f yellow "🏷️ Tags ($($existing.tags)): " -n; $tagsNew = Read-Host
if ([string]::IsNullOrEmpty($tagsNew)) {$tagsNew = $existing.tags} else {$tags = $tagsNew}
Write-Host -f yellow "📝 Notes (CTRL-Z + Enter to end): " -n; $notesNew = [Console]::In.ReadToEnd()
if ([string]::IsNullOrEmpty($notesNew)) {$notesNew = $existing.notes} else {$notes = $notesNew}

# Check for no real changes except password.
if ($username -eq $existing.Username -and $url -eq $existing.URL -and $tags -eq $existing.tags -and $notes -eq $existing.notes) {Write-Host -f yellow "🤔 No changes detected. Overwrite entry? (Y/N) " -n; $confirmDup = Read-Host
if ($confirmDup -notmatch '^[Yy]') {$script:warning = "Entry not saved."; nomessage; $password = $null; $passwordplain = $null; return}}

# Remove old entry from in-memory
$script:jsondatabase = $script:jsondatabase | Where-Object {!($_.Username -eq $username -and $_.URL -eq $url)}}}

# Create the new entry object.
$data = [PSCustomObject]@{Title = $title
Username = $username
Password = $secure
URL = $url
Tags = $tags
Notes = $notes
Created = (Get-Date).ToString("yyyy-MM-dd")
Expires = $expires}
$hmac = createperentryhmac $data $script:key
$entry = [PSCustomObject]@{Data = $data; HMAC = $hmac}

if (-not $script:jsondatabase) {$script:jsondatabase = @()} 
elseif ($script:jsondatabase -isnot [System.Collections.IEnumerable] -or $script:jsondatabase -is [PSCustomObject]) {$script:jsondatabase = @($script:jsondatabase)}

# Add new entry to in-memory database and then to disk.
$script:jsondatabase += $entry; savetodisk}

function paschwordgenerator ($design, [switch]$regenerate) {# Create an intuitive password
$specialChars = '~!@#$%^&*_+=.,;:-'.ToCharArray(); $superSpecialChars = '(){}[]'.ToCharArray(); $leetMap = @{'a' = @('@','4'); 'e' = @('3'); 'h' = @('#'); 'l' = @('1','7','!'); 'o' = @('0'); 's' = @('5','$')}

# Load dictionary.
if (-not $script:dictionaryWords) {if (-not (Test-Path $script:dictionaryfile)) {throw "Dictionary file not found: $script:dictionaryfile"}
$script:dictionaryWords = Get-Content -Path $script:dictionaryfile | Where-Object {$_.Trim().Length -gt 0}}

# Present user options.
if (-not $regenerate) {Write-Host ""
Write-Host -f yellow ("-" * 100)
Write-Host -f cyan "Schmart Password Generator:"
Write-Host -f yellow ("-" * 100)
Write-Host -f yellow "Modes, presented in hierarchal order:`n"
Write-Host -f white "[" -n; Write-Host -f cyan "P" -n; Write-Host -f white "]IN, 4-12 digits only, the default is 6."
Write-Host -f white "[" -n; Write-Host -f cyan "H" -n; Write-Host -f white "]uman readable 'leet' code, 12-32 characters."
Write-Host -f white "[" -n; Write-Host -f cyan "D" -n; Write-Host -f white "]ictionary words only, 12-32 characters."
Write-Host -f white "[" -n; Write-Host -f cyan "A" -n; Write-Host -f white "]lphanumeric characters, 4-32 characters."
Write-Host -f yellow ("-" * 100)
Write-Host -f yellow "Modifiers:`n"
Write-Host -f white "[" -n; Write-Host -f cyan "X" -n; Write-Host -f white "]paces may appear between words for [D]/[H], randomly in [A], never as the first or last character."
Write-Host -f white "[" -n; Write-Host -f cyan "S" -n; Write-Host -f white "]pecial characters include: " -n; Write-Host -f cyan "~!@#$%^&*_-+=.,;:" -n; Write-Host -f white "."
Write-Host -f white "[" -n; Write-Host -f cyan "Z" -n; Write-Host -f white "]uper special characters also includes brackets: " -n; Write-Host -f cyan "(){}[]" -n; Write-Host -f white "."
Write-Host -f yellow ("-" * 100)
Write-Host -f yellow "Length:`n"
Write-Host -f white "[" -n; Write-Host -f cyan "#" -n; Write-Host -f white "] 4-32 characters, within the restrictions stated above."
Write-Host -f yellow ("-" * 100)
Write-Host -f yellow "`nPlease choose a combination of the options above (Default = " -n; Write-Host -f cyan "DXS12" -n; Write-Host -f yellow "): " -n; $script:design = Read-Host

if ([string]::IsNullOrWhiteSpace($script:design)) {$script:design = 'DXS12'}

$start = "The password will be created as "
if ($script:design -match 'P') {$base = "a PIN"}
elseif ($script:design -match 'H') {$base = "Human-readable text"}
elseif ($script:design -match 'D') {$base = "Dictionary words"}
elseif ($script:design -match 'A') {$base = "Alphanumeric characters"}
if ($script:design -match 'X') {$spaces = ", allowing spaces"} else {$spaces = ""}
if ($script:design -match 'Z') {$specials = ", using special characters, as well as brackets"}
elseif ($script:design -match 'S') {$specials = ", using special characters"}
else {$specials = ""}
if ($script:design -match '(\d+)') {[int]$number = $matches[1]
if ($script:design -match 'P' -and $number -gt 16) {$number = 16}
elseif ($script:design -match 'D' -and $number -lt 12) {$number = 12}
$length = ", with a length of $number."} 
else {$length = "."}
if ($script:design -match 'P') {$builder = "$start$base$length"}
else {$builder = "$start$base$spaces$specials$length"}

Write-Host -f darkgray ("-" * 100)
Write-Host -f darkgray "$builder`n"; Write-Host -f yellow "Results:  " -n; Write-Host -f darkgray "N3w PaSsWoRd (" -n

$sample = "Co1our_By_Ch@ract3r_Type"
$sample.ToCharArray() | ForEach-Object {switch -regex ($_) {'(?-i)[A-Z]' {Write-Host -f gray $_ -n; continue}
'(?-i)[a-z]' {Write-Host -f darkgray $_ -n; continue}
'\d' {Write-Host -f cyan $_ -n; continue}
"[$($specialChars -join '')]" {Write-Host -f yellow $_ -n; continue}
"[$($superSpecialChars -join '')]" {Write-Host -f green $_ -n; continue}
' ' {Write-Host -b blue $_ -n; continue}
default {Write-Host -f magenta $_ -n}}}

Write-Host -f darkgray ")"; Write-Host -f darkgray ("-" * 100)}

# Parse input.
$null = $script:design
$flagsRaw = ($script:design -replace '\d','').ToCharArray(); $length = [int]($script:design -replace '\D','')
if (-not $length -and $script:design -match 'P') {$length = 4}
elseif (-not $length) {$length = 8}

# Clamp length with overrides
if ($script:design -match 'P') {$length = [Math]::Min([Math]::Max($length,4),12)}
elseif ($script:design -match 'D') {$length = [Math]::Max($length,12)}
else {$length = [Math]::Min([Math]::Max($length,4),32)}

# Special character flags (case-sensitive)
$useSpaces = $flagsRaw -contains 'X'; $useNormalSpecial = $flagsRaw -contains 'S'; $useSuperSpecial = $flagsRaw -contains 'Z'

# Determine effective mode (uppercase-insensitive)
$upperFlags = $flagsRaw | ForEach-Object {$_.ToString().ToUpperInvariant()}
if ($upperFlags -contains 'P') {$mode = 'P'}
elseif ($upperFlags -contains 'H') {$mode = 'H'}
elseif ($upperFlags -contains 'D') {$mode = 'D'}
else {$mode = 'A'}

#-------------------------PIN generator-------------------------

function generatepin($len) {$digits = 0..9; $pin = -join (1..$len | ForEach-Object {Get-Random -InputObject $digits})
return $pin}

#-------------------------Standard alphanumeric password generator-------------------------

function generatealphanumeric($len, $useSpaces, $useNormalSpecial, $useSuperSpecial) {$baseChars = @(); $specials = @()
$lower = [char[]]'abcdefghijklmnopqrstuvwxyz'
$upper = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
$digit = [char[]]'0123456789'
if ($useNormalSpecial) {$specials += $specialChars}
if ($useSuperSpecial) {$specials += $superSpecialChars}
$baseChars += $lower + $upper + $digit + $specials

# Build initial password
$pwChars = 1..$len | ForEach-Object {Get-Random -InputObject $baseChars}

# Enforce at least one lowercase, uppercase, and digit
if (-not ($pwChars -join '' -cmatch '[a-z]')) {$pwChars[(Get-Random -Minimum 0 -Maximum $len)] = Get-Random -InputObject $lower}
if (-not ($pwChars -join '' -cmatch '[A-Z]')) {$pwChars[(Get-Random -Minimum 0 -Maximum $len)] = Get-Random -InputObject $upper}
if (-not ($pwChars -join '' -cmatch '\d')) {$pwChars[(Get-Random -Minimum 0 -Maximum $len)] = Get-Random -InputObject $digit}

# Enforce at least one special if requested
if ($specials.Count -gt 0 -and -not ($pwChars -join '' -cmatch '[\[\]{}()<>|\\\/?!@#\$%\^&\*\-_=\+\.,;:]')) {$pwChars[(Get-Random -Minimum 0 -Maximum $len)] = Get-Random -InputObject $specials}

# Insert spaces if requested, avoiding first character
if ($useSpaces) {$maxSpaces = [Math]::Floor($len / 4); $spaceCount = Get-Random -Minimum 1 -Maximum ([Math]::Max(2, $maxSpaces)); $positions = 1..($len - 1) | Get-Random -Count $spaceCount
foreach ($pos in $positions) {$pwChars[$pos] = ' '}}

return -join $pwChars}

#-------------------------Word helpers-------------------------

function addleet($password) {

function transformWord($word) {$chars = $word.ToCharArray()
for ($i = 0; $i -lt $chars.Length; $i++) {$c = $chars[$i].ToString().ToLower()
if ($leetMap.ContainsKey($c) -and (Get-Random -Minimum 0 -Maximum 4) -eq 3) {$subs = $leetMap[$c]; $chars[$i] = $subs | Get-Random}}
return -join $chars}

return [regex]::Replace($password, '[a-zA-Z]{4,}', {param($match) transformWord $match.Value})}

function randomizecase($word) {$chars = $word.ToCharArray(); $forceIndex = Get-Random -Minimum 0 -Maximum $chars.Length
for ($i = 0; $i -lt $chars.Length; $i++) {$chars[$i] = if ((Get-Random -Minimum 0 -Maximum 2) -eq 1) {[char]::ToUpper($chars[$i])}
else {[char]::ToLower($chars[$i])}}
$upperCount = ($chars | Where-Object {$_ -cmatch '[A-Z]'}).Count; $lowerCount = $chars.Length - $upperCount; $chars[$forceIndex] = if ($upperCount -gt $lowerCount) {[char]::ToLower($chars[$forceIndex])}
else {[char]::ToUpper($chars[$forceIndex])}
return -join $chars}

function addjoiners($words, $useSpaces, $useNormalSpecial, $useSuperSpecial) {
# Prepare special pool
$specialPool = @()
$numbers = @('0','1','2','3','4','5','6','7','8','9')
if ($useNormalSpecial) {$specialPool += $specialChars}
if ($useSuperSpecial) {$specialPool += $superSpecialChars}

# Prepare joiner pool for filler joiners (space, special, number)
$fillerJoiners = @()
if ($useSpaces) {$fillerJoiners += ' '}
if ($specialPool.Count) {$fillerJoiners += $specialPool}
if ($numbers.Count) {$fillerJoiners += $numbers}

# Select 1 number, 1 special, 1 word for the mandatory core part and shuffle
$mandatoryNumber = ($numbers | Get-Random); $mandatorySpecial = ($specialPool | Get-Random); $mandatoryWord = ($words | Get-Random)
$coreParts = @($mandatoryNumber, $mandatorySpecial, $mandatoryWord) | Sort-Object {Get-Random}

# Build password starting with core parts joined without spaces
$remainingWords = $words | Where-Object {$_ -ne $mandatoryWord}
$password = -join $coreParts
for ($i=0; $i -lt $remainingWords.Count; $i++) {$joiner = ''
if ($fillerJoiners.Count -gt 0) {$joiner = $fillerJoiners | Get-Random
if ((Get-Random -Minimum 1 -Maximum 4) -ne 1) {$joiner = ''}}
$password += $joiner + $remainingWords[$i]}

return $password}

#-------------------------Human readable password generator-------------------------

function generatehumanreadable($len, $useSpaces, $useNormalSpecial, $useSuperSpecial) {$words = @(); $totalLength = 0
while ($totalLength -lt $len) {$w = Get-Random -InputObject $script:dictionaryWords; $words += $w; $totalLength += $w.Length}

$words = $words | ForEach-Object {randomizecase $_} | ForEach-Object {addleet $_}
$password = addjoiners $words $useSpaces $useNormalSpecial $useSuperSpecial

if ($password.Length -gt $len) {$password = $password.Substring(0, $len)}
elseif ($password.Length -lt $len) {$password = $password.PadRight($len, (Get-Random -InputObject ([char[]]'abcdefghijklmnopqrstuvwxyz')))}
return $password}

#-------------------------Dictionary password generator-------------------------

function generatedictionary($len, $useSpaces, $useNormalSpecial, $useSuperSpecial) {$words = @(); $totalLength = 0

# Pick words until near or above length or max count reached
while ($totalLength -lt $len -and $words.Count -lt 10) {$w = Get-Random -InputObject $script:dictionaryWords; $words += $w; $totalLength += $w.Length}

# Randomize casing of each word and build with joiners
$words = $words | ForEach-Object {randomizecase $_}
$password = addjoiners $words $useSpaces $useNormalSpecial $useSuperSpecial

# Truncate if too long, pad if too short.
if ($password.Length -gt $len) {$password = $password.Substring(0, $len)}
while ($password.Length -lt $len) {$allowedChars = @('a'..'z') + ('A'..'Z') + ('0'..'9')
if ($useNormalSpecial) {$allowedChars += $specialChars}
if ($useSuperSpecial) {$allowedChars += $superSpecialChars}
$password += (Get-Random -InputObject $allowedChars)}

# No trailing spaces from joiners or padding
while ($password[-1] -eq ' ') {$password = $password.Substring(0, $password.Length - 1) + (Get-Random -InputObject ([char[]]'abcdefghijklmnopqrstuvwxyz'))}

return $password}

#-------------------------Main dispatch-------------------------

$password = switch ($mode) {'P' {generatepin -len $length}
'A' {generatealphanumeric -len $length -useSpaces $useSpaces -useNormalSpecial $useNormalSpecial -useSuperSpecial $useSuperSpecial}
'H' {generatehumanreadable -len $length -useSpaces $useSpaces -useNormalSpecial $useNormalSpecial -useSuperSpecial $useSuperSpecial}
'D' {generatedictionary -len $length -useSpaces $useSpaces -useNormalSpecial $useNormalSpecial -useSuperSpecial $useSuperSpecial}}

Write-Host -f yellow "Password: " -n; Write-Host -f darkgray "$password (" -n

$password.ToCharArray() | ForEach-Object {switch -regex ($_) {'(?-i)[A-Z]' {Write-Host -f gray $_ -n; continue}
'(?-i)[a-z]' {Write-Host -f darkgray $_ -n; continue}
'\d' {Write-Host -f cyan $_ -n; continue}
"[$($specialChars -join '')]" {Write-Host -f yellow $_ -n; continue}
"[$($superSpecialChars -join '')]" {Write-Host -f green $_ -n; continue}
' ' {Write-Host -b blue $_ -n; continue}
default {Write-Host -f magenta $_ -n}}}
Write-Host -f darkgray ") " -n;

return $password}

function updateentry ($database = $script:jsondatabase, $keyfile = $script:keyfile, $searchterm) {# Find and update an existing entry.
$passwordplain = $null

# Validate search term.
if (-not $searchterm -or $searchterm.Length -lt 3) {$script:warning = "Search term too short. Use 3 or more characters."; nomessage; return}

# Load key if needed.
$key = if ($script:unlocked) {$script:realKey} else {decryptkey $keyfile; nowarning; nomessage}
if (-not $script:key) {$script:warning = "🔑 No key loaded. "; nomessage; return}

# Match entries by Title, Username, URL, Tags, Notes.
$searchterm = "(?i)$searchterm"; $searchterm = $searchterm -replace '\s*,\s*', '.+'
$entryMatches  = @(); foreach ($entry in $database) {$fullentry = "$($entry.data.Title) $($entry.data.Username) $($entry.data.URL) $($entry.data.Tags -join ' ') $($entry.data.Notes)"
if ($fullentry -match $searchterm) {$entryMatches += $entry}}

# Handle results.
if ($entryMatches.Count -eq 0) {$script:warning = "No entry found matching '$searchterm'."; nomessage; return}

elseif ($entryMatches.Count -gt 15) {$script:warning = "Too many matches ($($entryMatches.Count)). Please refine your search."; nomessage; return}

elseif ($entryMatches.Count -gt 1) {$invalidentry = "`n"
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $entryMatches.Count; $i++) {$m = $entryMatches[$i];
$notesAbbrev = if ($m.data.Notes.Length -gt 40) {$m.data.Notes.Substring(0,37) + "..."} else {$m.data.Notes}
$urlAbbrev = if ($m.data.URL.Length -gt 45) {$m.data.URL.Substring(0,42) + "..."} else {$m.data.URL}
$tagsAbbrev = if ($m.data.Tags.Length -gt 42) {$m.data.Tags.Substring(0,39) + "..."} else {$m.data.Tags}
Write-Host -f Cyan "$($i + 1). ".PadRight(4) -n
Write-Host -f yellow "📜 Title: " -n; Write-Host -f white $($m.data.Title).PadRight(38) -n
Write-Host -f yellow " 🆔 User: " -n; Write-Host -f white $($m.data.Username).PadRight(30) -n
Write-Host -f yellow " 🔗 URL: " -n; Write-Host -f white $urlAbbrev.PadRight(46)
Write-Host -f yellow "🏷  Tags: " -n; Write-Host -f white $tagsAbbrev.PadRight(44) -n
Write-Host -f yellow "📝 Notes: " -n; Write-Host -f white $notesAbbrev
Write-Host -f gray ("-" * 100)}
Write-Host -f red $invalidentry
Write-Host -f yellow "❌ Select an entry to update or Enter to cancel: " -n; $choice = Read-Host
if ($choice -eq "") {$script:warning = "Update cancelled."; nomessage; return}
$parsedChoice = 0; $refParsedChoice = [ref]$parsedChoice
if ([int]::TryParse($choice, $refParsedChoice) -and $refParsedChoice.Value -ge 1 -and $refParsedChoice.Value -le $entryMatches.Count) {$entry = $entryMatches[$refParsedChoice.Value - 1]; break}
else {$invalidentry = "`nInvalid entry. Try again."}}
while ($true)}

else {$entry = $entryMatches[0]}

$passwordplain = if ([string]::IsNullOrWhiteSpace($entry.data.Password)) {""}
else {try {decryptpassword $entry.data.Password}
catch {"[decryption failed]"}}

Write-Host -f white "`n🗓️ Created:  $($entry.data.Created)`n⌛ Expires:  $($entry.data.Expires)`n📜 Title:    $($entry.data.Title)`n🆔 UserName: $($entry.data.Username)`n🔐 Password: $passwordplain`n🔗 URL:      $($entry.data.URL)`n🏷️ Tags:     $($entry.data.Tags)`n------------------------------------`n📝 Notes:`n`n$($entry.data.Notes)"

# Prompt user for updated values.
Write-Host -f yellow "`n📝 Update entry fields. Leave blank to keep the current value.`n"
Write-Host -f white "📜 Title ($($entry.data.Title)): " -n; $title = Read-Host
Write-Host -f white "🆔 Username ($($entry.data.Username)): " -n; $username  = Read-Host

# Password choice.
Write-Host -f yellow "`n🔐 Do you want to update the password? (Y/N) " -n; $updatepass = Read-Host
if ($updatepass -match '^[Yy]') {Write-Host -f yellow "🔐 Do you want to want to keep a history of the old password in Notes? (Y/N) " -n; $passwordhistory = Read-Host
Write-Host -f yellow "Use Paschword generator? (Y/N) " -n; $gen = Read-Host

# Paschword generator.
if ($gen -match '^[Yy]') {$passplain = paschwordgenerator; Write-Host -f yellow "Accept password? (Y/N) " -n; $accept = Read-Host
while ($accept -match '^[Nn]') {$passplain = paschwordgenerator -regenerate; Write-Host -f yellow "Accept password? (Y/N) " -n; $accept = Read-Host}
try {$secure = encryptpassword $passplain $key}
catch {$script:warning = "Password encryption failed."; nomessage; return}}

# Manual password.
else {Write-Host -f yellow "🔐 Password: " -n; $pass = Read-Host -AsSecureString
try {$passplain = [System.Net.NetworkCredential]::new("", $pass).Password}
catch {$passplain = ""}
if ([string]::IsNullOrWhiteSpace($passplain)) {$secure = ""}
else {try {$secure = encryptpassword $passplain $key}
catch {$script:warning = "Password encryption failed."; nomessage; return}}}}

Write-Host -f white "`n🔗 URL ($($entry.data.URL)): " -n; $url = Read-Host 
Write-Host -f white  "⏳ Days before expiry (default: keep $($entry.data.Expires)) " -n; $expireIn = Read-Host
Write-Host -f white "🏷️ Tags ($($entry.data.Tags)): " -n; $tags = Read-Host
Write-Host -f white "📝 Notes (CTRL-Z, Enter to leave unchanged): " -n
$notesIn = [Console]::In.ReadToEnd()
Write-Host -f yellow  "`nAre you satisfied with everything? (Y/N) " -n; $abandon = Read-Host
if ($abandon -notmatch "^[Yy]") {$script:warning = "Abandoned updating entry."; nomessage; return}

# Expiration logic.
if ([int]::TryParse($expireIn, [ref]$null)) {$expireDays = [int]$expireIn
if ($expireDays -gt 365) {$expireDays = 365}
if ($expireDays -lt -365) {$expireDays = -365}
$expires = (Get-Date).AddDays($expireDays).ToString("yyyy-MM-dd")}
else {$expires = $entry.data.Expires}

# Validate HMAC.
if (-not (verifyentryhmac $entry)) {$script:warning = "❌ Entry '$($entry.data.Title)' failed HMAC validation. Tampering suspected. Aborted."; nomessage; return}

# Apply updated values.
$data = $entry.Data

$data.Title = if ($title) {$title} else {$data.Title}
$data.Username = if ($username) {$username} else {$data.Username}
$data.Password = $secure
$data.URL = if ($url) {$url} else {$data.URL}
$data.Tags = if ($tags) {($tags -split ',') | ForEach-Object {$_.Trim()} | Where-Object {$_} | Join-String -Separator ', '} else {$data.Tags}
$data.Notes = if ($notesIn) {$notesIn -replace '[^\u0009\u000A\u000D\u0020-\u007E]', ''} else {$data.Notes -replace '[^\u0009\u000A\u000D\u0020-\u007E]', ''}
$data.Expires = $expires

# Handle password history.
$updatedtoday = Get-Date -Format "yyyy-MM-dd"
if ($passwordhistory -match "[Yy]") {if (-not [string]::IsNullOrWhiteSpace($data.Notes)) {$data.Notes = $data.Notes.TrimEnd(); $data.Notes += "`n------------------------------------`n"}
$data.Notes += "[OLD PASSWORD] $passwordplain (valid from $($data.Created) to $updatedtoday)"}

$data.Created = $updatedtoday

# Recompute and update HMAC.
$entry.HMAC = createperentryhmac $data $script:key

# Save and confirm.
$script:jsondatabase = $database; $script:message = "`n✅ Entry successfully updated."; nowarning; savetodisk; return}

function removeentry ($searchterm) {# Remove an entry.

# Error-checking.
if (-not $script:jsondatabase) {$script:warning = "📑 No database loaded. "; nomessage; return}
if ($searchterm.Length -lt 3) {$script:warning = "Search term too short. Aborting removal."; nomessage; return}

$matches = $script:jsondatabase | Where-Object {$_.data.Title -match $searchterm -or $_.data.Username -match $searchterm -or $_.data.URL -match $searchterm -or $_.data.Tags -match $searchterm -or $_.data.Notes -match $searchterm}
$count = $matches.Count
if ($count -eq 0) {$script:warning = "No entries found matching '$searchterm'."; nomessage; return}
elseif ($count -gt 15) {$script:warning = "Too many matches ($count). Please refine your search."; nomessage; return}

if ($count -eq 1) {$selected = $matches[0]}
else {$invalidentry = "`n"
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $count; $i++) {$m = $matches[$i]
$notesAbbrev = if ($m.data.Notes.Length -gt 40) {$m.data.Notes.Substring(0,37) + "..."} else {$m.data.Notes}
$urlAbbrev = if ($m.data.URL.Length -gt 45) {$m.data.URL.Substring(0,42) + "..."} else {$m.data.URL}
$tagsAbbrev = if ($m.data.Tags.Length -gt 42) {$m.data.Tags.Substring(0,39) + "..."} else {$m.data.Tags}
Write-Host -f Cyan "$($i + 1). ".PadRight(4) -n
Write-Host -f yellow "📜 Title: " -n; Write-Host -f white $($m.data.Title).PadRight(38) -n
Write-Host -f yellow " 🆔 User: " -n; Write-Host -f white $($m.data.Username).PadRight(30) -n
Write-Host -f yellow " 🔗 URL: " -n; Write-Host -f white $urlAbbrev.PadRight(46)
Write-Host -f yellow "🏷  Tags: " -n; Write-Host -f white $tagsAbbrev.PadRight(44) -n
Write-Host -f yellow "📝 Notes: " -n; Write-Host -f white $notesAbbrev
Write-Host -f gray ("-" * 100)}
Write-Host -f red $invalidentry
Write-Host -f yellow "❌ Select an entry to remove or Enter to cancel: " -n; $choice = Read-Host
if ($choice -eq "") {$script:warning = "Entry removal cancelled."; nomessage; return}
$parsedChoice = 0; $refParsedChoice = [ref]$parsedChoice
if ([int]::TryParse($choice, $refParsedChoice) -and $refParsedChoice.Value -ge 1 -and $refParsedChoice.Value -le $count) {$selected = $matches[$refParsedChoice.Value - 1]; break}
else {$invalidentry = "`nInvalid entry. Try again."}}
while ($true)}

# Notify about HMAC failure.
$hmacValid = verifyentryhmac $selected
if (-not $hmacValid) {Write-Host -f red "⚠️  Warning: This entry failed HMAC validation and may have been tampered with.`n"}

# Confirm deletion.
Write-Host -f red "`n🗓️ Created:   " -n; Write-Host -f white "$($selected.data.Created)"
Write-Host -f red "⌛ Expires:   " -n; Write-Host -f white "$($selected.data.Expires)"
Write-Host -f red "📜 Title:     " -n; Write-Host -f white "$($selected.data.Title)"
Write-Host -f red "🆔 UserName:  " -n; Write-Host -f white "$($selected.data.Username)"
Write-Host -f red "🔗 URL:       " -n; Write-Host -f white "$($selected.data.URL)"
Write-Host -f red "🏷  Tags:      " -n; Write-Host -f white "$($selected.data.Tags)"
Write-Host -f white "------------------------------------"
Write-Host -f red "📝 Notes:`n"; Write-Host -f white "$($selected.data.Notes)"
Write-Host -f cyan "`nType 'YES' to confirm removal: " -n; $confirm = Read-Host
if ($confirm -ne "YES") {$script:warning = "Removal aborted."; nomessage; return}

# Remove entry from in-memory database and save to disk.
$script:jsondatabase = @($script:jsondatabase | Where-Object {$_ -ne $selected}); savetodisk}

function showentries ($entries, $pagesize = 30, [switch]$expired, [switch]$search, $keywords, [switch]$ips, [switch]$invalidurls, [switch]$validurls) {# Browse entire database.
$sortField = $null; $descending = $false; $ippattern = "(?i)(\d{1,3}\.){3}\d{1,3}"; $urlpattern = "(?i)(\w+?:\/\/|www\.|^[A-Z\d-]{3,}\.[A-Z\d-]{2,})"

# Expired filter.
if ($expired) {$entries = $entries | Where-Object {[datetime]$_.data.Expires -le $(Get-Date)}}

# Search filter.
if ($search) {$filtered = @()
foreach ($entry in $entries) {if ($entry.data.Title -match $keywords -or $entry.data.Username -match $keywords -or $entry.data.URL -match $keywords -or $entry.data.Tags -match $keywords -or $entry.data.Notes -match $keywords) {if (-not (verifyentryhmac $entry)) {$script:warning += "Entry $($entry.data.title) has an invalid HMAC and will be ignored. "; nomessage; continue}
$filtered += $entry}}
$entries = $filtered}

# Find IP filter.
if ($ips) {$filtered = @()
foreach ($entry in $entries) {$url = $entry.data.URL
if ($url -match $ippattern) {$filtered += $entry}}
$entries = $filtered}

# Invalid URL filter.
if ($invalidurls) {$filtered = @()
foreach ($entry in $entries) {$url = $entry.data.URL
if ($url -notmatch $ippattern -and $url -notmatch $urlpattern) {$filtered += $entry}}
$entries = $filtered}

# Valid URL filter.
if ($validurls) {$filtered = @()
foreach ($entry in $entries) {$url = $entry.data.URL
if ($url -match $urlpattern) {$filtered += $entry}}
$entries = $filtered}

# Bail out if no entries
$total = $entries.Count
if ($total -eq 0) {$script:warning = "No entries to view."; nomessage; return}
if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) {$entries = @($entries); $exportset = @($entries)}

$page = 0
while ($true) {cls; if ($sortField) {$entries = @(if ($descending) {$entries | Sort-Object $sortField -Descending} else {$entries | Sort-Object $sortField})}
$start = $page * $pagesize; $end = [math]::Min($start + $pagesize - 1, $total - 1); $chunk = $entries[$start..$end]

# Show expired entries header if filtered by expired
if ($expired) {Write-Host -f White "Expired Entries: " -n; Write-Host -f Gray "The following entries are older than their expiry date since last update."; Write-Host -f Yellow ("-" * 130)}

# Display the entries in a formatted table
$chunk | Select-Object `
@{Name='Title'; Expression = {if ($_.data.Title.Length -gt 25) {$_.data.Title.Substring(0,22) + '...'} else {$_.data.Title}}}, `
@{Name='Username'; Expression = {if ($_.data.Username.Length -gt 25) {$_.data.Username.Substring(0,22) + '...'} else {$_.data.Username}}}, `
@{Name='URL'; Expression = {if ($_.data.URL.Length -gt 40) {$_.data.URL.Substring(0,37) + '...'} else {$_.data.URL}}}, `
@{Name='Tags'; Expression = {if ($_.data.Tags.Length -gt 15) {$_.data.Tags.Substring(0,12) + '...'} else {$_.data.Tags}}}, `
@{Name='Created'; Expression = {Get-Date $_.data.Created -Format 'yyyy-MM-dd'}}, `
@{Name='Expires'; Expression = {Get-Date $_.data.Expires -Format 'yyyy-MM-dd'}} | Format-Table | Write-Output

# Sorting arrow indicator
$arrow = if ($descending) {"▾"} else {if (-not $sortField) {""} else {"▴"}}

# Footer UI with paging and sorting controls
Write-Host -f Yellow ("-" * 130)
Write-Host -f Cyan ("📑 Page $($page + 1)/$([math]::Ceiling($total / $pagesize))".PadRight(16)) -n
Write-Host -f Yellow "| ⏮️[F]irst [P]revious [N]ext [L]ast⏭️ |" -n
Write-Host -f Green " Sort by: 📜[T]itle 🆔[U]ser 🔗[W]eb URL 🏷 Ta[G]s" -n
Write-Host -f Yellow "| " -n
Write-Host -f Green "$arrow $sortField".PadRight(10) -n
Write-Host -f Yellow " | " -n
Write-Host -f Cyan "↩️[ESC] " -n
if ($validurls -and -not $script:standarduser) {Write-Host -f Green "`n`n[X]port valid URLs " -n}
if (-not $validurls -and -not $script:standarduser) {Write-Host -f Green "`n`n[X]port current search results " -n}

# User input for navigation and sorting
$key = [Console]::ReadKey($true)

switch ($key.Key) {'F' {$page = 0}
'Home' {$page = 0}
'N' {if (($start + $pagesize) -lt $total) {$page++}}
'PageDown' {if (($start + $pagesize) -lt $total) {$page++}}
'DownArrow' {if (($start + $pagesize) -lt $total) {$page++}}
'RightArrow' {if (($start + $pagesize) -lt $total) {$page++}}
'Enter' {if (($start + $pagesize) -lt $total) {$page++}}
'P' {if ($page -gt 0) {$page--}}
'PageUp' {if ($page -gt 0) {$page--}}
'UpArrow' {if ($page -gt 0) {$page--}}
'LeftArrow' {if ($page -gt 0) {$page--}}
'Backspace' {if ($page -gt 0) {$page--}}
'L' {$page = [int][math]::Floor(($total - 1) / $pagesize)}
'End' {$page = [int][math]::Floor(($total - 1) / $pagesize)}
'T' {if ($sortField -eq "Title") {$descending = -not $descending} else {$sortField = "Title"; $descending = $false}
$page = 0}
'U' {if ($sortField -eq "Username") {$descending = -not $descending} else {$sortField = "Username"; $descending = $false}
$page = 0}
'W' {if ($sortField -eq "URL") {$descending = -not $descending} else {$sortField = "URL"; $descending = $false}
$page = 0}
'G' {if ($sortField -eq "Tags") {$descending = -not $descending} else {$sortField = "Tags"; $descending = $false}
$page = 0}
'Q' {nowarning; nomessage; rendermenu; return}
'Escape' {nowarning; nomessage; rendermenu; return}
'X' {if (-not $script:standarduser) {if ($validurls) {$outpath = Join-Path $script:databasedir 'validurls.txt'; $entries.data.URL | Sort-Object -Unique | Out-File $outpath -Encoding UTF8 -Force; Write-Host -f cyan "`n`nExported " -n; Write-Host -f white "$($entries.Count)" -n; Write-Host -f cyan " valid URLs to: " -n; Write-Host -f white "$outpath"; launchvalidator; rendermenu; return}
elseif (-not $validurls) {$outpath = Join-Path $script:databasedir 'searchresults.csv'; @($entries.data) | Select-Object Title, Username, URL, Tags, Created, Expires | ConvertTo-Csv -NoTypeInformation | Out-File $outpath -Encoding UTF8 -Force; Write-Host -f white "Exported $($entries.Count) entries to: $outpath"; Write-Host -f cyan "`n↩️[RETURN] " -n; Read-Host; rendermenu; return}}}
default {}}}}

function launchvalidator {# Launch the validator in a separate window.
$validator = Join-Path $script:basemodulepath "ValidateURLs.ps1"; $file = Join-Path $script:databasedir "validurls.txt"
Write-Host -f cyan "Do you want to launch " -n; Write-Host -f white "ValidateURLs.ps1" -n; Write-Host -f cyan " in a separate window, to test that each of the URLs listed in " -n; Write-Host -f white "validurls.txt" -n; Write-Host -f cyan " are still active? (Y/N) " -n; $proceed = Read-Host
if ($proceed -match "^[Yy]") {if (-not (Test-Path $validator)) {$script:warning = "ValidateURLs.ps1 not found at the expected path:`n$script:basemodulepath"; nomessage; return}
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $validator $file -safe `"$script:useragent`"" -WindowStyle Normal; $script:message = "ValidateURLs.ps1 is running in a separate window. Remember to check on it's progress."; nowarning}
else {$script:warning = "Aborted external URL validation script."; nomessage; return}
return}


#---------------------------------------------MANAGEMENT MENU: PASSWORD VAULT----------------------

function validatedatabase {# Validate a database and correct IV collisions.
Write-Host -f cyan "`n`n📄 Provide name of PWDB file to validate: " -n; $file = Read-Host
if ([string]::IsNullOrWhiteSpace($file)) {$script:warning = "Aborted."; nomessage; return}
if (-not [IO.Path]::HasExtension($file)) {$file += ".pwdb"}
if (-not [IO.Path]::IsPathRooted($file)) {$file = Join-Path $script:databasedir $file}
elseif (-not (Test-Path $file)) {$script:warning = "File not found: $file"; nomessage; return}

$script:database = $file; Write-Host -f cyan "`n🔑 Provide KEY file required to open the PWDB: " -n; $keypath = Read-Host
if ([string]::IsNullOrWhiteSpace($keypath)) {$script:warning = "Aborted."; nomessage; return}
if (-not [IO.Path]::HasExtension($keypath)) {$keypath += ".key"}
if (-not [IO.Path]::IsPathRooted($keypath)) {$keypath = Join-Path $script:keydir $keypath}
if (-not (Test-Path $keypath)) {$script:warning = "Key file not found: $keypath"; nomessage; return}

try {decryptkey $keypath
if (-not $script:key) {$script:warning = "Key decryption failed."; nomessage; return}

$script:keyfile = $keypath; $script:jsondatabase = $null; $script:jsondatabase = @(); loadjson
if ($script:jsondatabase -and -not ($script:jsondatabase -is [System.Collections.IEnumerable])) {$script:jsondatabase = @($script:jsondatabase)}
if (-not $script:jsondatabase) {$script:warning = "Decryption produced no data."; nomessage; return}
elseif (-not ($script:jsondatabase -is [System.Collections.IEnumerable])) {$script:warning = "Decrypted data is not an array."; nomessage; return}

""; $badEntries = @(); $i = 0; $script:warning = $null
foreach ($entry in $script:jsondatabase) {$i++; $missingFields = @()
foreach ($field in 'Title','Password','URL') {if (-not ($entry.data.PSObject.Properties.Name -contains $field)) {$missingFields += $field}}
if ($missingFields.Count -gt 0) {$badEntries += [PSCustomObject]@{Index = $i; Content = $entry; Reason  = "Missing required field(s): $($missingFields -join ', ')"}
continue}
if (-not (verifyentryhmac $entry)) {$badEntries += [PSCustomObject]@{Index = $i; Content = $entry; Reason  = "Failed HMAC validation."}}}

if ($badEntries.Count -gt 0) {Write-Host -f red "`nSome entries are malformed or failed HMAC verification:`n"; $badEntries | Format-Table -AutoSize; Write-Host -f yellow "`n↩️ Return " -n; Read-Host; return}

# 🧪 Detect and resolve IV collisions (same IV in multiple entries)
$ivSeen = @{}; $collisions = 0; $skipping = 0
for ($i = 0; $i -lt $script:jsondatabase.Count; $i++) {$entry = $script:jsondatabase[$i]
try {if ([string]::IsNullOrWhiteSpace($entry.data.Password)) {Write-Host -f darkyellow "⚠️ Entry $i`: Empty password — skipping."; $skipping ++; continue}
$cipherBytes = [Convert]::FromBase64String($entry.data.Password)
if ($cipherBytes.Length -lt 16) {Write-Host -f darkyellow "⚠️ Entry $i`: Cipher too short — skipping."; continue}
$iv = [BitConverter]::ToString($cipherBytes[0..15]) -replace '-', ''}
catch {Write-Host -f red "⚠️ Entry $i`: Invalid base64 — skipping."; continue}
if ($ivSeen.ContainsKey($iv)) {foreach ($ix in @($i, $ivSeen[$iv])) {$e = $script:jsondatabase[$ix]; $plain = decryptentry $e
if ($plain) {$data = [PSCustomObject]@{Title = $plain.Title
Username = $plain.Username
Password = if ([string]::IsNullOrWhiteSpace($e.data.Password)) {$plain.Password} else {encryptpassword $plain.Password $script:key}
URL = $plain.URL
Tags = $plain.Tags
Notes = $plain.Notes
Created = $plain.Created
Expires = $plain.Expires}
$script:jsondatabase[$ix] = [PSCustomObject]@{Data = $data; HMAC = createperentryhmac $data $script:key}}}
$collisions++}
else {$ivSeen[$iv] = $i}}}
catch {$script:warning = "❌ Verification failed:`n$($_.Exception.Message)"; nomessage; return}

if ($collisions -gt 0 -or $skipping -gt 0) {Write-Host -f cyan "`n Press [ENTER] to return, once you have read all messages. " -n; read-host}
if ($collisions -gt 0) {savetodisk; $script:warning = "⚠️  Detected and re-encrypted $collisions IV collision(s) with no data changes."; nomessages; return}
else {$script:message = "✅ All entries are valid and IVs are unique.️"; nowarning}; return}

function importcsv ($csvpath) {# Import a CSV file into the database.

# Decrypt the key first.
$script:key = $null; decryptkey $script:keyfile
if (-not $script:key) {$script:warning = "Key decryption failed. Aborting import."; nomessage; return}

# Ensure the database is initialized. This is needed for new, empty databases.
if (-not ($script:jsondatabase -is [System.Collections.IList])) {$script:jsondatabase = @($script:jsondatabase)}

# Import CSV file.
$imported = Import-Csv $csvpath; $requiredFields = @('Title', 'Username', 'Password', 'URL'); $optionalFields = @('Tags','Notes','Created','Expires')

Write-Host -f yellow "`nAre the passwords being imported currently stored in plaintext format? (Y/N) " -n; $aretheyplain = Read-Host
if ($aretheyplain -match "[Nn]") {Write-Host -f yellow "Are the passwords for the entries that are being imported already encrypted with the currently loaded key? (Y/N) " -n; $alreadyencrypted = Read-Host
if ($alreadyencrypted -match "[Nn]") {Write-Host -f red "Imported passwords must either be plaintext or encrypted with the same key already loaded into memory." -n; Read-Host; $script:warning = "Aborted due to password incompatability."; nomessage; return}}

# Set expiry expectations.
Write-Host -f yellow "`n⏳ How many days before these entries should expire? (Default = 365): " -n; $expireInput = Read-Host; $expireDays = 365
if (-not [string]::IsNullOrWhiteSpace($expireInput)) {if ($expireInput -as [int]) {$expireDays = [int]$expireInput
if ($expireDays -gt 365) {$expireDays = 365}
elseif ($expireDays -lt -365) {$expireDays = -365}}
else {Write-Host -f Red "`n⚠️  Invalid input. Using default value: 365 days."}}
$expires = (Get-Date).AddDays($expireDays).ToString("yyyy-MM-dd")

# Detect extra fields not accounted for already.
$csvFields = $imported[0].PSObject.Properties.Name; $csvFields = $imported[0].PSObject.Properties.Name; $extraFields = $csvFields | Where-Object {($requiredFields -notcontains $_) -and ($optionalFields -notcontains $_)}; $fieldAppendNotes = @{}; $fieldTagMode = @{}
if ($extraFields.Count -gt 0) {foreach ($field in $extraFields) {Write-Host -f Green "`nExtra field detected: " -n; Write-Host -f White "$field"
Write-Host -f Yellow "Append '$field' to Notes? (Y/N) " -n; $appendNoteAns = Read-Host; $fieldAppendNotes[$field] = ($appendNoteAns.ToUpper() -eq 'Y')

Write-Host -f Cyan "Add '$field' as a tag? (Y/N) " -n; $addTagAns = Read-Host; if ($addTagAns.ToUpper() -eq 'Y') {Write-Host -f Cyan "Add tag to all or only populated entries? ([A]ll/[P]opulated) " -n; $mode = Read-Host; if ($mode -and ($mode.ToLower() -in @('a','p'))) {$fieldTagMode[$field] = $mode.ToLower()}
else {Write-Host -f Red "Invalid option. Skipping tag for '$field'."; $fieldTagMode[$field] = 'none'}}}}

$tagAddCounts = @{}
foreach ($field in $extraFields) {$tagAddCounts[$field] = 0}
$added = 0; $skipped = 0; $overwritten = 0; $duplicates = 0
if (-not ($script:jsondatabase -is [System.Collections.IList])) {$script:jsondatabase = @()}
foreach ($entry in $imported) {$title = $null; $username = $null; $plainpassword = $null; $url = $null; $notes = $null; $tags = $null
if (-not $entry.PSObject.Properties.Name -contains 'Title') {$entry | Add-Member -MemberType NoteProperty -Name Title -Value ""}
if (-not $entry.PSObject.Properties.Name -contains 'Username') {Write-Host -f Red "Skipping entry: Missing Username"; $skipped++; continue}
if (-not $entry.PSObject.Properties.Name -contains 'Password') {$entry | Add-Member -MemberType NoteProperty -Name Password -Value ""}
if (-not $entry.PSObject.Properties.Name -contains 'URL') {Write-Host -f Red "Skipping entry: Missing URL"; $skipped++; continue}
if (-not $entry.PSObject.Properties.Name -contains 'Notes') {$entry | Add-Member -MemberType NoteProperty -Name Notes -Value ""}
if (-not $entry.PSObject.Properties.Name -contains 'Tags') {$entry | Add-Member -MemberType NoteProperty -Name Tags -Value ""}

$title = if ($entry.Title -is [string] -and $entry.Title.Trim()) {$entry.Title.Trim()} else {""}
$username = if ($entry.Username -is [string] -and $entry.Username.Trim()) {$entry.Username.Trim()} else {""}
$plainpassword = $entry.Password
$url = if ($entry.URL -is [string] -and $entry.URL.Trim()) {$entry.URL.Trim()} else {""}
$notes = if ($entry.Notes) {$entry.Notes.Trim()} else {""}
$tags = if ($entry.Tags) {$entry.Tags.Trim()} else {""}

# Validate non-empty Username and URL.
if ([string]::IsNullOrWhiteSpace($username)) {Write-Host -f Cyan "`nUsername is empty for an entry (Title: '$title', URL: '$url'). Enter a Username or press Enter to skip: " -n; $username = Read-Host
if ([string]::IsNullOrWhiteSpace($username)) {Write-Host -f Yellow "Skipping entry due to empty Username."; $skipped++; continue}}

if ([string]::IsNullOrWhiteSpace($url)) {Write-Host -f Cyan "`nURL is empty for an entry (Title: '$title', Username: '$username'). Enter a URL or press Enter to skip: " -n; $url = Read-Host
if ([string]::IsNullOrWhiteSpace($url)) {Write-Host -f Yellow "Skipping entry due to empty URL."; $skipped++; continue}}

# Auto-fill Title from domain if empty.
if ([string]::IsNullOrWhiteSpace($title)) {$domain = if ($url -match '(?i)^(https?:\/\/)?(www\.)?(([a-z\d-]+\.)*[a-z\d-]+\.[a-z]{2,10})(\W|$)') {$matches[3].ToLower()} else {""}
if ([string]::IsNullOrWhiteSpace($domain)) {Write-Host -f Cyan "`nTitle is missing and could not auto-extract from URL: $url. Please enter a Title or press Enter to skip: " -n; $title = Read-Host
if ([string]::IsNullOrWhiteSpace($title)) {Write-Host -f Yellow "Skipping entry due to missing Title."; $skipped++; continue}}
else {$title = $domain; Write-Host -f Yellow "Title auto-set to domain: $title"}}

# Append extra fields to Notes if requested.
foreach ($field in $extraFields) {if ($entry.PSObject.Properties.Name -contains $field) {$val = $entry.$field
if (-not [string]::IsNullOrWhiteSpace($val) -and $fieldAppendNotes[$field]) {$notes += "`n$field`: $val"}}}

# Add tags for extra fields.
foreach ($field in $extraFields) {if ($fieldTagMode[$field] -ne 'none' -and $entry.PSObject.Properties.Name -contains $field) {$val = $entry.$field; $shouldAdd = $false
switch ($fieldTagMode[$field]) {'a' {$shouldAdd = $true}
'p' {$shouldAdd = -not [string]::IsNullOrWhiteSpace($val)}}
if ($shouldAdd) {$existingTags = $tags -split ',\s*' | Where-Object {$_ -ne ''}
if (-not ($existingTags -contains $field)) {$tags = if ([string]::IsNullOrWhiteSpace($tags)) {$field} else {"$tags,$field"}
$tagAddCounts[$field]++}}}}

# Check duplicates by Username and URL.
$matches = $script:jsondatabase | Where-Object {$_.Data.Username -eq $username -and $_.Data.URL -eq $url}

if ($matches.Count -gt 0) {$validMatches = $matches | Where-Object {verifyentryhmac $_}
$invalidMatches = $matches | Where-Object {-not (verifyentryhmac $_)}

if ($validMatches.Count -eq 0) {Write-Host -f Red "❌ All duplicate entries for 🆔 '$username' at 🔗 '$url' failed HMAC validation. Possible tampering suspected. Skipping duplicate handling."; continue}

# Proceed with first valid duplicate for the prompt
$match = $validMatches[0]; $duplicates++
Write-Host -f Yellow "`nDuplicate detected for 🆔 '$username' at 🔗 '$url'"
Write-Host -f Cyan "📜 Title: $($match.Data.Title) => $title"
Write-Host -f Cyan "🏷️  Tags: $($match.Data.Tags) => $tags"
Write-Host -f Cyan "📝 Notes: $($match.Data.Notes) => $notes"
Write-Host -f White "`nOptions: (S)kip / (O)verwrite / (K)eep both [default: Keep]: " -n; $choice = Read-Host
switch ($choice.ToUpper()) {"O" {$script:jsondatabase = $script:jsondatabase | Where-Object {$_ -ne $match}; Write-Host -f Red "`nOverwritten."; $overwritten++}
"S" {Write-Host -f Red "`nSkipping entry."; $skipped++; continue}
"K" {Write-Host -f Green "`nKeeping both."}
default {Write-Host -f Green "`nKeeping both."}}}

# Encrypt password using encryptpassword function; allow empty password.
if ($alreadyencrypted -match "[Yy]") {$encryptedPassword = $plainpassword}
else {if ([string]::IsNullOrWhiteSpace($plainpassword)) {Write-Host -f Yellow "`nEntry for 🆔 '$username' at 🔗 '$url' has no password. Adding with 🚫 empty password."; $encryptedPassword = ""}
else {try {$encryptedPassword = encryptpassword $plainpassword}
catch {Write-Host -f Red "❌ Failed to encrypt password for 🆔 '$username' at 🔗 '$url'. Skipping this entry."; continue}}}

# Create new entry and add to in-memory database and then save to disk.
$data = [PSCustomObject]@{Title = $title
Username = $username
Password = $encryptedPassword
URL = $url
Tags = $tags
Notes = $notes
Created = (Get-Date).ToString("yyyy-MM-dd")
Expires = $expires}
$hmac = createperentryhmac $data $script:key
$newEntry = [PSCustomObject]@{Data = $data; HMAC = $hmac}

$script:jsondatabase += $newEntry; $added++}
savetodisk

# Summarize output.
Write-Host -f Green "`n✅ Import complete.`n"
Write-Host -f Yellow "New entries added:" -n; Write-Host -f White " $added"
Write-Host -f Gray "Duplicates skipped:" -n; Write-Host -f White " $skipped"
Write-Host -f Red "Overwritten entries:" -n; Write-Host -f White " $overwritten"
Write-Host -f Yellow "Total duplicates:" -n; Write-Host -f White " $duplicates"
$tagsAdded = ($tagAddCounts.GetEnumerator() | Where-Object {$_.Value -gt 0})
if ($tagsAdded.Count -gt 0) {Write-Host -f Yellow "Tag types added:" -n; Write-Host -f White " $($tagsAdded.Count)"
Write-Host -f Yellow "Tags added:" -n; Write-Host -f White " $($tagsAdded.Name -join ', ')"}

# Offer secure delete of CSV file after import.
Write-Host -f red "`n⚠️  Do you want to securely erase the imported CSV file from disk? (Y/N) " -n; $wipecsv = Read-Host
if ($wipecsv -match '^[Yy]') {try {$passes = Get-Random -Minimum 3 -Maximum 50; $length = (Get-Item $csvpath).Length
for ($i = 0; $i -lt $passes; $i++) {$junk = New-Object byte[] $length; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($junk); [System.IO.File]::WriteAllBytes($csvpath, $junk)}
Remove-Item $csvpath -Force
Write-Host -f white "`n🧨 CSV file wiped and deleted in $passes passes."}
catch {Write-Host -f Red "❌ Failed to securely wipe CSV file: $_"}}

Write-Host -f Cyan "`n↩️Return" -n; Read-Host}

function export ($path, $fields) {# Export current in-memory database content to CSV
if (-not $script:jsondatabase) {$script:warning = "No database content is currently loaded."; nomessage; return}

$validfields = 'Title','Username','Password','URL','Tags','Notes','Created','Expires'
$fieldList = $fields -split ',' | ForEach-Object {$_.Trim()}
$invalidfields = $fieldList | Where-Object {$_ -notin $validfields}
if ($invalidfields) {$script:warning = "Invalid field(s): $($invalidfields -join ', ')"; $script:message = "Allowed fields: $($validfields -join ', ')"; return}

# $script:jsondatabase is assumed to be an array of objects (already parsed JSON)
$script:warning = $null; $filtered = @()
foreach ($record in $script:jsondatabase) {if (-not (verifyentryhmac $record)) {$script:warning += "Entry $($record.data.Title) has an invalid HMAC and will be ignored. "; nomessage; continue}

$entry = $record.data; $obj = [ordered]@{}; foreach ($field in $fieldList) {$value = $entry.$field
switch -Regex ($field) {'^Title$' {$obj['Title'] = $value; continue}
'^Username$' {$obj['Username'] = $value; continue}
'^Password$' {$obj['Password (AES-256-CBC)'] = $value; continue}
'^URL$' {$obj['URL'] = $value; continue}
'^Tags$' {$obj['Tags'] = $value; continue}
'^Notes$' {$obj['Notes'] = $value; continue}
'^Created$' {$obj['Created'] = $value; continue}
'^Expires$' {$obj['Expires'] = $value; continue}
default {$obj[$field] = $value}}}
$filtered += [pscustomobject]$obj}

if (-not $filtered -or $filtered.Count -eq 0) {$script:warning += "No valid entries found in the in-memory database."; nomessage; return}
$filtered | Export-Csv -Path $path -NoTypeInformation -Force

if ($path -match '(?i)((\\[^\\]+){2}\\\w+\.csv)') {$shortname = $matches[1]} else {$shortname = $path}
$script:message = "Exported JSON database to: $shortname"; nowarning; return}

function fulldbexport {# Export the current database with all passwords in plaintext.

if (masterlockout) {return}
else {Write-Host -f green  "`n`n`t 👑 Master Password " -n; $master = Read-Host -AsSecureString
if (-not (verifymasterpassword $master)) {$script:failedmaster ++; $script:warning = "Wrong master password. $([math]::Max(0,4 - $script:failedmaster)) attempts remain before lockout."; nomessage; return}}

# Verify the database password.
resetmasterfailures; $script:key = $null; decryptkey $script:keyfile
if (-not $script:key) {$script:warning += "Wrong database password. Aborting export."; nomessage; return}

# Decrypt the full database contents.
$databasename = [System.IO.Path]::GetFileNameWithoutExtension($script:database)
$fullexport = Join-Path $script:privilegedir "fullexport_$databasename.csv"
$decrypted = @()

$exporterrors = 0; ""
foreach ($entry in $script:jsondatabase) {$pwd = "[NO PASSWORD SET]"
if ($entry.data.Password -and $entry.data.Password -ne "") {try {$pwd = decryptpassword $entry.data.Password
if ($null -eq $pwd) {$pwd = "[DECRYPTION FAILED]"; Write-Host "'$($entry.data.Title)' decrypted to null."
$exporterrors++}
elseif ($pwd -eq "") {$pwd = "[EMPTY PASSWORD]"}}
catch {$pwd = "[DECRYPTION FAILED]"; Write-Host "'$($entry.data.Title)' failed to decrypt password: $_"; $exporterrors++}}

$decrypted += [pscustomobject]@{
Title = $entry.data.Title
Username = $entry.data.Username
Password = $pwd
URL = $entry.data.URL
Tags = $entry.data.Tags -join ', '
Notes = $entry.data.Notes
Created = $entry.data.Created
Expires = $entry.data.Expires}}

if ($exporterrors -gt 0) {Write-Host -f yellow "`n⚠️  $exporterrors password(s) failed to decrypt. Press [ENTER] to continue." -n; Read-Host}

# Export to CSV.
$decrypted | Sort-Object Title | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $fullexport
$script:message = "$databasename exported to fullexport_$databasename.csv"; nowarning; return}

function saveandsort {# Sort the database by tag, then by title.
$script:jsondatabase = $script:jsondatabase | Sort-Object {($_.data.Tags -join ' ').ToLower()}, {$_.data.Title.ToLower()}; savetodisk}


#---------------------------------------------MANAGEMENT MENU--------------------------------------

function newkey ($basename) {# basename with no extension, e.g. "MyDB"
$keyfile = Join-Path $script:keydir "$basename.key"; $pwdbfile = Join-Path $script:databasedir "$basename.pwdb"; $script:registryfile = Join-Path $script:privilegedir "$basename.db"

if ((Test-Path $keyfile -ea SilentlyContinue) -or (Test-Path $pwdbfile -ea SilentlyContinue) -or (Test-Path $script:registryfile -ea SilentlyContinue)) {$script:warning = "One or more the target files already exists. Choose a different base name."; nomessage; return}

# Prompt for DB password
Write-Host -f green "🔐 Enter a password to protect this new database: " -n; $securePass = Read-Host -AsSecureString
$plainPass = [System.Net.NetworkCredential]::new("", $securePass).Password

if ($plainPass -notmatch '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$') {$script:warning = "❌ Password must be at least 8 characters and include upper, lower, digit, and symbol."; nomessage; return}

# Generate AES key and write encrypted keyfile
$aesKey = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($aesKey); $marker = [System.Text.Encoding]::UTF8.GetBytes("SCHV"); $keyWithMarker = $marker + $aesKey; $salt = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt); $protectKey = derivekeyfrompassword $plainPass $salt; $encryptedKey = protectbytesaeshmac $keyWithMarker $protectKey; $output = $salt + $encryptedKey; [IO.File]::WriteAllBytes($keyfile, $output)

# Set session variables
$script:keyfile = $keyfile; $script:keyexists = $true; $script:key = $aesKey; $script:disablelogging = $false

# Create empty pwdb file encrypted with the key
$script:jsondatabase = @(); $json = "[]"; $jsonBytes = [Text.Encoding]::UTF8.GetBytes($json); $encryptedDb = protectbytesaeshmac $jsonBytes $script:key; [IO.File]::WriteAllBytes($pwdbfile, $encryptedDb); $script:database = $pwdbfile

# Create default admin user in user registry encrypted with same AES key
$script:users = @(); $expiry = (Get-Date).AddDays(30); $salt = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt); $derived = derivekeyfrompassword 'admin' $salt; $sha256 = [Security.Cryptography.SHA256]::Create(); $hash = $sha256.ComputeHash($derived); $sha256.Dispose(); $encoded = [Convert]::ToBase64String($salt + $hash); 
$data = [PSCustomObject]@{Username = 'admin'
Password = $encoded
Role     = 'privileged'
Created  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
Expires  = $expiry.ToUniversalTime().ToString("yyyy-MM-dd")
Active   = $true}
$hmac = createperentryhmac $data $script:key
$entry = [PSCustomObject]@{data = $data; hmac = $hmac}
$script:users += $entry

saveregistry; $script:message = "✅ The new database environment has been created: a keyfile, database, and user registry with the default admin user."; nowarning}

function modifyconfiguration {# Modify the PSD1 configuration.
# Load current settings
$manifest = Import-PowerShellDataFile -Path $configpath
$config = $manifest.PrivateData

# Define editable keys with constraints
$editable = @{defaultkey = @{desc='Key filename'; validate={param($v) $v -match '\S'}}
defaultdatabase = @{desc='Database filename'; validate={param($v) $v -match '\S'}}
keydir = @{desc='Key directory path'; validate={param($v) $v -match '\S'}}
databasedir = @{desc='Database directory path'; validate={param($v) $v -match '\S'}}
timeoutseconds = @{desc='Timeout (max 5940 seconds)'; validate={param($v) try {($v -as [int]) -in 1..5940} catch {$false}}}
timetobootlimit = @{desc='Boot time limit (max 120 minutes)'; validate={param($v) try {($v -as [int]) -in 1..120} catch {$false}}}
delayseconds = @{desc='Clipboard delay (in seconds)'; validate={param($v) try {[int]$v -ge 0} catch {$false}}}
expirywarning = @{desc='Password expiry (1–365 days)'; validate={param($v) try {($v -as [int]) -in 1..365} catch {$false}}}
logretention = @{desc='Log retention (min 30 days)'; validate={param($v) try {[int]$v -ge 30} catch {$false}}}
dictionaryfile = @{desc='Dictionary filename'; validate={param($v) $v -match '\S'}}
backupfrequency = @{desc='Backup frequency (in days)'; validate={param($v) try {[int]$v -ge 1} catch {$false}}}
archiveslimit = @{desc='Archives limit (files to retain)'; validate={param($v) try {[int]$v -ge 1} catch {$false}}}
useragent = @{desc='User-Agent'; validate={param($v) $v -match '\S'}}}

Write-Host -f yellow "`n`nCurrent Configuration:`n"; $i = 0
Write-Host -f cyan "There are currently $($editable.count) configurable items in v$script:version.`n"
foreach ($key in $editable.Keys) {$current = $config[$key]; $i++
Write-Host -f white "$i. $($editable[$key].desc) [$key = '$current']: " -n; $input = Read-Host
if ($input -ne '') {if (-not (& $editable[$key].validate $input)) {Write-Host -f red "Invalid value for $key. Keeping existing value."}
else {$config[$key] = "$input"; Write-Host -f green "$key updated to '$input'"}}}

# Rebuild psd1 content
# Save new file with predictable key order
$lines = @(); $lines += "# Core module details`n@{"

# Desired order for top-level keys
$topKeys = 'RootModule','ModuleVersion','GUID','Author','CompanyName','Copyright','Description'
foreach ($k in $topKeys) {if ($manifest.ContainsKey($k)) {$v = $manifest[$k]
if ($v -is [string]) {$lines += "$k = '$v'"}
elseif ($v -is [array]) {$lines += "$k = @('" + ($v -join "', '") + "')"}
else {$lines += "$k = $v"}}}

# Handle all remaining non-PrivateData keys not in topKeys
foreach ($k in $manifest.Keys | Where-Object {$_ -notin $topKeys -and $_ -ne 'PrivateData'}) {$v = $manifest[$k]
if ($v -is [string]) {$lines += "$k = '$v'"}
elseif ($v -is [array]) {$lines += "$k = @('" + ($v -join "', '") + "')"}
else {$lines += "$k = $v"}}

# Append PrivateData block
$lines += "`n# Configuration data"; $lines += "PrivateData = @{"
foreach ($sk in $config.Keys) {$sv = $config[$sk]; $lines += "$sk = '$sv'"}
$lines += "}}"

# Save new file
Set-Content -Path $configpath -Value $lines -Encoding UTF8; Write-Host -f green "`nConfiguration updated successfully."; initialize; return}

#---------------------------------------------MANAGEMENT MENU: MASTER PASSWORD---------------------

function rewrapdbkey {# Re-encrypt the current DB key under a new child key.
if (-not $script:database -or -not (Test-Path $script:database)) {$script:warning = "No database is currently loaded."; nomessage; return}
if (-not $script:key -or $script:key.Length -ne 32) {$script:warning = "Active key not found or invalid. Cannot rewrap."; nomessage; return}

# Derive existing base name.
$basename = [System.IO.Path]::GetFileNameWithoutExtension($script:database)

# Ask user for new key name.
Write-Host -f yellow "`n`nEnter a name for the new .key file: " -n; $newname = Read-Host
if (-not $newname -or $newname.Length -lt 3) {$script:warning = "Invalid key name."; nomessage; return}
if ($newname -notmatch '\.key$') {$newname += ".key"}

$newkeyfile = Join-Path $script:keydir $newname
if (Test-Path $newkeyfile) {$script:warning = "That key file already exists."; nomessage; return}

# Prompt for the new key password.
neuralizer; Write-Host -f yellow "🔐 Enter a new password for the key: " -n; $securePass = Read-Host -AsSecureString; $pwd = [System.Net.NetworkCredential]::new("", $securePass).Password

# Check the password against minimum password requirements.
if ($pwd -notmatch '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$') {$script:warning = "❌ The password must be at least 8 characters long and include upper-case and lower-case letters, digits and symbols."; nomessage; return}

# Verify the password.
Write-Host -f yellow "🔐 Confirm the password.: " -n; $securePass2 = Read-Host -AsSecureString
if (-not (comparesecurestring $securePass $securePass2)) {$script:warning += "Passwords do not match. "; nomessage; return}

# Generate new salt + derive key
$salt = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt); $derived = derivekeyfrompassword $pwd $salt

# Prepend magic marker and encrypt existing database key.
$marker = [System.Text.Encoding]::UTF8.GetBytes("SCHV"); $full = $marker + $script:key; $wrapped = protectbytesaeshmac $full $derived; [IO.File]::WriteAllBytes($newkeyfile, $salt + $wrapped)

# Ask if user wants to securely erase the old key file.
Write-Host -f red "`n⚠️  Securely wipe the original key file from disk? (Y/N): " -n; $wipeKey = Read-Host
if ($wipeKey -match '^[Yy]') {try {$passes = Get-Random -Minimum 3 -Maximum 50; $length = (Get-Item $script:keyfile).Length
for ($i = 0; $i -lt $passes; $i++) {$junk = New-Object byte[] $length; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($junk); [System.IO.File]::WriteAllBytes($script:keyfile, $junk)}
Remove-Item $script:keyfile -Force; $script:message = "🧨 The original key was securely wiped in $passes passes. "; nowarning}
catch {Write-Host -f red "❌ Failed to securely wipe original key file: $_"}}

# Determine DB and key file that matches the *original* key's base name.
$oldKeyName = [System.IO.Path]::GetFileNameWithoutExtension($script:keyfile)
$newKeyName = [System.IO.Path]::GetFileNameWithoutExtension($newname)
$oldDbName = Join-Path $script:databasedir "$oldKeyName.pwdb"
$newDbPath = Join-Path $script:databasedir "$newKeyName.pwdb"
$oldRegistry = Join-Path $privilegedir "$oldKeyName.db"
$newRegistry = Join-Path $privilegedir "$newKeyName.db"
$oldMaster = Join-Path $privilegedir "$oldKeyName.dbkey"
$newMaster = Join-Path $privilegedir "$newKeyName.dbkey"

# Prompt to rename, even if file doesn't exist yet.
Write-Host -f yellow "`n🔄 Rename database from: " -n; Write-Host -f white "$(Split-Path $oldDbName -Leaf)" -n; Write-Host -f yellow " to: " -n; Write-Host -f white "$(Split-Path $newDbPath -Leaf)" -n; Write-Host -f yellow "? (Y/N): " -n; $renameDb = Read-Host

if ($renameDb -match '^[Yy]') {if (-not (Test-Path $oldDbName)) {Write-Host -f red "❌ Cannot rename — source file '$oldDbName' does not exist."}
else {try {Rename-Item -Path $oldDbName $newDbPath -Force; $script:database = $newDbPath; $script:message += "The database was renamed to match the key. "; nowarning}
catch {$script:warning += "❌ Failed to rename database: $_"; nomessage}}}

# Rename user registry.
try {Rename-Item -Path $oldRegistry -NewName $newRegistry -Force; $script:registryfile = $newRegistry; $script:message += "The user registry was renamed, as well."; nowarning}
catch {$script:warning += "❌ Failed to rename user registry: $_"; nomessage}

# Rename Master key, if it exists.
if (Test-Path $oldMaster -ea SilentlyContinue) {try {Rename-Item -Path $oldMaster -NewName $newMaster -Force; $script:message += "The Master key was renamed, as well."; nowarning}
catch {$script:warning += "❌ Failed to rename Master key: $_"; nomessage}}

if ($script:warning) {nomessage; return}

# Update script:keyfile.
$script:keyfile = $newkeyfile; $script:message += "🧬 Rewrap successful. This database is now using: $newname"; nowarning; return}

function wrapdbkeyformaster ([string]$KeyName = "paschwords") {# Wrap the database key inside the Master key.
$KeyName = [IO.Path]::GetFileNameWithoutExtension($KeyName); $kpath = Join-Path $script:keydir "$KeyName.key"; $pwrap = Join-Path $privilegedir "$KeyName.dbkey"

if (-not (Test-Path $kpath)) {$script:warning = "❌ Key file not found: $kpath"; nomessage; return}

# Load salt and encrypted key.
[byte[]]$raw = [IO.File]::ReadAllBytes($kpath); [byte[]]$salt = $raw[0..15]; [byte[]]$encKey = $raw[16..($raw.Length - 1)]

# Prompt for the database key password.
Write-Host -f green "`n`🔐 Enter the password for the database: " -n; $secure = Read-Host -AsSecureString; $plain = [System.Net.NetworkCredential]::new("", $secure).Password

# Decrypt original keyfile.
try {$wrapKey = derivekeyfrompassword $plain $salt; [byte[]]$fullKey = unprotectbytesaeshmac $encKey $wrapKey
if (-not $fullKey -or $fullKey.Length -lt 36) {$script:warning = "The key is too short or null."; nomessage; return}
if ([System.Text.Encoding]::UTF8.GetString($fullKey[0..3]) -ne "SCHV") {$script:warning = "Invalid marker in the decrypted keyfile."; nomessage; return}
$aesKey = $fullKey[4..35]}
catch {$script:warning = "❌ Failed to decrypt the key file: $_"; nomessage; return}

# Prompt for the master password and load the Master key.
if (masterlockout) {return}
else {Write-Host -f green "👑 Enter the master password " -n; $masterSecure = Read-Host -AsSecureString
if (-not (verifymasterpassword $masterSecure)) {$script:failedmaster++; $script:warning = "❌ Wrong master password. $([math]::Max(0, 4 - $script:failedmaster)) attempts remain before lockout."; nomessage; return}}

# Load the Master key.
resetmasterfailures; $script:rootkey = loadprivilegekey $masterSecure; $real = New-Object byte[] 32; [Array]::Copy($script:rootkey, $script:rootkey.Length - 32, $real, 0, 32); $script:rootkey = $real
if (-not $script:rootkey) {$script:warning = "❌ Failed to load the Master key."; nomessage; return}

# Wrap and write the new .dbkey.
try {$wrapped = protectbytesaeshmac $aesKey $script:rootkey; [IO.File]::WriteAllBytes($pwrap, $wrapped); $script:message = "✅ Wrapped key written to: $pwrap"; nowarning; return}
catch {$script:warning = "❌ Failed to write wrapped key: $_"; nomessage; return}}

function rotatemasterpassword {# Rewrap root.key with a new master password
if (masterlockout) {return}

Write-Host -f green "`n`n👑 Enter current master password " -n; $oldPwd = Read-Host -AsSecureString; $rootKey = loadprivilegekey $oldPwd
if (-not $rootKey) {$script:warning = "❌ Could not decrypt the current root key. Master password rotation aborted."; nomessage; return}

# Prompt for the new master password.
Write-Host -f green "👑 Enter new master password " -n; $newPwd = Read-Host -AsSecureString; $plainPwd = [System.Net.NetworkCredential]::new("", $newPwd).Password

# Check the password against minimum password requirements.
if ($plainPwd -notmatch '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{8,}$') {$script:warning = "❌ The password must be at least 8 characters long and include upper-case and lower-case letters, digits and symbols."; nomessage; return}

# Check for master password reuse.
if (comparesecurestring $oldPwd $newPwd) {$script:warning = "You cannot reuse the same password."; nomessage; return}

# Verify the password.
Write-Host -f green "👑 Confirm the new master password " -n; $newPwd2 = Read-Host -AsSecureString
if (-not (comparesecurestring $newPwd $newPwd2)) {$script:warning = "Passwords do not match."; nomessage; return}

$newWrapSalt = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($newWrapSalt); $newWrapKey = derivekeyfrompassword -Password $newPwd -Salt $newWrapSalt; $encRoot = protectbytesaeshmac $rootKey $newWrapKey; [System.IO.File]::WriteAllBytes($script:rootkeyFile, $newWrapSalt + $encRoot)

$script:message = "Master password rotated successfully."; nowarning; return}

function switchtomasterkey {# Elevate to master-level access to the current DB
if (-not $script:database) {$script:warning = "❌ No database is currently loaded."; nomessage; return $false}

Write-Host -f green "`n`n👑 Enter the master password " -n; $securePass = Read-Host -AsSecureString
$script:switchtomaster = $true; $script:rootkey = loadprivilegekey $securePass; $real = New-Object byte[] 32; [Array]::Copy($script:rootkey, $script:rootkey.Length - 32, $real, 0, 32); $script:rootkey = $real; $basename = [System.IO.Path]::GetFileNameWithoutExtension($script:database); $wrappedPath = Join-Path $privilegedir "$basename.dbkey"
if (-not (Test-Path $wrappedPath)) {$script:warning = "❌ No wrapped database key found for '$basename'. You may need to wrap the database key inside the Master key first."; nomessage; return $false}

try {$wrapped = [System.IO.File]::ReadAllBytes($wrappedPath); $unwrapped = unprotectbytesaeshmac $wrapped $script:rootkey

if (-not $unwrapped -or $unwrapped.Length -ne 32) {$script:failedmaster++; $script:warning = "❌ Wrong master password. $([math]::Max(0, 4 - $script:failedmaster)) attempts remain before lockout."; nomessage; return $false}

# Load the Master key.
resetmasterfailures; $script:key = $unwrapped; $script:switchtomaster = $false; loadjson; $script:message = "✅ Privilege elevated. 👑 Now using the unlocked Master key."; nowarning; return $true}

catch {$script:warning = "❌ Failed to unwrap the database key with the Master key: $_"; nomessage; return $false}}


#---------------------------------------------MANAGEMENT MENU: ARCHIVE-----------------------------

function backup {# Backup currently loaded key and database pair to the database directory.

$script:message = $null; $script:warning = $null; $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script:database); $timestamp = Get-Date -Format "MM-dd-yyyy @ HH_mm_ss"; $zipName = "$baseName ($timestamp).zip"; $zipPath = Join-Path $script:databasedir $zipName

try {$tempDir = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $tempDir | Out-Null
Copy-Item $script:database -Destination $tempDir; Copy-Item $script:keyfile -Destination $tempDir; Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath $zipPath -Force; Remove-Item $tempDir -Recurse -Force; $script:message = $script:message += "✅ Backup created: $zipName "; nowarning} catch {if ((Test-Path $script:database -ea SilentlyContinue) -and (Test-Path $script:keyfile -ea SilentlyContinue)) {$script:warning = "Backup failed: $_ "; nomessage; return} else {$script:warning = "Backup was not initiated. "; nomessage; return}}
return}

function backupprivilege {# Zip all contents of $privilegedir.
if (-not (Get-ChildItem -File $privilegedir -ea SilentlyContinue).count -gt 0) {return}
$timestamp = (Get-Date).ToString("MM-dd-yyyy @ HH_mm_ss"); $backupName = "privileges ($timestamp).zip"; $backupPath = Join-Path $privilegedir $backupName; $tempDir = Join-Path $privilegedir ".tempbackup"
if (Test-Path $tempDir) {Remove-Item -Recurse -Force -Path $tempDir -ea SilentlyContinue}
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Copy only direct contents, skip .zip and temp folder
Get-ChildItem -Path $privilegedir -File -ea SilentlyContinue | Where-Object {$_.Extension -ne '.zip'} | ForEach-Object {Copy-Item -Path $_.FullName -Destination (Join-Path $tempDir $_.Name) -Force}

Compress-Archive -Path "$tempDir\*" -DestinationPath $backupPath -Force; Remove-Item $tempDir -Recurse -Force

# Keep only 5 newest backups
$backups = Get-ChildItem -Path $privilegedir -Filter 'privileges (*.zip)' | Sort-Object LastWriteTime -Descending
if ($backups.Count -gt 5) {$backups | Select-Object -Skip $script:archiveslimit | Remove-Item -Force}
$script:message += "`n✅ Privilege backup created: $backupName`n`n(Privilege backups need to be restored manually.)"}

function scheduledbackup {# Run backup according to PSD1 settings.
if (-not (Get-ChildItem -File $databasedir -ea SilentlyContinue).count -gt 0 -and -not (Get-ChildItem -File $keydir -ea SilentlyContinue).count -gt 0) {return}
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($script:database)
$backups = Get-ChildItem -Path $script:databasedir -File "*.zip" -ea SilentlyContinue | Where-Object {$_.Name -like "$baseName*(*@*).zip"}
$needBackup = $true
$newest = $backups | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($newest) {$age = (Get-Date) - $newest.LastWriteTime
if ($age.TotalDays -lt $script:backupfrequency) {$needBackup = $false}}

if ($needBackup) {Write-Host -f darkgray "💾 Creating new backup..."; backup; backupprivilege}
else {$script:message = $script:message + "🕒 No scheduled backup is currently required."; nowarning; return}

# Enforce archive limit
$backups = Get-ChildItem -Path $script:databasedir -File "$baseName*(*.zip)" -ea SilentlyContinue

$sortedBackups = $backups | Sort-Object LastWriteTime -Descending
if ($sortedBackups.Count -gt $script:archiveslimit) {$toDelete = $sortedBackups | Select-Object -Skip $script:archiveslimit
foreach ($file in $toDelete) {try {Remove-Item -LiteralPath $file.FullName -Force -ea Stop; $script:message = $script:message + "`n🗑️ Deleted old backup: $($file.Name)"; nowarning}
catch {$script:warning = "⚠️ Failed to delete: $($file.FullName) - $_"}}}; nomessage; return}

function restore {# Restore a backup.
$script:message = $null; $script:warning = $null
$pattern = '^[A-Za-z0-9_]+ \(\d{2}-\d{2}-\d{4} @ \d{2}_\d{2}_\d{2}\)\.zip$'; 

$backups = Get-ChildItem -Path $script:databasedir -Filter '*.zip' | Where-Object {$_.Name -match $pattern} | Sort-Object Name
if (-not $backups) {$script:warning = "No backup files found in: $script:databasedir"; nomessage; return}
Write-Host -f yellow "`nAvailable backups:`n"
for ($i = 0; $i -lt $backups.Count; $i++) {Write-Host -f cyan ("{0}. " -f ($i + 1)) -n; Write-Host -f white $backups[$i].Name}
Write-Host -f yellow "`nSelect a backup to restore (1-$($backups.Count)) " -n; $selection = Read-Host
if (-not [int]::TryParse($selection, [ref]$null) -or $selection -lt 1 -or $selection -gt $backups.Count) {$script:warning = "Invalid selection. Restore aborted."; nomessage; return}

$chosenFile = $backups[$selection - 1].FullName; $tempDir = Join-Path $env:TEMP ([Guid]::NewGuid().ToString())
try {New-Item -ItemType Directory -Path $tempDir | Out-Null; Expand-Archive -Path $chosenFile -DestinationPath $tempDir -Force; $dbFile  = Get-ChildItem -Path $tempDir -Filter '*.pwdb' | Select-Object -First 1; $keyFile = Get-ChildItem -Path $tempDir -Filter '*.key'  | Select-Object -First 1
if (-not $dbFile -or -not $keyFile) {$script:warning = "Backup is missing required files:`n" + (if (-not $dbFile) {"- Database (.pwdb)`n"} else {""}) + (if (-not $keyFile) {"- Key file (.key)`n"} else {""})
Remove-Item $tempDir -Recurse -Force; nomessage; return}

$destDb  = Join-Path $script:databasedir $dbFile.Name; $destKey = Join-Path $script:keydir     $keyFile.Name
if (Test-Path $destDb) {Write-Host -f red "`nOverwrite existing database '$($dbFile.Name)'? (Y/N) " -n
if ((Read-Host) -notmatch '[Yy]$') {$script:warning = "Database overwrite declined. Restore aborted."; Remove-Item $tempDir -Recurse -Force; nomessage; return}}

if (Test-Path $destKey) {Write-Host -f red "Overwrite existing key file '$($keyFile.Name)'? (Y/N) " -n
if ((Read-Host) -notmatch '[Yy]$') {$script:warning = "Key overwrite declined. Restore aborted."; Remove-Item $tempDir -Recurse -Force; nomessage; return}}

Copy-Item -Path $dbFile.FullName  -Destination $destDb -Force; Copy-Item -Path $keyFile.FullName -Destination $destKey -Force

if ($chosenFile -match '(?i)((\\[^\\]+){2}\\[^\\]+\.ZIP)') {$shortfile = $matches[1]} else {$shortfile = $chosenFile}
$script:message = "Restored '$($dbFile.Name)' and '$($keyFile.Name)' from backup: $shortfile"; nowarning}
catch {$script:warning = "Restore failed:`n$_"; nomessage; return}
finally {if (Test-Path $tempDir) {Remove-Item $tempDir -Recurse -Force}}; return}


#---------------------------------------------MANAGEMENT MENU: USER--------------------------------

function viewuser {# View the user registry.
loadregistry

if (-not $script:users -or $script:users.Count -eq 0) {$script:warning = "📭 No users found in registry."; nomessage; return}

Write-Host -f white "`n`n📋 Registered Users:`n"

foreach ($entry in $script:users) {if (-not (verifyentryhmac $entry)) {Write-Host -f red "⚠️  Skipping tampered or invalid user entry."; continue}
$user = $entry.data; $status = if ($user.Active) {"✅ Active"} else {"🚫 Inactive"}
Write-Host -f yellow ("-" * 50)
Write-Host -f white "👤 User:    $($user.Username)"
Write-Host -f white "🔑 Role:    $($user.Role)"
Write-Host -f white "🕓 Created: $($user.Created)"
Write-Host -f white "📅 Expires: $($user.Expires)"
Write-Host -f white "📌 Status:  $status"}
Write-Host -f yellow ("-" * 50)
Write-Host -f white "`n↩️[RETURN] " -n; Read-Host}

function addregistryuser {# Add a user.
loadregistry

# Ask for username.
Write-Host -f white "`n`n👤 Enter new username " -n; $username = Read-Host
if (-not ($username -match '^[a-zA-Z]{5,12}[0-9]{0,3}$')) {$script:warning = "❌ Invalid username format. Must be 5–12 letters, optionally ending in 0–3 digits."; nomessage; return}

# Ensure $script:users is always an array
if (-not $script:users) {$script:users = @()}
elseif ($script:users -isnot [System.Collections.IEnumerable]) {$script:users = @($script:users)}
if ($script:users | Where-Object {$_.data.Username -eq $username}) {$script:warning = "⚠️ User already exists."; nomessage; return}

# Ask for password.
Write-Host -f white "🔐 Enter password " -n; $secure1 = Read-Host -AsSecureString
Write-Host -f white "🔁 Re-enter password " -n; $secure2 = Read-Host -AsSecureString
$plain1 = [System.Net.NetworkCredential]::new("", $secure1).Password; $plain2 = [System.Net.NetworkCredential]::new("", $secure2).Password; $secure1.Dispose(); $secure2.Dispose()
if ($plain1 -ne $plain2) {$script:warning = "❌ Passwords do not match."; nomessage; return}
if ($plain1.Length -lt 8 -or $plain1 -notmatch '[a-z]' -or $plain1 -notmatch '[A-Z]' -or $plain1 -notmatch '[0-9]' -or $plain1 -notmatch '[^a-zA-Z0-9]') {$script:warning = "❌ The password must be at least 8 characters long and include upper-case and lower-case letters, digits and symbols."; nomessage; return}

# Ask for role.
Write-Host -f white "`n👥 Role? [standard/privileged] " -n; $role = Read-Host
if ($role -notin @('standard','privileged')) {$script:warning = "❌ Role must be 'standard' or 'privileged'."; nomessage; return}

# Ask for Expiration date.
Write-Host -f white "⏳ Expiration date (yyyy-MM-dd) (leave blank or invalid = today + 365) " -n; $expires = Read-Host
if (-not $expires) {$expiry = (Get-Date).AddDays(365)}
else {try {$expiry = [datetime]::ParseExact($expires, 'yyyy-MM-dd', $null)}
catch {$script:warning = "❌ Invalid expiration format.❌ Invalid expiration format. Using default (today + 365 days)."; $expiry = (Get-Date).AddDays(365); nomessage; return}}

# Ask for Active status.
Write-Host -f white "🔘 Active? [true/false] (leave blank or invalid = true) " -n; $active = Read-Host
if ($active.ToLower() -eq 'false') {$activeStatus = $false}
else {if ($active -ne '' -and $active.ToLower() -ne 'true') {Write-Host -f white "❌ Invalid active status. Defaulting to active."}
$activeStatus = $true}

$salt = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt); $derived = derivekeyfrompassword $plain1 $salt; $sha256 = [Security.Cryptography.SHA256]::Create(); $hash = $sha256.ComputeHash($derived); $sha256.Dispose(); $encoded = [Convert]::ToBase64String($salt + $hash)

$data = [PSCustomObject]@{Username = $username
Password = $encoded
Role     = $role
Created  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
Expires  = $expiry.ToUniversalTime().ToString("yyyy-MM-dd")
Active   = $activeStatus}
$hmac = createperentryhmac $data $script:key
$entry = [PSCustomObject]@{data = $data; hmac = $hmac}
$script:users += $entry; saveregistry; $script:message = "✅ User '$username' added as $role."; nowarning; return}

function updateregistryuser {# Change user details.
loadregistry

if (-not $script:users -or $script:users.Count -eq 0) {$script:warning = "📭 No users found in registry."; nomessage; return}

# Ensure $script:users is always an array
if (-not $script:users) {$script:users = @()}
elseif ($script:users -isnot [System.Collections.IEnumerable]) {$script:users = @($script:users)}

Write-Host -f white "`n`n👤 Enter username to update: " -n; $username = Read-Host
if (-not ($script:users -is [System.Collections.IEnumerable])) {$script:users = @()}
$entry = $script:users | Where-Object {$_.data.Username -eq $username}
if (-not $entry) {$script:warning = "❌ User '$username' not found."; nomessage; return}

# Update password
Write-Host -f white "🔐 Enter new password (leave blank to keep current): " -n; $secure1 = Read-Host -AsSecureString
if ($secure1.Length -gt 0) {Write-Host -f white "🔁 Re-enter new password: " -n; $secure2 = Read-Host -AsSecureString
$plain1 = [System.Net.NetworkCredential]::new("", $secure1).Password; $plain2 = [System.Net.NetworkCredential]::new("", $secure2).Password; $secure1.Dispose(); $secure2.Dispose()
if ($plain1 -ne $plain2) {$script:warning = "❌ Passwords do not match."; nomessage; return}
if ($plain1.Length -lt 8 -or $plain1 -notmatch '[a-z]' -or $plain1 -notmatch '[A-Z]' -or $plain1 -notmatch '[0-9]' -or $plain1 -notmatch '[^a-zA-Z0-9]') {$script:warning = "❌ The password must be at least 8 characters long and include upper-case and lower-case letters, digits and symbols."; nomessage; return}

$salt = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt); $derived = derivekeyfrompassword $plain1 $salt; $sha256 = [Security.Cryptography.SHA256]::Create(); $hash = $sha256.ComputeHash($derived); $sha256.Dispose(); $encoded = [Convert]::ToBase64String($salt + $hash); $entry.data.Password = $encoded}

# Update role
Write-Host -f white "👥 Role? [standard/privileged] (leave blank to keep current) " -n; $role = Read-Host
if ($role) {if ($role -notin @('standard','privileged')) {$script:warning = "❌ Role must be 'standard' or 'privileged'."; nomessage; return}
$entry.data.Role = $role}

# Update expiration date
Write-Host -f white "⏳ Expiration date (yyyy-MM-dd) (leave blank to keep current) " -n; $expires = Read-Host
if ($expires) {try {$expiry = [datetime]::ParseExact($expires, 'yyyy-MM-dd', $null); $entry.data.Expires = $expiry.ToString('yyyy-MM-dd')}
catch {$script:warning = "❌ Invalid expiration format."; nomessage; return}}

# Update active status
Write-Host -f white "🔘 Active? [true/false] (leave blank to keep current) " -n; $active = Read-Host
if ($active) {if ($active.ToLower() -in @('true','false')) {$entry.data.Active = [bool]::Parse($active)}
else {$script:warning = "❌ Active status must be 'true' or 'false'. Leaving unmodified."; nomessage; return}}

# Refresh HMAC and save
$entry.hmac = createperentryhmac $entry.data $script:key; saveregistry; $script:message = "✅ User '$username' updated."; nowarning; return}

function removeregistryuser {# Remove a user.
loadregistry
if (-not $script:users -or $script:users.Count -eq 0) {$script:warning = "📭 No users found in registry."; nomessage; return}

Write-Host -f white "`n`n👤 Enter username to remove: " -n; $username = Read-Host
$entry = $script:users | Where-Object {$_.data.Username -eq $username}
if (-not $entry) {$script:warning = "❌ User '$username' not found."; nomessage; return}

Write-Host -f red "`nConfirm removal of user '$username': (Y/N) " -n; $confirm = Read-Host
if ($confirm -match '^[Yy]') {$script:users = @($script:users | Where-Object {$_.data.Username -ne $username})
saveregistry; $script:message = "✅ User '$username' removed."; nowarning; return}
else {$script:warning = "Aborted."; nomessage; return}}

#---------------------------------------------MENU DISPLAY-----------------------------------------

function rendermenu {# Dynamically display menus.

function startline {# |...
Write-Host -f cyan "|" -n}

function horizontal {# |--...--|
Write-Host -f cyan "|" -n; Write-Host -f cyan ("-" * 70) -n; Write-Host -f cyan "|"}

function linecap {# ...|
Write-Host -f cyan "|"}

function endcap {# +---...---+
Write-Host -f cyan "+" -n; Write-Host -f cyan ("-" * 70) -n; Write-Host -f cyan "+"}

function menuheader {# Define header.
# Title and countdown timer.
cls; ""; endcap
startline; Write-Host -f white " 🔑 Secure Paschwords Manager v$script:version 🔒".padright(52) -n
if ($script:minutes -ge 99) {[int]$timerdisplay = 99} else {[int]$timerdisplay = $script:minutes +1}
if ($script:unlocked) {if ($countdown -ge 540) {Write-Host -f green "🔒 in $timerdisplay minutes. " -n}
elseif ($countdown -lt 540 -and $countdown -ge 60) {Write-Host -f green " 🔒 in $($script:minutes +1) minutes. " -n}
elseif ($countdown -lt 60) {Write-Host -f red -n ("      🔒 in 0:{0:D2} " -f $script:seconds)}
else {Write-Host "`t`t    🔒 "-n}} 
else {Write-Host "`t`t    🔒 "-n}; linecap
horizontal

# Loaded resource display.
if ($script:database) {$displaydatabase = Split-Path -Leaf $script:database -ea SilentlyContinue} else {$displaydatabase = "none loaded"}
if ($script:keyfile) {$displaykey = Split-Path -Leaf $script:keyfile -ea SilentlyContinue} else {$displaykey = "none loaded"}
$databasestatus = if ($db -and $key -and $db -ne $key) {"🤔"} elseif ($displaykey -eq "none loaded" -or $displaydatabase -eq "none loaded" -or $script:unlocked -eq $false) {"🔒"} else {"🔓"}
$keystatus = if ($script:unlocked -eq $false -or $displaykey -eq "none loaded") {"🔒"} else {"🔓"}

startline; Write-Host -f white " Current database: " -n; Write-Host -f green "$displaydatabase $databasestatus".padright(33) -n
Write-Host -f yellow "⏱️ [T]imer reset. " -n; linecap
startline; Write-Host -f white " Current key: " -n; Write-Host -f green "$displaykey $keystatus".padright(35) -n
if ($displaydatabase -eq "none loaded" -or $displaykey -eq "none loaded") {Write-Host -f green "♻️ Rel[O]ad defaults." -n} else {Write-Host (" " * 21) -n};linecap

if ($displaydatabase -match '^(?i)(.+?)\.pwdb$') {$db = $matches[1]}
if ($displaykey -match '^(?i)(.+?)\.key$') {$key = $matches[1]}
if (($displaykey -eq "none loaded" -or $displaydatabase -eq "none loaded") -and ($script:database -or $script:keyfile)) {if ($script:warning -notmatch "Make sure") {if ($script:warning) {$script:warning += "`n"}; $script:warning += "Make sure to load both a database and a keyfile before continuing."}
if ($db -and $key -and $db -ne $key) {startline; Write-Host -f red " Warning: " -n; Write-Host -f yellow "The key and database filenames do not match.".padright(60) -n; linecap
if ($script:warning -notmatch "Continuing") {if ($script:warning) {$script:warning += "`n"}; $script:warning += "Continuing with an incorrect key and database pairing could lead to data corruption. Ensure you have the correct file combination before making any file changes."}}}
horizontal}

function menufooter {# Define footer.
horizontal
# Session options.
startline; if ($script:unlocked -eq $true) {Write-Host " 🔓 " -n} else {Write-Host " 🔒 " -n}
if ($script:unlocked -eq $true) {Write-Host -f red "[L]ock Session " -n} else {Write-Host -f darkgray "[L]ock Session " -n}
Write-Host -f white "/ " -n;
if ($script:unlocked -eq $true) {Write-Host -f darkgray "[U]nlock session".padright(22) -n} else {Write-Host -f green "[U]nlock session".padright(22) -n}
if (-not (Test-Path $script:keyfile -ea SilentlyContinue)) {Write-Host -f black -b yellow "❓ [H]elp <-- " -n; Write-Host "".padright(4) -n}
else {Write-Host -f yellow "❓ [H]elp".padright(17) -n}
Write-Host -f gray "⏏️ [ESC] " -n;; linecap 
horizontal

# Key message: 
startline; Write-Host -f cyan " 🔐 Active key in use: " -n
if ($script:rootkey -is [byte[]] -and $script:rootkey.Length -eq 32) {Write-Host -f red "Master key".padright(21) -n; Write-Host -f cyan "🪪 User: " -n; Write-Host -f red "$script:loggedinuser".padright(17) -n}
elseif ($script:key) {Write-Host -f white "Database key".padright(21) -n; Write-Host -f cyan "🪪 User: " -n; Write-Host -f white "$script:loggedinuser".padright(17) -n}
else {Write-Host -f darkgray "No valid key loaded".padright(47) -n}
linecap

# Message and warning center.
endcap
$script:message = wordwrap $script:message; $script:warning = wordwrap $script:warning
if ($script:message.length -ge 1) {Write-Host "  🗨️" -n; indent $script:message white 2}
if ($script:warning.length -ge 1) {Write-Host "  ⚠️" -n; indent $script:warning red 2}
if ($script:message.length -ge 1 -or $script:warning.length -ge 1 ) {Write-Host -f cyan ("-" * 72)}
Write-Host -f white "⚡ Choose an action: " -n}

menuheader

if (-not $script:management) {# Display basic menu.
# Display menu options.
$clipboard = if ($script:noclip -eq $true) {"🚫"} else {"📋"}
startline; Write-Host -f cyan " R. " -n; Write-Host -f white "🔓 [R]etrieve an entry.".padright(50) -n; Write-Host -f cyan "Z. " -n; Write-Host -f white "Clipboard $clipboard " -n; linecap
startline; Write-Host -f cyan " A. " -n; Write-Host -f yellow "➕ [A]dd a new entry.".padright(65) -n; linecap
startline; Write-Host -f cyan " C. " -n; Write-Host -f yellow "✏️ [C]hange an existing entry.".padright(66) -n; linecap
startline; Write-Host -f cyan " X. " -n; Write-Host -f red "❌ Remove an entry.".padright(65) -n;linecap
horizontal
startline; Write-Host -f cyan " B. " -n; Write-Host -f white "🧐 [B]rowse all entries: " -n; Write-Host -f cyan "$(($script:jsondatabase).Count)".padright(41) -n; linecap
$today = Get-Date; $expiredcount = ($script:jsondatabase | Where-Object {$_.data.Expires -and ($_.data."Expires" -as [datetime]) -le $today}).Count
startline; Write-Host -f cyan " E. " -n; Write-Host -f white "⌛ [E]xpired entries view: " -n; if ($expiredcount -eq 0) {Write-Host -f green "0".padright(39) -n} else {Write-Host -f red "$expiredcount".padright(39) -n}; linecap
startline; Write-Host -f cyan " S. " -n; Write-Host -f white "🔍 [S]earch entries.".padright(66) -n; linecap
startline; Write-Host -f cyan " N. " -n; Write-Host -f white "🖥  [N]etwork IPs.".padright(67) -n; linecap
startline; Write-Host -f cyan " V. " -n; Write-Host -f white "🌐 [V]alid URLs.".padright(66) -n; linecap
startline; Write-Host -f cyan " I. " -n; Write-Host -f white "👎 [I]nvalid URLs.".padright(66) -n; linecap
horizontal
startline; Write-Host -f cyan " D. " -n; Write-Host -f white "📑 Select a different password [D]atabase.".padright(66) -n; linecap
startline; Write-Host -f cyan " K. " -n; Write-Host -f white "🗝️ Select a different password encryption [K]ey.".padright(67) -n; linecap
horizontal
startline; Write-Host -f cyan " M. " -n; Write-Host -f white "🛠️ [M]anagement Menu. ".padright(67) -n; linecap}

elseif ($script:management){# Display management menu.
startline; Write-Host -f cyan " D. " -n; Write-Host -f white "📑 Select a different password [D]atabase.".padright(47) -n; if ($script:disablelogging) {Write-Host -f red "Logging is off. 🔴 " -n} else {Write-Host -f green "Logging is on.  🟢 " -n}; linecap
startline; Write-Host -f cyan " K. " -n; Write-Host -f white "🗝️ Select a different encryption [K]ey.".padright(67) -n; linecap
horizontal
startline; Write-Host -f cyan " N. " -n; Write-Host -f yellow "📄 Create a [N]ew password database.".padright(66) -n; linecap
startline; Write-Host -f cyan " S. " -n; Write-Host -f white "✅ [S]anitize a PWDB file, correcting IV collisions.".padright(65) -n; linecap
horizontal
startline; Write-Host -f cyan " I. " -n; Write-Host -f yellow "📥 [I]mport a CSV plaintext password database.".padright(66) -n; linecap
startline; Write-Host -f cyan " E  " -n; Write-Host -f white "📤 [E]xport database to CSV, but " -n; Write-Host -f green "encryption remains intact. ".padright(33) -n; linecap
startline; Write-Host -f cyan " F. " -n; Write-Host -f white "📂 [F]ull database export with " -n; Write-Host -f red "unencrypted" -n; Write-Host -f white " passwords.".padright(24) -n; linecap
horizontal
startline; Write-Host -f cyan " P. " -n; Write-Host -f white "🧬 [P]assword change for database access key.".padright(66) -n; linecap
startline; Write-Host -f cyan " J. " -n; Write-Host -f white "🔗 [J]oin the database to a Master key: " -n
$dbkey = Get-ChildItem -Path $privilegedir -Filter '*.dbkey' -File -ea SilentlyContinue
if (Test-Path $script:rootKeyFile -ea SilentlyContinue) {if ($dbkey.Count -eq 0) {Write-Host -f green "Master key exists.".padright(26) -n}
elseif ($dbkey.Count -eq 1) {Write-Host -f green "1 child key exists.".padright(26) -n}
else {Write-Host -f green "$($dbkey.Count) child keys exist.".padright(26) -n}}
else {Write-Host -f darkgray "no Master key exists yet.".padright(26) -n}
linecap
startline; Write-Host -f cyan " W. " -n; Write-Host -f white "👑 [W]rite a new Master password.".padright(66) -n; linecap
startline; Write-Host -f cyan " G. " -n; Write-Host -f white "🛡️ [G]rant Master key privileges.".padright(67) -n; linecap
horizontal
startline; Write-Host -f cyan " B. " -n; Write-Host -f white "📦←︎ [B]ackup current database, key and privilege directory.".padright(67) -n; linecap
startline; Write-Host -f cyan " R. " -n; Write-Host -f yellow "📦→︎ [R]estore a backup.".padright(67) -n; linecap
horizontal
startline; Write-Host -f cyan " V. " -n; Write-Host -f white "🔍 [V]iew the user registry.".padright(66) -n; linecap
startline; Write-Host -f cyan " A. " -n; Write-Host -f white "➕ [A]dd a user.".padright(65) -n; linecap
startline; Write-Host -f cyan " C. " -n; Write-Host -f white "✏️ [C]hange user details.".padright(66) -n; linecap
startline; Write-Host -f cyan " X. " -n; Write-Host -f red "❌ Remove a user.".padright(65) -n; linecap
horizontal
startline; Write-Host -f cyan " Z. " -n; Write-Host -f darkcyan "🧙‍♂️ New workspace setup Wi[Z]ard: " -n; Write-Host -f white "key, database & user registry.".padright(33) -n; linecap
horizontal

startline; Write-Host -f cyan " M. " -n; Write-Host -f white "🏠️ [M]ain Menu. ".padright(67) -n; linecap}
menufooter}

function loggedin {# Dynamic menu interaction.
$script:sessionstart = Get-Date; $choice = $null
loadjson
scheduledbackup
rendermenu

do {# Wait for a keypress, in order to refresh the screen.
while (-not [Console]::KeyAvailable -and -not $script:quit) {

# End function at user request.
if ($script:quit) {logoff; return}

# End script after a preset number of minutes of inactivity.
if ($script:timetoboot -ne $null) {$elapsed = (Get-Date) - $script:timetoboot
if ($elapsed.TotalMinutes -ge $script:timetobootlimit) {$script:quit = $true; logoff; return}}

# Set session timer variables.
$timeout = (Get-Date).AddSeconds(10); $countdown = [int]($script:timeoutseconds - ((Get-Date) - $script:sessionstart).TotalSeconds); if ($countdown -lt 0) {$countdown = 0}; $script:minutes = [int]([math]::Floor($countdown / 60)); $script:seconds = $countdown % 60

# Lock session when timer runs out and break from continual refreshes.
if ($script:unlocked -eq $true -and $countdown -le 0) {neuralizer; $script:message = "Session timed out. The key has been locked."; nowarning; rendermenu}

# Refresh display if session is unlocked
if ($script:unlocked -and ($countdown -lt 60 -or $script:minutes -lt $script:lastrefresh)) {rendermenu; $script:lastrefresh = $script:minutes}

# Wait for next loop.
if ($countdown -gt 60) {Start-Sleep -Milliseconds 250}
else {Start-Sleep -Seconds 1}}

# Send key presses to the menu for processing.
if ([Console]::KeyAvailable -and -not $script:quit) {$key = [Console]::ReadKey($true); $choice = $key.Key.ToString().ToUpper()

logchoices $choice $script:message $script:warning


#---------------------------------------------MENU CHOICES-----------------------------------------

if (-not $script:management) {# Main menu key options
switch ($choice) {
'R' {# Retrieve an entry.
if (-not $script:keyfile) {$script:warning = "🔑 No key loaded. "; nomessage; return}

if (-not $script:jsondatabase) {$script:warning = "📑 No database loaded. " + $script:warning; nomessage}

if ($script:keyfile -and $script:jsondatabase) {Write-Host -f green "`n`n🔓 Enter Title, 🆔 Username, 🔗 URL, 🏷  Tag or 📝 Note to identify entry: " -n; $searchterm = Read-Host}

if ([string]::IsNullOrWhiteSpace($searchterm)) {$script:warning = "No search term provided."; nomessage}

elseif ($searchterm) {retrieveentry $script:jsondatabase $script:keyfile $searchterm $noclip}
rendermenu}

'A' {# Add a new entry.
newentry $script:database $script:keyfile; rendermenu}

'C' {# Change an existing entry.
Write-Host -f green "`n`n🔓 Enter Title, 🆔 Username, 🔗 URL, 🏷  Tag or 📝 Note to identify entry (comma separated): " -n; $searchterm = Read-Host
if ([string]::IsNullOrWhiteSpace($searchterm)) {$script:warning = "No search term provided."; nomessage; rendermenu; break}
elseif ($searchterm) {updateentry $script:jsondatabase $script:keyfile $searchterm}
rendermenu}

'X' {# Remove an entry.
Write-Host -f red "`n`n❌ Enter Title, Username, URL, Tag or Note to identify entry: " -n; $searchterm = Read-Host; removeentry $searchterm; rendermenu}

'B' {# Browse all entries.
if (-not $script:jsondatabase -or -not $script:jsondatabase.Count) {$script:warning = "No valid entries loaded in memory to display."; nomessage}
else {showentries $script:jsondatabase; nomessage; nowarning}}

'E' {# Expired entries view.
if (-not $script:jsondatabase -or -not $script:jsondatabase.Count) {$script:warning = "📑 No database loaded. "; nomessage; rendermenu}

$expiredEntries = $script:jsondatabase | Where-Object {try {[datetime]::Parse($_.data.expires) -le (Get-Date)}
catch {$false}}

if (-not $expiredEntries.Count) {$script:warning = "No expired entries found."}
else {showentries $expiredEntries -expired; nowarning}; nomessage; rendermenu}

'S' {# Search entries.
if (-not $script:jsondatabase -or $script:jsondatabase.Count -eq 0) {$script:warning = "📑 No database loaded. "; nomessage; rendermenu; break}

Write-Host -f yellow "`n`nProvide a comma separated list of keywords to find: " -n; $keywords = Read-Host

if (-not $keywords -or $keywords.Trim().Length -eq 0) {$matchedEntries = $null; $script:warning = "No search terms provided."; nomessage; rendermenu; break}

# Split keywords, trim and to lowercase for case-insensitive matching
$pattern = "(?i)(" + ($keywords -replace "\s*,\s*", "|") + ")"; $matchcount = 0; $script:warning = $null
foreach ($entry in $script:jsondatabase) {if ($entry.data.Title -match $pattern -or $entry.data.Username -match $pattern -or $entry.data.URL -match $pattern -or $entry.data.Tags -match $pattern -or $entry.data.Notes -match $pattern) {if (-not (verifyentryhmac $entry)) {$script:warning += "Entry $($entry.data.title) has an invalid HMAC and will be ignored. "; nomessage; continue}
$matchcount++; break}}

if ($matchcount -eq 0) {$script:warning = "No matches found for provided keywords."; nomessage; rendermenu}

else {showentries $script:jsondatabase -search -keywords "$pattern"; nomessage; nowarning}}

'N' {# Network IPs.
if (-not $script:jsondatabase -or -not $script:jsondatabase.Count) {$script:warning = "📑 No database loaded. "; nomessage; rendermenu}
else {showentries $script:jsondatabase -ips; nomessage; nowarning}}

'V' {# Valid URLs.
if (-not $script:jsondatabase -or -not $script:jsondatabase.Count) {$script:warning = "📑 No database loaded. "; nomessage; rendermenu}
else {showentries $script:jsondatabase -validurls; nomessage; nowarning}}

'I' {# Invalid URLs.
if (-not $script:jsondatabase -or -not $script:jsondatabase.Count) {$script:warning = "📑 No database loaded. "; nomessage; rendermenu}
else {showentries $script:jsondatabase -invalidurls; nomessage; nowarning}}

'Z' {# Toggle clipboard.
if ($script:noclip -eq $true) {$script:noclip = $false; $script:message = "Retrieved passwords will be copied to the clipboard for $script:delayseconds seconds."; nowarning; rendermenu}
elseif ($script:noclip -eq $false) {$script:noclip = $true; $script:message = "Retrieved passwords will not be copied to the clipboard."; nowarning; rendermenu}}}}

if ($script:management) {# Management menu key options
switch ($choice) {
'N' {# Create a new password database.
if (-not $script:key) {$script:warning = "You must have a key loaded, in order for it to be associated to the database."; nomessage; rendermenu}
Write-Host -f green "`n`n📄 Enter filename for new password database: " -n; $getdatabase = Read-Host
if ($getdatabase.length -lt 1) {$script:warning = "No filename entered."; nomessage; rendermenu}
else {if (-not $getdatabase.EndsWith(".pwdb")) {$getdatabase += ".pwdb"}
$path = Join-Path $script:databasedir $getdatabase
if (Test-Path $path) {$script:warning = "File already exists. Choose a different name."; nomessage}
else {$script:jsondatabase = $null; $script:jsondatabase = @(); decryptkey $script:keyfile; $script:database = $Path
savetodisk; $script:message = "📄 New database $getdatabase created."; nowarning}; rendermenu}}

'S' {# Sanitize a PWDB file, correcting IV collisions.
validatedatabase; rendermenu}

'I' {# Import a CSV plaintext password database.
$script:message = "Imported files must contain the fields: Title, Username, Password and URL. Timestamp is ignored and Password can be empty, but must exist. All other fields can be added as notes and/or tags. Fields added to notes will only be added if they are populated. Fields added to tags can be added to all imported entries or only those that are populated."; nowarning
if (-not $script:database -and -not $script:keyfile) {$script:warning = "You must have a database and key file loaded in order to start an import."; nomessage; break}
Write-Host -f yellow "`n`n📥 Enter the full path to the CSV file: " -n; $csvpath = Read-Host
if ($csvpath.length -lt 1) {$script:warning = "Aborted."; nomessage; rendermenu}
elseif (Test-Path $csvpath -ea SilentlyContinue) {importcsv $csvpath}
else {$script:warning = "CSV not found."; nomessage}; rendermenu}

'E' {# Export database to CSV, but encryption remains intact.
nomessage; nowarning; rendermenu
Write-Host -f yellow "`n`nProvide an export path for the database.`nOtherwise the database directory will be used: " -n; $path = Read-Host
if ($path.length -lt 1) {$path = "$script:database"; $path = $path -replace '\.pwdb$', '.csv'}
Write-Host -f yellow "`nSpecify the fields and the order in which to includet them.`nThe default is (" -n; Write-Host -f white "Title, Username, URL" -n; Write-Host -f yellow "): " -n; $fields = Read-Host
if ($fields.length -lt 1) {$fields = "Title,Username,URL"}
$fields = $fields -replace "\s*,\s*", ","
Write-Host -f yellow "`nProceed? (Y/N) " -n; $confirmexport = Read-Host
if ($confirmexport -match "^[Yy]$") {export $path $fields; rendermenu} else {$script:warning = "Aborted."; nomessage; rendermenu}}

'F' {# Full database export with unencrypted passwords.
if ($script:unlocked) {fulldbexport; rendermenu}}

'P' {# Password change for database access key.
rewrapdbkey; ""; decryptkey $script:keyfile; loadjson; rendermenu}

'J' {# If master privilege key doesn't exist yet, initialize it.
if (-not (Test-Path $script:rootkeyFile -ea SilentlyContinue)) {initializeprivilege -Key $script:key -Master $null; wrapdbkeyformaster ([IO.Path]::GetFileNameWithoutExtension($script:keyfile)); rendermenu; break}
elseif (Test-Path $script:rootkeyFile -ea SilentlyContinue) {wrapdbkeyformaster ([IO.Path]::GetFileNameWithoutExtension($script:keyfile)); rendermenu}}

'W' {# Write a new Master password.
if ($script:key) {rotatemasterpassword; rendermenu}}

'G' {# Grant Master key privileges.
if (masterlockout) {break}
if (-not (switchtomasterkey)) {$script:rootkey = $null}; rendermenu}

'B' {# Backup current database, key and privilege directory.
backup
Write-Host -f yellow "`n`nDo you also want to backup the privilege directory? " -n; $confirmprivilegebackup = Read-Host
if ($confirmprivilegebackup -match "^[Yy]") {backupprivilege}
rendermenu}

'R' {# Retore a backup.
restore; rendermenu}

'V' {# View the user registry.
viewuser; rendermenu}

'A' {# Add a user.
addregistryuser; rendermenu}

'C' {# Change user details.
updateregistryuser; rendermenu}

'X' {# Remove a user.
removeregistryuser; rendermenu}

'Z' {# Setup Wizard.
Write-Host -f green "`n`n🔑 Enter a filename for the new key and database: " -n; $getkey = Read-Host
if ($getkey -lt 1) {$script:warning = "No filename entered."; nomessage; rendermenu}
newkey $getkey; rendermenu}

'F4' {# Turn off Logging.
if ($script:keyfile -match '\\([^\\]+)$') {$shortkey = $matches[1]}
if ($script:disablelogging -eq $true) {$script:warning = "Logging is already turned off for $shortkey."; nomessage; rendermenu; break}
elseif ($script:disablelogging -eq $false) {$script:disablelogging = $true; $script:warning = "Logging temporarily turned off for $shortkey @ $(Get-Date)"; nomessage; rendermenu}}

'F10' {# Modify PSD1 configuration.
""; decryptkey $script:keyfile
if ($script:unlocked) {modifyconfiguration; $script:database = $script:defaultdatabase; $script:keyfile = $script:defaultkey; Write-Host -f yellow "Reloading default key and database."; decryptkey $script:keyfile
if ($script:unlocked) {$script:message = "New configuration active. Default key and database successfully loaded and made active."; nowarning}}
rendermenu}

'F12' {# Sort and resave database.
""; decryptkey $script:keyfile
if ($script:unlocked) {saveandsort; if ($script:message) {$script:message += "`nDatabase has been sorted by tag, then title."}}
rendermenu}}}

switch ($choice) {# Shared menu key options
'D' {# Select a different password database.
$dbFiles = Get-ChildItem -Path $script:databasedir -Filter *.pwdb
if (-not $dbFiles) {$script:warning = "No .pwdb files found."; nomessage; rendermenu}
else {Write-Host -f white "`n`n📑 Available Password Databases:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $dbFiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $dbFiles[$i].Name}
Write-Host -f green "`n📑 Enter number of the database file to use: " -n; $sel = Read-Host
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $dbFiles.Count) {$script:jsondatabase = $null; $script:database = $dbFiles[$sel - 1].FullName; $dbloaded = $script:database -replace '.+\\Modules\\', ''; loadjson; $script:message = "$dbloaded selected and made active."; nowarning
if ($script:jsondatabase.Count -eq 0) {$script:warning = "If changing database and key combinations, always load the key before the database."} else {nowarning}}
else {$script:warning = "Invalid selection."; nomessage}; rendermenu}}

'K' {# Select a different password encryption key.
$script:keyfiles = Get-ChildItem -Path $script:keydir -Filter *.key
if (-not $script:keyfiles) {$script:warning = "No .key files found."; nomessage; rendermenu}
elseif ($script:keyfiles) {Write-Host -f white "`n`n🗝  Available AES Key Files:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $script:keyfiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $script:keyfiles[$i].Name}
Write-Host -f green "`n🗝  Enter number of the key file to use: " -n; $sel = Read-Host
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $script:keyfiles.Count) {$script:keyfile = $script:keyfiles[$sel - 1].FullName; $script:keyexists = $true; nowarning; neuralizer; decryptkey $script:keyfile
if ($script:unlocked) {if ($script:keyfile -match '(?i)((\\[^\\]+){2}\\\w+\.KEY)') {$shortkey = $matches[1]}
else {$shortkey = $script:keyfile}

$providedkeyname = [IO.Path]::GetFileNameWithoutExtension($script:keyfile); $script:registryfile = Join-Path $privilegedir "$providedkeyname.db"; $script:database = Join-Path $databasedir "$providedkeyname.pwdb"
if (-not (Test-Path $script:database -ea SilentlyContinue)) {$script:database = $null; $script:registryfile = $null}
else {loadjson}

$script:database; $script:registryfile
$script:message = "$shortkey selected and made active."; nowarning; $script:disablelogging = $false}
if (-not $script:key) {$script:warning += " Key decryption failed. Aborting."; nomessage}}}; rendermenu}

'M' {# Toggle Management mode.
if ($script:management -eq $true) {$script:management = $false; nowarning; nomessage; rendermenu; break}
if ($script:standarduser) {$script:warning = "You do not have sufficient privileges."; nomessage; rendermenu; break}
if (-not $script:management) {nowarning; nomessage; $script:management = $true}
nowarning; nomessage; rendermenu}

'L' {# Lock session.
$script:message = "Session locked."; nowarning; neuralizer; rendermenu}

'U' {# Unlock session.
if (-not $script:key) {$script:warning = "🔑 No key loaded. "; nomessage; rendermenu; break}
if ($script:unlocked) {break}
if ($script:key -and -not $script:unlocked) {""; $script:key = $null; 
if ($script:rootkey) {wipe ([ref]$script:rootkey)}
decryptkey $script:keyfile}
if ($script:unlocked) {loadjson; $script:disablelogging = $false; $script:message += "Session unlocked."; nowarning}
rendermenu}

'H' {# Help.
nowarning
if ($script:keyexists -eq $false) {$script:warning = "First time use: You will need to create key and database files with the menu options above. The defaults configured in the PSD1 file use the filename 'paschwords' for both."}
else {helptext}; rendermenu}

'F1' {# Help.
nowarning
if ($script:keyexists -eq $false) {$script:warning = "First time use: You will need to create key and database files with the menu options above. The defaults configured in the PSD1 file use the filename 'paschwords' for both."}
else {helptext}; rendermenu}

'ESCAPE' {# Quit. (Includes funky logic to capture keys after the user confirms.)
Write-Host -f green "`n`nAre you sure you want to quit? (Y/N) " -n; $confirmquit = Read-Host
if ($confirmquit -notmatch "^[Yy]$") {$script:warning = "Aborted."; nomessage; rendermenu}
else {$script:quit = $true; logoff; while ([Console]::KeyAvailable) {return}; return}}

'Q' {# Quit. (Includes funky logic to capture keys after the user confirms.)
Write-Host -f green "`n`nAre you sure you want to quit? (Y/N) " -n; $confirmquit = Read-Host
if ($confirmquit -notmatch "^[Yy]$") {$script:warning = "Aborted."; nomessage; rendermenu}
else {$script:quit = $true; logoff; while ([Console]::KeyAvailable) {return}; return}}

'T' {# Set Timer.
if (-not $script:keyfile -or -not $script:unlocked) {$script:warning = "You must have a key loaded and unlocked to reset its timer."; nomessage; rendermenu}
else {""; decryptkey $script:keyfile
if (-not $script:unlocked) {neuralizer; rendermenu}
if ($script:unlocked) {loadjson; Write-Host -f yellow "`nHow many minutes should the session remain unlocked? (1-99) " -n; $usersetminutes = Read-Host; if ($usersetminutes -as [int] -and [int]$usersetminutes -ge 1 -and [int]$usersetminutes -le 99) {$script:timeoutseconds = [int]$usersetminutes * 60; $script:sessionstart = Get-Date; $script:lastrefresh = 99; rendermenu}
else {$script:warning = "Invalid timer value set."; nomessage; rendermenu}}}}

'O' {# Reload defaults.
if (-not $script:database -or -not $script:keyfile) {$script:unlocked = $false; $script:database = $script:defaultdatabase; $script:keyfile = $script:defaultkey; ""; decryptkey $script:keyfile
if ($script:unlocked) {loadjson; $script:message += "Defaults successfully loaded and made active."; nowarning; rendermenu}
else {$script:database = $null; $script:keyfile = $null; rendermenu}}}

'BACKSPACE' {# Clear messages.
nomessage; nowarning; rendermenu}

'ENTER' {# Clear messages.
nomessage; nowarning; rendermenu}

'F9' {# Configuration details.
$fixedkeydir = $keydir -replace '\\\\', '\' -replace '\\\w+\.\w+',''; $fixeddatabasedir = $databasedir -replace '\\\\', '\' -replace '\\\w+\.\w+',''; $configfileonly = $script:configpath -replace '.+\\', ''; $keyfileonly = $defaultkey -replace '.+\\', ''; $databasefileonly = $defaultdatabase -replace '.+\\', ''; $dictionaryfileonly = $dictionaryfile -replace '.+\\', ''; $timeoutminutes = [math]::Floor($timeoutseconds / 60); $privilege = if ($script:standarduser) {"Standard user"} else {"Privileged user"}
$script:message = "Configuration Details:`n`nCurrent User:`t`t   $script:loggedinuser`nAccess:`t`t   $privilege`n`nVersion:`t`t   $script:version`nConfiguration File Path: $configfileonly`nDefault Key:             $keyfileonly`nDefault Database:        $databasefileonly`nDictionary File:         $dictionaryfileonly`n`nSession Inactivity Timer: $timeoutseconds seconds / $timeoutminutes minutes`nScript Inactivity Timer:  $script:timetobootlimit minutes`nClipboard Timer:          $delayseconds seconds`nEntry Expiration Warning: $expirywarning days`nLog Retention:            $logretention days`nBackup Frequency:         $script:backupfrequency days`nArchives Limit:           $script:archiveslimit ZIP files`n`nDirectories:`n$fixedkeydir`n$fixeddatabasedir`n`nValidateURLs User-Agent:`n$script:useragent"; nowarning; rendermenu}

default {if ($choice.length -gt 0) {}}}

#---------------------------------------------END OF MENU CHOICES----------------------------------

# Reset on key press.
$script:sessionstart = Get-Date
$choice = $null}} while (-not $script:quit)}

# Initialize and launch.
login}

function paschwordshelpdialogue {#---------------------------------------------HELP SCREENS-----------------------------------------

<#
## Overview
❓ Usage: paschwords <database.pwdb> <keyfile.key> -noclip -notime

Here are some useful pieces of information to know:

Paschwords is an enterprise grade password manager written entirely in PowerShell with no outside dependancies or libraries. It will work on any computer running Windows 10 with PowerShell 5.1 or higher.

Standard users have permissions to view, search, retrieve update and remove individual entries, toggle clipboard, lock and unlock the session and reset the timer. They can also load a different database and key either via the command line, or within the interface. All other features are only granted to privileged users.

The import function is extremely powerful, accepting non-standard fields and importing them as tags, notes, or both. This should make it capable of importing password databases from a wide variety of other password managers, commercial and otherwise. Title, URL and Password fields are mandatory.

When the clipboard empties, it is first overwritten with junk, in order to reduce memory artifacts. Additionally, when the module switches databases, locks a session or exits, in memory components are securely overwritten several times before being set to null.
## Installation: Required Files
In order to get started, install the following files within your PowerShell modules directory.

This directory should typically look like one of the following:

c:\users\USERNAME\Documents\PowerShell\Modules\Paschwords
c:\users\USERNAME\Documents\Windows PowerShell\Modules\Paschwords

Required files:

Common.dictionary	A well curated list of English words used in password generation.
CheckNTPTime.ps1	An external tool, used to verify that the system time has not been modified.
DevHashes.ps1		A tool to verify that the version of Paschwords being executed is legitimate.
ValidateURLs.ps1	An external tool, used to test a list of URLs for connectivity.
Paschwords.psd1		This file contains the configuration details for Paschwords.
Paschwords.psm1		The main module.
License.txt		MIT License details.
validhashes.sha256	Known valid versions of the module, kept in the privilege directory.
## Installation: Module Import & Roll-Back
On first run, it is recommended to add the line "ipmo paschwords" to your user profile, via the PowerShell command line:

		'`nipmo paschwords' | Add-Content -Path $PROFILE

Rollback:

You can run Paschwords once without any configuration. Afterwards, it will have created dependencies which will prevent it from running properly if you have not created the necessary accounts and configurations. These include the following directories, which are initially created inside the Paschwords module directory, but you will move these during setup:

.privilege
databases
keys
logs

If you need to abandon the setup and restart, simply delete these directories and restart the module.
## Installation: Encrypted Version
If you're going to use the encrypted version of the Paschwords, in order to protect the module from tampering or being reverse engineered, add the paschwords.ps1 script as a function in your profile:

'`nfunction startpaschwords {$powershell = Split-Path $profile; & " $powershell\modules\paschwords\paschwords.ps1"}'| Add-Content -Path $PROFILE

Ensure that you've copied the following 2 files into the Paschwords directory and made a backup of Pascwhords.psm1 somewhere that Standard users cannot gain access to it:

EncryptPaschwordsModule.ps1 
Paschwords.ps1

Then run: "EncryptPaschwordsModule.ps1 paschwords.psm1"

This will prompt you for a password to encrypt the module. Do not lose this. It will need to be entered everytime Paschwords is launched, decrypting the module and executing it exclusively in memory. The script will now ask if you want to delete the Paschwords.psm1 file. Agree. This will ensure that the only copy of the Paschwords module that exists, other than your backup, will be the newly created and entirely unique "paschwords.enc" file that will be initiated by the startpaschwords command you created with the profile function above. You now have a fully encrypted, secure, HMAC, RBAC, enterprise grade password manager at your disposal.
## Installation: First Launch
Once running, press M to switch to the Management menu, which is freely accessible only until proper user accounts have been setup.

Next, press Z to run the "New workspace setup Wi[Z]ard" which will prompt you for a database name and password. "paschwords" is the default. This wizard will create the security key and an empty database, fully encrypted with HMAC verification and GZip compression, as well as an "admin" account to get you started. The default password is also "admin", but this account is set to expire after 30 days. I strongly recommend you replace this account immediately after setup.

Press J to create a Master password and then attach it to this new database.

Next, press F10 to change the configuration settings located in the PSD1 file, where you can configure the final directory locations of files, such as the password databases and keys.

The one critical directory you cannot configure from this menu is the privilege directory. This was a conscious decision made to make it less convenient for standard users to tamper with the installation. You will need to edit the PSD1 file manually to set this location.

If this is being used in a multi-user environment, it is highly recommended to set this to a directory for which standard users have read-only access and all interactions with that directory are logged for audit and security purposes, specifically Windows Event ID 4663 to that directory.
## Installation: PSD1 Configuration
The following settings are configurable for the module:

expirywarning = '365'	Sets the default expires date flag for password entries.
delayseconds = '30'	Sets the timer for the clipboard clearance, if the clipboard is being used.
archiveslimit = '5'	Sets the maximum number of backup files to keep.
backupfrequency = '7'	Sets the number of days to wait between scheduled backups.
logretention = '30'	Sets the number of days to keep log files.
timeoutseconds = '900'	Sets the number of seconds to wait before an active session times out.
timetobootlimit = '60'	Sets the number of minutes to wait after a session locks to exit the main module.

The following two lines set the name of the default password (PWDB) and key files (KEY), which should ideally share the same base filename. The extensions are mandatory:

defaultdatabase = 'paschwords.pwdb'
defaultkey = 'paschwords.key'
## Installation: PSD1 Configuration Continued...
This line sets the name of the default dictionary to be used within the embedded Paschwords password generator:

dictionaryfile = 'common.dictionary'

This line sets the User-Agent to be used for the ValidURLs support script:

useragent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'

The following lines configure the locations of the password databases, keys, log files and privilege directory. If this is not being used for personal use, these should be changed after initial setup to different locations, with access to these directories via Windows Event ID 4663 monitored for at least the privilege directory and preferably the logs directory:

databasedir = 'DefaultPowerShellDirectory\Modules\Paschwords\databases'
keydir = 'DefaultPowerShellDirectory\Modules\Paschwords\keys'
logdir = 'DefaultPowerShellDirectory\Modules\Paschwords\logs'
privilegedir = 'DefaultPowerShellDirectory\Modules\Paschwords\.privilege'
## Paschword Generator: Modes
When a new entry is added to the database, the user is presented with an option to use the built-in paschword generator, providing users with the ability to create paschwords which still meet all typical security requirements. This option features several intelligent mechanisms to build more useful and memorable paschwords by simply selecting a series of options at the design prompt. In hierarchical order, these option are:

• [P]IN: This option supercedes all others and creates a purely numerical paschword, with a minimum character length of 4 and maximum of 16. This conforms to banking standards.

• [H]uman readable: This option uses a plaintext dictionary to extract two or more words at random, in order to generate a paschword. These are then run through an alphanumeric word derivation, commonly known as 'leet' code, wherein certain letters are replaced with similar looking numbers and symbols.

• [D]ictionary words only: While not typically as secure as human readable word derivations, this method is the same as the last, but skips the 'leet' code replacement.

• [A]lphanumeric: This is your most common paschword generator method, which starts with a base of letters and numbers to create a random string of characters. Sure, it's secure, but rarely memorable.
## Paschword Generator: Word Derivations
A few notes about the word derivations:

• All of the options except for PIN will randomize the case of words, so that there should always be a strong mix of upper-case and lower-case letters and they will all include at least 1 number.

• The 2 options that use the dictionary have a minimum character length of 12, while the PIN and Alphanumeric options have a minimum character length of 4.

• The maximum character length of all paschwords is 32, except for PIN, which as previously mentioned is 16.

• The included dictionary used for Human readable and Dictionary paschwords contains 4720 common English words with a minimum length of 4 letters and a maximum of 10. This list was pulled from Google's most common words list and modified to remove suffixes and most proper nouns. So, you would find words like encrypt, but not encrypted or encrypts. This was done in order to make the word list as compact and diverse as possible.

• The included dictionary may be replaced with any plaintext dictionary, if so desired. It is after all, just a base for pseudo-random paschword generation, while attempting to make the words easier for humans to decipher and remember.
## Paschword Generator: Modifiers
Next up are the paschword derivations, of which there are 3:

• [X] Spaces may be included, but will never appear as the first or last letter of a paschword. In the Human readable and Dictionary options, the spaces, if they appear, will always be located between words, in order to make them more useful for generating those memorable paschwords.

• [S]pecial includes the following characters: ~!@#$%^&*_-+=.,;:.

• [Z]uper special characters will also includes brackets: (){}[].

If the Special or Zuper special character options are chosen, a minimum of 1 character is guaranteed to exist in the paschword. This does not mean that there will be 1 Special and 1 Zuper special character, just that there will be 1 that belongs to either of those two groups, if requested.

Length:

The final element determines the paschword length, with a previously stated range of 4-16, 12-32 or 4-32 characters, depending on the options chosen.

• [#]4-32 characters in length.
## Paschword Generator: Examples
What does this look like in practice?

P12: Would generate a 12 character PIN consisting entirely of numbers.

AS32: This would generate an Alphanumeric paschword, with special characters and a length of 32 characters. This is complex and random, but not very memorable.

DXS12: This is the default paschword generation model, which will be used if no characters are typed at the design prompt. It will create a 12 character paschword based on Dictionary words, include standard Special characters and may contains Spaces. This makes for very memorable paschwords, but is still random enough to make it difficult for standard decipering tools like brute force or rainbow tables from being able to decipher them.

Now, you have the tool at your disposal, you can use it to mix and match as you see fit. What do you need? DS12, HXS14 AS8? You decide. The paschword generator will create one for you based on the provided critera and ask you if you're satisfied with the result before accepting it. It's fast and easy.
## Menu Options: Shared
• 🔑 Paschwords version and lock status.
• 🔒 Remaining time before inactivity lockout, or the session is locked icon.

• 📑 Currently loaded database and lock (🔒/🔓) status.
• 🗝️ Currently loaded key name and lock (🔒/🔓) status.
• ⏱️ [T]imer reset for adjusting session lockout time.

• 📑 Select a different password [D]atabase from those available in the databases directory.
• 🗝️ Select a different password encryption [K]ey from those available in the key directory.

• 🛠️ [M]anagement Menu or 🏠 Main Menu switch. Management is only available to privileged users.

• 🔓 [L]ock or [U]nlock the current session.
• ❓ [F1] or [H]elp, provides access to this menu.
• ⏏️ [ESC] or [Q]uit to exit, clearing memory artifacts as it does.

• 🔐 Active key in use identifies if the standard Database key or a Master key is currently loaded.
• 🪪 User logged in, both entries on this line will display in red if Master privileges are active.

• 🗨️ Message and ⚠  Warning centers regarding the status of the last executed commands.
## Menu Options: Main Menu
• 🔓 [R]etrieve an entry from the currently loaded database.
• 📋 [Z] Toggle clipboard status for automatically copying retrieved passwords.
• ➕ [A]dd a new entry. This grants access to the integrated Paschwords generator.
• ✏️ [C]hange an existing entry. This also grants access to the Paschwords generator.
• ❌ [X]Remove an entry.

• 🧐 [B]rowse all entries: #, with an entry count.
• ⌛ [E]xpired entries view: #, with an entry count.
• 🔍 [S]earch entries using Regex or plaintext keyword search, comma separated.
• 🖥  [N]etwork IPs displays entries that feature IPs in the URL field.
• 🌐 [V]alid URLs displays all entries that were saved with a URL following standard format.
• 👎 [I]nvalid URLs displays entries that have non-standard URL fields, ie: "n/a".
## Menu Options: Entry Browser
Navigation keys: 

• [F]irst page, also enabled is the [Home] key.
• [P]revious page, also enabled are the [Backspace], [PgUp], [up] and [left] keys.
• [N]ext page, also enabled are [Enter], [PgDn], [down] and [right] keys.
• [L]ast page, also enabled is the [End] key.

Sort fields in ascending or descending order:

• 📜[T]itle, sorts by Title.
• 🆔[U]ser, sorts by User.
• 🔗[W]eb URL, sorts by URL.
• 🏷 Ta[G]s, sorts by the first Tag.

Available only to privileged users:

• [X]port the current search criteria to a "searchresults.csv" file in the database directory. The Valid URLs search however, will export to a "validurls.txt" file in the database directory, at which point the user has an option to run the supplementary "ValidateURLs" script.

• [ESC] or [Q]uit will return to the main menu.
## Menu Options: ValidateURLs.ps1 Supplementary Script
The ValidateURLs.ps1 script uses various methods to attempt connection to each URL listed in the file passed to it. It then generates two files based on the results, "validatedurls.txt" and "expiredurls.txt". 

While this script was designed specifically for use with Paschwords, it is independant, in order to maintain the offline security of the database manager. As such, it can also be used entirely separate from this module, as well.

It accepts 3 arguments; the input filename, a "-safe" switch to slow processing down, in order to prevent the current system from getting blocked for suspcious activity, due to the speed of processing, and a "user-agent" for the same purpose. A user-agent should always be used, rather than the standard PowerShell user-agent, lest the current computer get blocked for rapid fire URL testing. This is the reason the PSD1 file for Paschwords has a user-agent pre-configured.
## Menu Options: Function Keys
Standard Users:

• [F9] View current configuration settings.

Privileged Users:

• [F4] Disable logging. Logging will be reenabled when any key is reloaded/unlocked.
• [F10] Modify PSD1 configuration file.
• [F12] Sort by Name and then Tag and resave the database.
## Menu Options: Management Menu
• 📄 Create a [N]ew password database. One key or Master key can unlock one or multiple databases.
• ✅ [S]anitize a PWDB file, correcting IV collisions ensures database security and file health.

• 📥 [I]mport a CSV plaintext password database.
• 📤 [E]xport database to CSV, choosing the fields and order, with password encryption intact.
• 📂 [F]ull database export with unencrypted passwords, requires the Master Password to execute.

• 🧬 [P]assword change for database access key.
• 🔗 [J]oin the database to a Master key: #, creates the Master password for elevated privileges.
• 👑 [W]rite a new Master password, to change the Master password.
• 🛡️ [G]rant Master key privileges, useful primarily for audit purposes.

• 📦←︎ [B]ackup current database, key and privilege directory.
• 📦→︎ [R]estore a backup of the database and key, but privilege backups must be completed manually.

• 🔍 [V]iew the user registry.
• ➕ [A]dd a user, either standard or privileged.
• ✏️ [C]hange user details, including password, role, expiration date and active/inactive status.
• ❌ [X]Remove a user.

• Z. 🧙‍♂️ New workspace setup Wi[Z]ard, to create a new key, database & user registry combination.
## Technical Details: Password handling
• Database passwords are secured via PBKDF2-based key derivation, salted and hashed with SHA-256, but are never stored.

• Master passwords are secured similarly using PBKDF2 with salt and SHA-256 hashing, and validated via a separate authentication mechanism.

• User registry passwords are processed using PBKDF2, then salted, hashed, and Base64 encoded. These passwords differ fundamentally from database passwords because they are never decrypted, reflecting a one-way authentication model.

• Each password entry within a database, each password database at the file level, and the user registry at the file level are all encrypted with AES-256-CBC using unique, random IVs after which, HMAC validation is appended in order to ensure integrity and detect tampering.

• After database passwords are individually AES-encrypted, they are then Base64-encoded, before per-entry HMAC is appended.
## Technical Details: File handling
• The database is serialized to JSON, compressed with GZIP, then encrypted at rest, at which point the file-level HMAC is appended.

• The user registry is serialized to JSON, then encrypted at rest and features file-level HMAC.

• Since the user registry always remains small, per entry HMAC and file level GZip compression would provide no appreciable security or size benefits, which is why it differs in implementation from the database and entries stored therein.

• This layered approach ensures robust security through strong KDFs, encryption, integrity verification, compression, and encoding.
## Technical Details: Additional Security Features
• Designed with zero-trust principles; keys, secrets, and databases are securely wiped multiple times using diverse methods after critical operations.

• Role-Based Access Control (RBAC) enforces two-factor authentication and three privilege levels.

• Brute-force protection mechanisms safeguard both the master password and individual user accounts.

• External NTP time synchronization and hash verification enable trusted source execution.

• Comprehensive, timestamped activity logs record both standard and administrative user actions.
## License
MIT License

Copyright (c) 2025 Schvenn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
##>}
