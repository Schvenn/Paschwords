function paschwords ($database = $script:database, $keyfile = $script:keyfile, [switch]$noclip) {# Password Manager.

function initialize {# Load the user configuration.
$script:database = $database; $script:keyfile = $keyfile; $script:powershell = Split-Path $profile; $basemodulepath = Join-Path $script:powershell "Modules\Paschwords"; $script:configpath = Join-Path $basemodulepath "Paschwords.psd1"
if (!(Test-Path $script:configpath)) {throw "Config file not found at $script:configpath"}

$config = Import-PowerShellDataFile -Path $configpath
$script:keydir = $config.PrivateData.keydir; $script:defaultkey = $config.PrivateData.defaultkey; $script:keydir = $script:keydir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $script:defaultkey = Join-Path $script:keydir $script:defaultkey
$script:databasedir = $config.PrivateData.databasedir; $script:defaultdatabase = $config.PrivateData.defaultdatabase; $script:databasedir = $script:databasedir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $script:defaultdatabase = Join-Path $script:databasedir $script:defaultdatabase
$script:delayseconds = $config.PrivateData.delayseconds
$script:timeoutseconds = $config.PrivateData.timeoutseconds; if ([int]$script:timeoutseconds -gt 5940) {$script:timeoutseconds = 5940}
$script:timetobootlimit = $config.PrivateData.timetobootlimit#; if ([int]$script:timetobootlimit -gt 120) {$script:timetobootlimit = 120}
$script:expirywarning = $config.PrivateData.expirywarning; if ([int]$script:expirywarning -gt 365) {$script:expirywarning = 365}
$script:logretention = $config.PrivateData.logretention; if ([int]$script:logretention -lt 30) {$script:logretention = 30}
$script:dictionaryfile = $config.PrivateData.dictionaryfile; $script:dictionaryfile = Join-Path $basemodulepath $script:dictionaryfile
$script:message = $null; $script:warning = $null; neuralizer; $script:sessionstart = Get-Date; $script:lastrefresh = 1000; $script:management = $false; $script:quit = $false; $script:timetoboot = $null; $script:noclip = $noclip}

function setdefaults {# Set Key and Database defaults.
# Check database validity.
if (-not $script:database -or -not (Test-Path $script:database -ErrorAction SilentlyContinue)) {$script:database = $script:defaultdatabase}
if ($script:database) {if (-not [System.IO.Path]::IsPathRooted($script:database)) {$script:database = Join-Path $script:databasedir $script:database}}

# Check key validity, but allow the menu to load, even if there is no default key.
$script:keyexists = $true
if (-not $script:keyfile -or -not (Test-Path $script:keyfile -ErrorAction SilentlyContinue)) {$script:keyfile = $script:defaultkey}
if ($script:keyfile -and -not [System.IO.Path]::IsPathRooted($script:keyfile)) {$script:keyfile = Join-Path $script:keydir $script:keyfile}
if (-not (Test-Path $script:keyfile -ErrorAction SilentlyContinue) -and -not (Test-Path $script:defaultkey -ErrorAction SilentlyContinue)) {$script:keyexists = $false; $script:keyfile = $null; $script:database = $null}}

function clearclipboard ($delayseconds = 30) {# Fill the clipboard with junk and then clear it after a delay.
Start-Job -ScriptBlock {param($delay, $length); Start-Sleep -Seconds $delay; $junk = -join ((33..126) | Get-Random -Count $length | ForEach-Object {[char]$_}); Set-Clipboard -Value $junk; Start-Sleep -Milliseconds 500; Set-Clipboard -Value $null} -ArgumentList $delayseconds, 64 | Out-Null}

function nowarning {# Set global warning field to null.
$script:warning = $null}

function nomessage {# Set global message field to null.
$script:message = $null}

function wordwrap ($field, [int]$maximumlinelength = 65) {# Modify fields sent to it with proper word wrapping.
if ($null -eq $field -or $field.length -eq 0) {return $null}
$breakchars = ',.;?!\/ '; $wrapped = @()

foreach ($line in $field -split "`n") {$remaining = $line.Trim()
while ($remaining.Length -gt $maximumlinelength) {$segment = $remaining.Substring(0, $maximumlinelength); $breakIndex = -1

foreach ($char in $breakchars.ToCharArray()) {$index = $segment.LastIndexOf($char)
if ($index -gt $breakIndex) {$breakChar = $char; $breakIndex = $index}}
if ($breakIndex -lt 0) {$breakIndex = $maximumlinelength - 1; $breakChar = ''}
$chunk = $segment.Substring(0, $breakIndex + 1).TrimEnd(); $wrapped += $chunk; $remaining = $remaining.Substring($breakIndex + 1).TrimStart()}

if ($remaining) {$wrapped += $remaining} elseif ($line -eq '') {$wrapped += ''}}
return ($wrapped -join "`n")}

function indent ($field, $colour = 'white', [int]$indent = 2) {# Set a default indent for a field.
if ($field.length -eq 0) {return}
$prefix = (' ' * $indent)
foreach ($line in $field -split "`n") {Write-Host -f $colour "$prefix$line"}}

function helptext {# Detailed help.

function scripthelp ($section) {# (Internal) Generate the help sections from the comments section of the script.
""; Write-Host -f yellow ("-" * 100); $pattern = "(?ims)^## ($section.*?)(##|\z)"; $match = [regex]::Match($scripthelp, $pattern); $lines = $match.Groups[1].Value.TrimEnd() -split "`r?`n", 2; Write-Host $lines[0] -f yellow; Write-Host -f yellow ("-" * 100)
if ($lines.Count -gt 1) {$lines[1] | Out-String | Out-Host -Paging}; Write-Host -f yellow ("-" * 100)}

$scripthelp = Get-Content -Raw -Path $PSCommandPath; $sections = [regex]::Matches($scripthelp, "(?im)^## (.+?)(?=\r?\n)")
if ($sections.Count -eq 1) {cls; Write-Host "$([System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)) Help:" -f cyan; scripthelp $sections[0].Groups[1].Value; ""; return}
$selection = $null

do {cls; Write-Host "$([System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)) Help Sections:`n" -f cyan; for ($i = 0; $i -lt $sections.Count; $i++) {"{0}: {1}" -f ($i + 1), $sections[$i].Groups[1].Value}
if ($selection) {scripthelp $sections[$selection - 1].Groups[1].Value}
$input = Read-Host "`nEnter a section number to view"
if ($input -match '^\d+$') {$index = [int]$input
if ($index -ge 1 -and $index -le $sections.Count) {$selection = $index}
else {$selection = $null}} else {""; return}}
while ($true); return}

#---------------------------------------------SECURE FILE MANAGEMENT FUNCTIONS---------------------

function decryptkey ($keyfile = $script:keyfile) {# Decrypt a keyfile and start session.
nomessage; nowarning
if (-not (Test-Path $keyfile -ErrorAction SilentlyContinue)) {$script:warning = "Encrypted key file not found."; nomessage; return}
$raw = [IO.File]::ReadAllBytes($keyfile); $salt = $raw[0..15]; $iv = $raw[16..31]; $cipher = $raw[32..($raw.Length - 1)]

Write-Host -f green "`n`t🔐 Password: " -n; $secureMaster = Read-Host -AsSecureString; $master = [System.Net.NetworkCredential]::new("", $secureMaster).Password; $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($master, $salt, 10000); $protectKey = $pbkdf2.GetBytes(32)
$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Key = $protectKey; $aes.IV = $iv; $decryptor = $aes.CreateDecryptor()
try {$decrypted = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)

if ([System.Text.Encoding]::UTF8.GetString($decrypted[0..3]) -ne 'SCHV') {$script:warning = "Marker mismatch. Keyfile is invalid or corrupted."; $script:keyfile = $null; $script:database = $null; return}
$script:key = $decrypted[4..($decrypted.Length - 1)]; $script:unlocked = $true; $script:sessionstart = Get-Date; $script:timetoboot = $null}

catch {$script:warning = "Incorrect master password or corrupted key file. Clearing key and database settings."; $script:keyfile = $null; $script:database = $null; nomessage}}

function encryptpassword ($password) {# Encrypt a password using AES-256-CBC with Base64 output
$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Key = $script:key; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; $aes.GenerateIV(); $iv = $aes.IV; $encryptor = $aes.CreateEncryptor(); $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($password); $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length); $combinedBytes = $iv + $cipherBytes; $secure = [Convert]::ToBase64String($combinedBytes); return $secure}

function decryptpassword ($encryptedBase64) {# Decrypt the password fields seperately.
$fullCipher = [Convert]::FromBase64String($encryptedBase64); $aes = [System.Security.Cryptography.Aes]::Create(); $aes.Key = $script:key; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

# Extract IV from first 16 bytes (AES block size)
$iv = $fullCipher[0..15]; $cipherBytes = $fullCipher[16..($fullCipher.Length - 1)]; $aes.IV = $iv

$decryptor = $aes.CreateDecryptor(); $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
return [System.Text.Encoding]::UTF8.GetString($plainBytes)}

function loadjson {# Load and decrypt a database, but not the passwords.
# Error-checking.
if (-not (Test-Path $script:database)) {$script:warning = "Database file not found: $script:database"; nomessage; return}
if (-not (Test-Path $script:keyfile)) {$script:warning = "Keyfile not found: $script:keyfile"; nomessage; return}
if (-not $script:key) {$script:warning = "Key not loaded. You must call decryptkey first."; nomessage; return}

try {$encryptedBytes = [System.IO.File]::ReadAllBytes($script:database); $aes = [System.Security.Cryptography.Aes]::Create(); $aes.Key = $script:key; $aes.IV = $encryptedBytes[0..15]; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

# Decrypt the rest of the bytes (after the IV)
$decryptor = $aes.CreateDecryptor(); $cipherBytes = $encryptedBytes[16..($encryptedBytes.Length - 1)]; $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)

# Decompress the decrypted bytes via GzipStream properly
$ms = [System.IO.MemoryStream]::new($decryptedBytes); $gzip = [System.IO.Compression.GzipStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress); $reader = [System.IO.StreamReader]::new($gzip); $jsonText = $reader.ReadToEnd(); $reader.Close()

# Convert JSON text to object and store globally
$script:jsondatabase = $jsonText | ConvertFrom-Json; $script:message = "Database loaded."; nowarning; return}
catch {$script:warning = "Failed to load database: $_"; nomessage; return}}

function savetodisk {# Save to disk (Serialized JSON → GZip compression → Prepend AES IV → AES-256-CBC encryption → Base64 encoded).
# Clean-up.
$password = $null; $passwordplain = $null

try {$jsonText = $script:jsondatabase | ConvertTo-Json -Depth 5 -Compress; $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonText)

$ms = [System.IO.MemoryStream]::new(); $gzip = [System.IO.Compression.GzipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress); $gzip.Write($jsonBytes, 0, $jsonBytes.Length); $gzip.Close(); $compressedBytes = $ms.ToArray()

$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Key = $script:key; $aes.GenerateIV(); $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; $encryptor = $aes.CreateEncryptor(); $cipherBytes = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length); $finalBytes = $aes.IV + $cipherBytes

[System.IO.File]::WriteAllBytes($script:database, $finalBytes)}
catch {$script:warning = "❌ Failed to save updated database: $_"; nomessage}
$script:message = "✅ Updated database saved successfully to disk."; nowarning}

function neuralizer {# Wipe key and database from memory.
$script:unlocked = $false; $choice = $null; $script:timetoboot = Get-Date; $keypasscount = Get-Random -Minimum 3 -Maximum 50; $databasepasscount = Get-Random -Minimum 3 -Maximum 10
if ($script:noclip -eq $false) {clearclipboard 0 64}

function wipe ([byte[]]$buffer) {$originalLength = $buffer.Length
for ($i = 0; $i -lt $keypasscount; $i++) {$multiplier = Get-Random -Minimum 1.1 -Maximum 3.9; $roundingMethod = Get-Random -InputObject 'Floor','Ceiling','Round'; $targetLength = [Math]::$roundingMethod($originalLength * $multiplier); $junk = New-Object byte[] $targetLength; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($junk); [Array]::Copy($junk, 0, $buffer, 0, $originalLength)}; $buffer = $null}

function corruptdatabase {if (-not ($script:jsondatabase -and $script:jsondatabase.Count -gt 0)) {return}
for ($i = 0; $i -lt $databasepasscount; $i++) {foreach ($entry in $script:jsondatabase) {foreach ($property in $entry.PSObject.Properties) {$original = "$($property.Value)"
if ([string]::IsNullOrEmpty($original)) {continue}
$originalLength = $original.Length; $multiplier = Get-Random -Minimum 1.1 -Maximum 3.9; $roundingMethod = Get-Random -InputObject 'Floor','Ceiling','Round'; $targetLength = [Math]::$roundingMethod($originalLength * $multiplier); $junkBytes = New-Object byte[] $targetLength; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($junkBytes); $trimmed = $junkBytes[0..($originalLength - 1)]; $asciiJunk = ($trimmed | ForEach-Object {[char](($_ % 94) + 33)}) -join ''; $property.Value = $asciiJunk}}}; $script:jsondatabase = $null}

function scramble ([string]$reference) {if ([string]::IsNullOrEmpty($reference)) {return}
$length = $reference.Length
for ($i = 0; $i -lt $passCount; $i++) {$multiplier = Get-Random -Minimum 1.1 -Maximum 3.9; $roundingMethod = Get-Random -InputObject 'Floor','Ceiling','Round'; $targetLength = [Math]::$roundingMethod($length * $multiplier)
$junk = -join ((33..126) | Get-Random -Count $targetLength | ForEach-Object {[char]$_})
$script:temp = $junk
$reference = $junk}
$reference = $null}

# Overwrite byte and secure string variables
if ($script:key -ne $null -and $script:key.Length -gt 0) {wipe $script:key}
if ($secure -ne $null -and $secure.length -gt 0) {wipe $secure}
corruptdatabase; scramble $password; scramble $passwordplain
if ($script:quit -eq $true) {scramble $script:message; scramble $script:warning}}

function showentries ($entries, $pagesize = 30, [switch]$expired, [switch]$search, $keywords) {# Browse entire database.
$sortField = $null; $descending = $false

# Apply expired filter (if switch is set)
if ($expired) {$cutoffDate = (Get-Date).AddDays(-$script:expirywarning)
$entries = $entries | Where-Object {[datetime]$_.Timestamp -lt $cutoffDate}}

# Apply search filter (if switch is set)
if ($search) {$pattern = "(?i)(" + ($keywords -replace "\s*,\s*", "|") + ")"; $filtered = @()
foreach ($entry in $entries) {$joined = ($entry.PSObject.Properties | ForEach-Object {$_.Value}) -join "`n"
if ($joined -match $pattern) {$filtered += $entry}}
$entries = $filtered}

# Bail out if no entries
$total = $entries.Count
if ($total -eq 0) {$script:warning = "No entries to view."; nomessage; rendermenu; return}
if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) {$entries = @($entries)}

$page = 0
while ($true) {cls; if ($sortField) {$entries = if ($descending) {$entries | Sort-Object $sortField -Descending} else {$entries | Sort-Object $sortField}}
$start = $page * $pagesize; $end = [math]::Min($start + $pagesize - 1, $total - 1); $chunk = $entries[$start..$end]

# Show expired entries header if filtered by expired
if ($expired) {$warningDate = (Get-Date).AddDays(-$script:expirywarning).ToShortDateString(); Write-Host -f White "Expired Entries: " -n; Write-Host -f Gray "The following entries are more than $script:expirywarning days ($warningDate) old since last update."; Write-Host -f Yellow ("-" * 130)}

# Display the entries in a formatted table
$chunk | Select-Object `
@{Name='Title'; Expression = {$_.Title}}, `
@{Name='Username'; Expression = {$_.Username}}, `
@{Name='URL'; Expression = {if ($_.URL.Length -gt 40) {$_.URL.Substring(0,37) + '...'} else {$_.URL}}}, `
@{Name='Tags'; Expression = {if ($_.Tags.Length -gt 35) {$_.Tags.Substring(0,32) + '...'} else {$_.Tags}}}, `
@{Name='Created'; Expression = {Get-Date $_.Created -Format 'yyyy-MM-dd'}}, `
@{Name='Expires'; Expression = {Get-Date $_.Expires -Format 'yyyy-MM-dd'}} | Format-Table -AutoSize

# Sorting arrow indicator
$arrow = if ($descending) {"▾"} else {if (-not $sortField) {""} else {"▴"}}

# Footer UI with paging and sorting controls
Write-Host -f Yellow ("-" * 130)
Write-Host -f Cyan ("📑 Page $($page + 1)/$([math]::Ceiling($total / $pagesize))".PadRight(16)) -n
Write-Host -f Yellow "| ⏮️(F)irst (P)revious (N)ext (L)ast⏭️ |" -n
Write-Host -f Green " Sort by: 📜(T)itle 🆔(U)ser 🔗(W)eb URL 🏷 Ta[G]s" -n
Write-Host -f Yellow "| " -n
Write-Host -f Green "$arrow $sortField".PadRight(10) -n
Write-Host -f Yellow " | " -n
Write-Host -f Cyan "↩️[ESC] "

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
default {}}}}

function retrieveentry ($database = $script:jsondatabase, $keyfile = $script:keyfile, $searchterm, $noclip) {

# Validate minimum search length
if (-not $searchterm -or $searchterm.Length -lt 3) {$script:warning = "Requested match is too small. Aborting search."; nomessage; return}

# Ensure key is loaded (use cached if unlocked)
if ($script:unlocked -eq $true) {$key = $script:realKey}
else {$key = decryptkey $keyfile; nomessage; nowarning
if (-not $key) {$script:warning = "🔑 No key loaded. " + $script:warning; return}}

# Case-insensitive match on Title, URL, Tags, or Notes
$entrymatches = @()
foreach ($entry in $script:jsondatabase) {if ($entry.Title -match $searchterm -or $entry.Username -match $searchterm -or $entry.URL -match $searchterm -or $entry.Tags -match $searchterm -or $entry.Notes -match $searchterm) {$entrymatches += $entry}}
$total = $entrymatches.Count

# Handle no matches or too many matches
if ($total -eq 0) {$script:warning = "🔐 No entry found matching '$searchterm'"; nomessage; return}
elseif ($total -gt 15) {$script:warning = "Too many matches ($total). Please enter a more specific search."; nomessage; return}

# If exactly one match, select it directly
if ($total -eq 1) {$selected = $entrymatches[0]}

# Between 2 and 15 matches, display menu for user selection
else {$invalidentry = "`n"
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $total; $i++) {$m = $entrymatches[$i]
$notesAbbrev = if ($m.Notes.Length -gt 40) {$m.Notes.Substring(0, 37) + "..."} else {$m.Notes}
$notesAbbrev = $notesAbbrev -replace "\r?\n", ""
$urlAbbrev = if ($m.URL.Length -gt 45) {$m.URL.Substring(0, 42) + "..."} else {$m.URL}
$tagsAbbrev = if ($m.Tags.Length -gt 42) {$m.Tags.Substring(0, 39) + "..."} else {$m.Tags}
Write-Host -f Cyan ("{0}. " -f ($i + 1)).PadRight(4) -n; Write-Host -f Yellow "📜 Title: " -n; Write-Host -f White ($m.Title).PadRight(38) -n; Write-Host -f Yellow " 🆔 User: " -n; Write-Host -f White ($m.Username).PadRight(30) -n; Write-Host -f Yellow " 🔗 URL: " -n; Write-Host -f White $urlAbbrev.PadRight(46) -n; Write-Host -f Yellow "🏷️ Tags:  " -n; Write-Host -f White $tagsAbbrev.PadRight(42) -n; Write-Host -f Yellow " 📝 Notes: " -n; Write-Host -f White $notesAbbrev; Write-Host -f Gray ("-" * 100)}; Write-Host -f Red $invalidentry; Write-Host -f Yellow "🔍 Select an entry to view or Enter to cancel: " -n; $choice = Read-Host
if ($choice -eq "") {$script:warning = "Password retrieval cancelled by user."; nomessage; return}

$parsedChoice = 0; $refParsedChoice = [ref]$parsedChoice
if ([int]::TryParse($choice, $refParsedChoice) -and $refParsedChoice.Value -ge 1 -and $refParsedChoice.Value -le $total) {$selected = $entrymatches[$refParsedChoice.Value - 1]; break}
else {$invalidentry = "`nInvalid entry. Try again."}}
while ($true)}

# Decrypt password field safely
$plain = "🚫 <no password saved> 🚫"
if ($selected.Password -and $selected.Password -ne "") {try {$plain = decryptpassword $selected.Password}
catch {$plain = "⚠️ <unable to decrypt password> ⚠️"}}

# Copy to clipboard unless -noclip switch is set
if (-not $noclip.IsPresent) {try {$plain | Set-Clipboard; clearclipboard} 
catch {}}

# Compose formatted output message
$script:message = "`n🗓️ Created:  $($selected.Created)`n⌛ Expires:  $($selected.Expires)`n📜 Title:    $($selected.Title)`n🆔 UserName: $($selected.Username)`n🔐 Password: $plain`n🔗 URL:      $($selected.URL)`n🏷️ Tags:     $($selected.Tags)`n------------------------------------`n📝 Notes:`n`n$($selected.Notes)"; nowarning; rendermenu}

function export ($path, $fields) {# Export current in-memory database content to CSV
if (-not $script:jsondatabase) {$script:warning = "No database content is currently loaded."; nomessage; rendermenu; return}

$validfields = 'Title','Username','Password','URL','Tags','Notes','Created','Expires'
$fieldList = $fields -split ',' | ForEach-Object {$_.Trim()}
$invalidfields = $fieldList | Where-Object {$_ -notin $validfields}
if ($invalidfields) {$script:warning = "Invalid field(s): $($invalidfields -join ', ')"; $script:message = "Allowed fields: $($validfields -join ', ')"; return}

# $script:jsondatabase is assumed to be an array of objects (already parsed JSON)
$filtered = $script:jsondatabase | ForEach-Object {$obj = [ordered]@{}
foreach ($field in $fieldList) {$value = $_.$field
switch -Regex ($field) {'^Title$' {$obj['Title'] = $value; continue}
'^Username$' {$obj['Username'] = $value; continue}
'^Password$' {$obj['Password (AES-256-CBC)'] = $value; continue}
'^URL$' {$obj['URL'] = $value; continue}
'^Tags$' {$obj['Tags'] = $value; continue}
'^Notes$' {$obj['Notes'] = $value; continue}
'^Created$' {$obj['Created'] = $value; continue}
'^Expires$' {$obj['Expires'] = $value; continue}
default {$obj[$field] = $value}}}
[pscustomobject]$obj}

if (-not $filtered) {$script:warning = "No valid entries found in the in-memory database."; nomessage; return}

$filtered | Export-Csv -Path $path -NoTypeInformation -Force
if ($path -match '(?i)((\\[^\\]+){2}\\\w+\.csv)') {$shortname = $matches[1]} else {$shortname = $path}
$script:message = "Exported JSON database to: $shortname"; nowarning; rendermenu}

function newentry ($database = $script:database, $keyfile = $script:keyfile) {# Create a new entry.
$answer = $null; $confirmDup = $null

# Prompt for fields.
Write-Host -f yellow "`n`n📜 Enter Title: " -n; $title = Read-Host
if (-not $title) {$script:warning = "Every entry must have a Title, as well as a Username and URL. Aborted."; nomessage; rendermenu; return}
Write-Host -f yellow "🆔 Username: " -n; $username = Read-Host
if (-not $username) {$script:warning = "Every entry must have a Username, as well as a Title and URL. Aborted."; nomessage; rendermenu; return}

# Paschword generator.
Write-Host -f yellow "`nDo you want to use the Paschword generator? (Y/N) " -n; $generator = Read-Host
if ($generator -match '^[Yy]') {$password = paschwordgenerator; Write-Host -f yellow "Accept password? (Y/N) " -n; $accept = Read-Host
if ($accept -match '^[Nn]') {do {$password = paschwordgenerator -regenerate; Write-Host -f yellow "Accept password? (Y/N) " -n; $accept = Read-Host} while ($accept -match '^[Nn]')}; ""}
else {Write-Host -f yellow "🔐 Password: " -n; $password = Read-Host -AsSecureString; ""}

Write-Host -f yellow "🔗 URL: " -n; $url = Read-Host
if (-not $url) {$script:warning = "Every entry must have a URL, as well as a Title and Username. Aborted."; nomessage; rendermenu; return}
Write-Host -f yellow "⏳ How many days before this password should expire? (Default = 365): " -n; $expireInput = Read-Host; $expireDays = 365
if ([int]::TryParse($expireInput, [ref]$null)) {$expireDays = [int]$expireInput
if ($expireDays -le 0) {$expireDays = 365}}
$expires = (Get-Date).AddDays($expireDays).ToString("yyyy-MM-dd")
Write-Host -f yellow "🏷️ Tags: " -n; $tags = Read-Host; $tags = ($tags -split ',') | ForEach-Object {$_.Trim()} | Where-Object {$_} | Join-String -Separator ', '
Write-Host -f yellow "📝 Notes (Enter, then CTRL-Z + Enter to end): " -n; $notes = [Console]::In.ReadToEnd()

# Decrypt key if needed
if ($script:unlocked -eq $false) {decryptkey $script:keyfile}

# Convert SecureString to plain and then encrypt
if ($password -is [SecureString]) {try {$passwordPlain = [System.Net.NetworkCredential]::new("", $password).Password} catch {$passwordPlain = ""}}
else {$passwordPlain = $password; write-host $passwordplain}
if ([string]::IsNullOrWhiteSpace($passwordPlain)) {$passwordPlain = ""}; $secure = encryptpassword $passwordPlain

# Initialize or load in-memory database object.
if (-not $script:jsondatabase) {$script:jsondatabase = @()}

# Check for existing entry by Username and URL.
$existing = $script:jsondatabase | Where-Object {$_.Username -eq $username -and $_.URL -eq $url}

if ($existing) {Write-Host -f yellow "`n🔁 An entry already exists for '$username' at '$url'."; Write-Host -f yellow "`nDuplicate it? (Y/N) " -n; $answer = Read-Host

if ($answer -notmatch '^[Yy]') {Write-Host -f yellow "`nPlease update the entry:`n"; Write-Host -f yellow "📜 Enter Title ($($existing.Title)): " -n; $titleNew = Read-Host
if ([string]::IsNullOrEmpty($titleNew)) {$titleNew = $existing.Title} else {$title = $titleNew}
Write-Host -f yellow "🆔 Username ($($existing.Username)): " -n; $usernameNew = Read-Host
if ([string]::IsNullOrEmpty($usernameNew)) {$usernameNew = $existing.Username} else {$username = $usernameNew}
Write-Host -f green "🔐 Do you want to keep the original password or use the new one you just entered? (new/old) " -n; $keep = Read-Host
if ($keep -match "^(?i)old$") {$secure = $existing.Password}
elseif ($keep -match "^(?i)new$") {}
else {$script:warning = "Invalid choice. Aborting."; nomessage; rendermenu; return}
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
$entry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
Title     = $title
Username  = $username
Password  = $secure
URL       = $url
Tags      = $tags
Notes     = $notes
Created   = (Get-Date).ToString("yyyy-MM-dd")
Expires   = $expires}

if (-not $script:jsondatabase) {$script:jsondatabase = @()} 
elseif ($script:jsondatabase -isnot [System.Collections.IEnumerable] -or $script:jsondatabase -is [PSCustomObject]) {$script:jsondatabase = @($script:jsondatabase)}

# Add new entry to in-memory database and then to disk.
$script:jsondatabase += $entry; savetodisk}

function removeentry ($searchterm) {# Remove an entry.

# Error-checking.
if (-not $script:jsondatabase) {$script:warning = "No database loaded."; nomessage; return}
if ($searchterm.Length -lt 3) {$script:warning = "Search term too short. Aborting removal."; nomessage; return}

$matches = $script:jsondatabase | Where-Object {$_.Title -match $searchterm -or $_.Username -match $searchterm -or $_.URL -match $searchterm -or $_.Tags -match $searchterm -or $_.Notes -match $searchterm}
$count = $matches.Count
if ($count -eq 0) {$script:warning = "No entries found matching '$searchterm'."; nomessage; return}
elseif ($count -gt 15) {$script:warning = "Too many matches ($count). Please refine your search."; nomessage; return}

if ($count -eq 1) {$selected = $matches[0]}
else {$invalidentry = "`n"
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $count; $i++) {$m = $matches[$i]
$notesAbbrev = if ($m.Notes.Length -gt 40) {$m.Notes.Substring(0,37) + "..."} else {$m.Notes}
$urlAbbrev = if ($m.URL.Length -gt 45) {$m.URL.Substring(0,42) + "..."} else {$m.URL}
$tagsAbbrev = if ($m.Tags.Length -gt 42) {$m.Tags.Substring(0,39) + "..."} else {$m.Tags}
Write-Host -f Cyan "$($i + 1). ".PadRight(4) -n
Write-Host -f yellow "📜 Title: " -n; Write-Host -f white $($m.Title).PadRight(38) -n
Write-Host -f yellow " 🆔 User: " -n; Write-Host -f white $($m.Username).PadRight(30) -n
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

# Confirm deletion
Write-Host -f cyan "`nYou selected:`n"
Write-Host -f yellow "📜 Title: " -n; Write-Host -f white "$($selected.Title)"
Write-Host -f yellow "🆔 User:  " -n; Write-Host -f white "$($selected.Username)"
Write-Host -f yellow "🔗 URL:   " -n; Write-Host -f white "$($selected.URL)"
Write-Host -f yellow "🏷  Tags:  " -n; Write-Host -f white "$($selected.Tags)"
Write-Host -f yellow "📝 Notes: " -n; Write-Host -f white "$($selected.Notes)"
Write-Host -f cyan "`nType 'YES' to confirm removal: " -n; $confirm = Read-Host
if ($confirm -ne "YES") {$script:warning = "Removal aborted."; nomessage; return}

# Remove entry from in-memory database and save to disk.
$script:jsondatabase = $script:jsondatabase | Where-Object {$_ -ne $selected}; savetodisk}

function newkey ($keyfile) {# Create an AES key, protected with a master password.
if (-not $keyfile) {$script:warning = "No key file identified."; nomessage}

# Generate AES key
$aesKey = New-Object byte[] 32; [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)

# Prepend magic marker "SCHV"
$marker = [System.Text.Encoding]::UTF8.GetBytes("SCHV"); $keyWithMarker = $marker + $aesKey

$keyfile = Join-Path $script:keydir $keyfile
if (Test-Path $keyfile) {$script:warning = "That key file already exists."; nomessage; rendermenu; return}

neuralizer; Write-Host -f yellow "🔐 Enter a master password to protect your key:" -n; $secureMaster = Read-Host -AsSecureString; $master = [System.Net.NetworkCredential]::new("", $secureMaster).Password

# Generate salt and derive key using PBKDF2
$salt = New-Object byte[] 16; [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($salt); $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($master, $salt, 10000); $protectKey = $pbkdf2.GetBytes(32)

# Encrypt keyWithMarker using protectKey
$aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $protectKey; $aes.GenerateIV(); $iv = $aes.IV; $encryptor = $aes.CreateEncryptor(); $encryptedKey = $encryptor.TransformFinalBlock($keyWithMarker, 0, $keyWithMarker.Length)

# Store salt + IV + ciphertext
$output = [byte[]]($salt + $iv + $encryptedKey); [IO.File]::WriteAllBytes("$keyfile", $output); $script:message = "Encrypted AES key created."; $script:keyfile = $keyfile; $script:keyexists = $true; $script:disablelogging = $false; nowarning}

function importcsv ($csvpath) {# Import a CSV file into the database.

# Decrypt the key first.
$key = decryptkey $script:keyfile
if (-not $script:key) {$script:warning = "Key decryption failed. Aborting import."; nomessage; return}

# Ensure the database is initialized. This is needed for new, empty databases.
$script:jsondatabase = @()

# Import CSV file.
$imported = Import-Csv $csvpath; $requiredFields = @('Title', 'Username', 'Password', 'URL'); $optionalFields = @('Tags','Notes','Created','Expires')

# Set expiry expectations.
Write-Host -f yellow "`n⏳ How many days before these entries should expire? (Default = 365): " -n; $expireInput = Read-Host; $expireDays = 365
if ([int]::TryParse($expireInput, [ref]$null)) {$expireDays = [int]$expireInput
if ($expireDays -le 0) {$expireDays = 365}}
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

# Validate non-empty Username and URL
if ([string]::IsNullOrWhiteSpace($username)) {Write-Host -f Cyan "`nUsername is empty for an entry (Title: '$title', URL: '$url'). Enter a Username or press Enter to skip: " -n; $username = Read-Host
if ([string]::IsNullOrWhiteSpace($username)) {Write-Host -f Yellow "Skipping entry due to empty Username."; $skipped++; continue}}

if ([string]::IsNullOrWhiteSpace($url)) {Write-Host -f Cyan "`nURL is empty for an entry (Title: '$title', Username: '$username'). Enter a URL or press Enter to skip: " -n; $url = Read-Host
if ([string]::IsNullOrWhiteSpace($url)) {Write-Host -f Yellow "Skipping entry due to empty URL."; $skipped++; continue}}

# Auto-fill Title from domain if empty
if ([string]::IsNullOrWhiteSpace($title)) {$domain = if ($url -match '(?i)^(https?:\/\/)?(www\.)?(([a-z\d-]+\.)*[a-z\d-]+\.[a-z]{2,10})(\W|$)') {$matches[3].ToLower()} else {""}
if ([string]::IsNullOrWhiteSpace($domain)) {Write-Host -f Cyan "`nTitle is missing and could not auto-extract from URL: $url. Please enter a Title or press Enter to skip: " -n; $title = Read-Host
if ([string]::IsNullOrWhiteSpace($title)) {Write-Host -f Yellow "Skipping entry due to missing Title."; $skipped++; continue}}
else {$title = $domain; Write-Host -f Yellow "Title auto-set to domain: $title"}}

# Append extra fields to Notes if requested
foreach ($field in $extraFields) {if ($entry.PSObject.Properties.Name -contains $field) {$val = $entry.$field
if (-not [string]::IsNullOrWhiteSpace($val) -and $fieldAppendNotes[$field]) {$notes += "`n$field`: $val"}}}

# Add tags for extra fields
foreach ($field in $extraFields) {if ($fieldTagMode[$field] -ne 'none' -and $entry.PSObject.Properties.Name -contains $field) {$val = $entry.$field; $shouldAdd = $false
switch ($fieldTagMode[$field]) {'a' {$shouldAdd = $true}
'p' {$shouldAdd = -not [string]::IsNullOrWhiteSpace($val)}}
if ($shouldAdd) {$existingTags = $tags -split ',\s*' | Where-Object {$_ -ne ''}
if (-not ($existingTags -contains $field)) {$tags = if ([string]::IsNullOrWhiteSpace($tags)) {$field} else {"$tags,$field"}
$tagAddCounts[$field]++}}}}

# Check duplicates by Username and URL
$match = $script:jsondatabase | Where-Object {$_.Username -eq $username -and $_.URL -eq $url}
if ($match) {$duplicates++
Write-Host -f Yellow "`nDuplicate detected for 🆔 '$username' at 🔗 '$url'"
Write-Host -f Cyan "📜 Title: $($match.Title) => $title"
Write-Host -f Cyan "🏷️  Tags: $($match.Tags) => $tags"
Write-Host -f Cyan "📝 Notes: $($match.Notes) => $notes"
Write-Host -f White "`nOptions: (S)kip / (O)verwrite / (K)eep both [default: Keep]: " -n
$choice = Read-Host
switch ($choice.ToUpper()) {"O" {$script:jsondatabase = $script:jsondatabase | Where-Object {$_ -ne $match}
Write-Host -f Red "`nOverwritten."; $overwritten++}
"S" {Write-Host -f Red "`nSkipping entry."; $skipped++; continue}
"K" {Write-Host -f Green "`nKeeping both."}
default {Write-Host -f Green "`nKeeping both."}}}

# Encrypt password using encryptpassword function; allow empty password
if ([string]::IsNullOrWhiteSpace($plainpassword)) {Write-Host -f Yellow "`nEntry for 🆔 '$username' at 🔗 '$url' has no password. Adding with 🚫 empty password."; $plainpassword = ""}
$encryptedPassword = encryptpassword $plainpassword

# Create new entry and add to in-memory database and then save to disk.
$newEntry = [PSCustomObject]@{Title = $title; Username = $username; Password = $encryptedPassword; URL = $url; Tags = $tags; Notes = $notes; Created = (Get-Date).ToString("yyyy-MM-dd"); Expires = $expires}
$script:jsondatabase += $newEntry; $added++}
savetodisk

# Summary output
Write-Host -f Green "`n✅ Import complete.`n"
Write-Host -f Yellow "New entries added:" -n; Write-Host -f White " $added"
Write-Host -f Gray "Duplicates skipped:" -n; Write-Host -f White " $skipped"
Write-Host -f Red "Overwritten entries:" -n; Write-Host -f White " $overwritten"
Write-Host -f Yellow "Total duplicates:" -n; Write-Host -f White " $duplicates"
$tagsAdded = ($tagAddCounts.GetEnumerator() | Where-Object {$_.Value -gt 0})
if ($tagsAdded.Count -gt 0) {Write-Host -f Yellow "Tag types added:" -n; Write-Host -f White " $($tagsAdded.Count)"
Write-Host -f Yellow "Tags added:" -n; Write-Host -f White " $($tagsAdded.Name -join ', ')"}
Write-Host -f Cyan "`n↩️Return" -n; Read-Host}

#---------------------------------------------END SECURE FILE MANAGEMENT FUNCTIONS-----------------

function backup {# Backup currently loaded key and database pair to the database directory.
$script:message = $null; $script:warning = $null; $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script:database); $timestamp = Get-Date -Format "MM-dd-yyyy @ HH_mm_ss"; $zipName = "$baseName ($timestamp).zip"; $zipPath = Join-Path $script:databasedir $zipName

try {$tempDir = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $tempDir | Out-Null
Copy-Item $script:database -Destination $tempDir; Copy-Item $script:keyfile -Destination $tempDir; Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath $zipPath -Force; Remove-Item $tempDir -Recurse -Force; $script:message = "Backup created: $zipName"; nowarning} catch {$script:warning = "Backup failed: $_"; nomessage}; return}

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
if (-not $dbFile -or -not $keyFile) {$script:warning = "Backup is missing required files:`n" + (if (-not $dbFile) { "- Database (.pwdb)`n" } else {""}) + (if (-not $keyFile) { "- Key file (.key)`n" } else {""})
Remove-Item $tempDir -Recurse -Force; return}

$destDb  = Join-Path $script:databasedir $dbFile.Name; $destKey = Join-Path $script:keydir     $keyFile.Name
if (Test-Path $destDb) {Write-Host -f red "`nOverwrite existing database '$($dbFile.Name)'? (Y/N) " -n
if ((Read-Host) -notmatch '[Yy]$') {$script:warning = "Database overwrite declined. Restore aborted."; Remove-Item $tempDir -Recurse -Force; return}}

if (Test-Path $destKey) {Write-Host -f red "Overwrite existing key file '$($keyFile.Name)'? (Y/N) " -n
if ((Read-Host) -notmatch '[Yy]$') {$script:warning = "Key overwrite declined. Restore aborted."; Remove-Item $tempDir -Recurse -Force; return}}

Copy-Item -Path $dbFile.FullName  -Destination $destDb -Force; Copy-Item -Path $keyFile.FullName -Destination $destKey -Force

if ($chosenFile -match '(?i)((\\[^\\]+){2}\\[^\\]+\.ZIP)') {$shortfile = $matches[1]} else {$shortfile = $chosenFile}
$script:message = "Restored '$($dbFile.Name)' and '$($keyFile.Name)' from backup: $shortfile"; nowarning}
catch {$script:warning = "Restore failed:`n$_"; nomessage}
finally {if (Test-Path $tempDir) {Remove-Item $tempDir -Recurse -Force}}}

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
$script:design
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

function emoji {# Display emoji in Choose an Action prompt when there are processing delays.
$script:emoji = $null
if ($choice -eq $null) {$script:emoji = ""}
elseif ($choice -eq 'K') {$script:emoji = "🗝  Select a key"}
elseif ($choice -eq 'C') {$script:emoji = "🔑 Create a key"}
elseif ($choice -eq 'D') {$script:emoji = "📑 Select a database"}
elseif ($choice -eq 'P') {$script:emoji = "📄 Create a database"}
elseif ($choice -eq 'V') {$script:emoji = "✅ Verify a database"}
elseif ($choice -eq 'I') {$script:emoji = "📥 Import from CSV"}
elseif ($choice -eq 'OEMMINUS') {$script:emoji = "📤 Export to CSV"}
elseif ($choice -eq 'SUBTRACT') {$script:emoji = "📤 Export to CSV"}
elseif ($choice -eq 'OEMPERIOD') {$script:emoji = "📦←︎ Backup"}
elseif ($choice -eq 'OEMCOMMA') {$script:emoji = "📦→︎ Restore"}
elseif ($choice.length -gt 1) {$script:emoji = ""}
else {$script:emoji = $choice}
return $script:emoji}

function managementisdisabled {# Restrict access to specific features.
emoji; if (-not $script:management) {$script:warning = "'$script:emoji' is disabled outside of management mode."; nomessage; rendermenu; break}}

function rendermenu {# Title and countdown timer.
$toggle = if ($script:management) {"Hide"} else {"Show"}; $managementcolour = if ($script:management) {"darkgray"} else {"green"}

# Create border elements.
function endcap {Write-Host -f cyan "+" -n; Write-Host -f cyan ("-" * 70) -n; Write-Host -f cyan "+"}
function horizontal {Write-Host -f cyan "|" -n; Write-Host -f cyan ("-" * 70) -n; Write-Host -f cyan "|"}
function startline {Write-Host -f cyan "|" -n}
function linecap {Write-Host -f cyan "|"}

# Title and countdown timer.
cls; ""; endcap
startline; Write-Host -f white "🔑 Secure Paschwords Manager 🔒".padright(53) -n
if ($script:unlocked) {if ($countdown -ge 540) {Write-Host -f green "🔒 in $($script:minutes +1) minutes " -n}
elseif ($countdown -lt 540 -and $countdown -ge 60) {Write-Host -f green " 🔒 in $($script:minutes +1) minutes " -n}
elseif ($countdown -lt 60) {Write-Host -f red -n ("      🔒 in 0:{0:D2} " -f $script:seconds)}
else {Write-Host "`t`t    🔒 "-n}} 
else {Write-Host "`t`t    🔒 "-n}; linecap
horizontal

# Loaded resource display.
if ($script:database) {$displaydatabase = Split-Path -Leaf $script:database -ErrorAction SilentlyContinue} else {$displaydatabase = "none loaded"}
if ($script:keyfile) {$displaykey = Split-Path -Leaf $script:keyfile -ErrorAction SilentlyContinue} else {$displaykey = "none loaded"}
$databasestatus = if ($db -and $key -and $db -ne $key) {"🤔"} elseif ($displaykey -eq "none loaded" -or $displaydatabase -eq "none loaded" -or $script:unlocked -eq $false) {"🔒"} else {"🔓"}
$keystatus = if ($script:unlocked -eq $false -or $displaykey -eq "none loaded") {"🔒"} else {"🔓"}

startline; Write-Host -f white " Current Database: " -n; Write-Host -f green "$displaydatabase $databasestatus".padright(34) -n
Write-Host -f yellow "⏱️ [T]imer reset." -n; linecap
startline; Write-Host -f white " Current Key: " -n; Write-Host -f green "$displaykey $keystatus".padright(35) -n
if ($displaydatabase -eq "none loaded" -or $displaykey -eq "none loaded") {Write-Host -f green "♻️ Rel[O]ad defaults." -n} else {Write-Host (" " * 21) -n};linecap

if ($displaydatabase -match '^(?i)(.+?)\.pwdb$') {$db = $matches[1]}
if ($displaykey -match '^(?i)(.+?)\.key$') {$key = $matches[1]}
if (($displaykey -eq "none loaded" -or $displaydatabase -eq "none loaded") -and ($script:database -or $script:keyfile)) {if ($script:warning -notmatch "Make sure") {if ($script:warning) {$script:warning += "`n"}; $script:warning += "Make sure to load both a database and a keyfile before continuing."}
if ($db -and $key -and $db -ne $key) {startline; Write-Host -f red " Warning: " -n; Write-Host -f yellow "The key and database filenames do not match.".padright(60) -n; linecap
if ($script:warning -notmatch "Continuing") {if ($script:warning) {$script:warning += "`n"}; $script:warning += "Continuing with an incorrect key and database pairing could lead to data corruption. Ensure you have the correct file combination before making any file changes."}}}

# Display menu options.
horizontal
startline; Write-Host -f cyan " A. " -n; Write-Host -f yellow "➕ [A]dd a new entry or update an existing one.".padright(65) -n; linecap
$clipboard = if ($script:noclip -eq $true) {"🚫"} else {"📋"}
startline; Write-Host -f cyan " R. " -n; Write-Host -f white "🔓 [R]etrieve an entry.".padright(50) -n; Write-Host -f cyan "Z. " -n; Write-Host -f white "Clipboard $clipboard " -n; linecap
startline; Write-Host -f cyan " X. " -n; Write-Host -f red "❌ Remove an entry.".padright(41) -n; if($script:disablelogging){Write-Host -f red "Logging is disabled. 🔴 " -n} else {Write-Host -f green "Logging is enabled.  🟢 " -n};linecap
horizontal
startline; Write-Host -f cyan " B. " -n; Write-Host -f white "🧐 [B]rowse all entries: " -n; Write-Host -f cyan "$(($script:jsondatabase).Count)".padright(41) -n; linecap
$now = Get-Date; $expiredcount = ($script:jsondatabase | Where-Object {$_.Expires -and ($_."Expires" -as [datetime]) -le $now}).Count
startline; Write-Host -f cyan " E. " -n; Write-Host -f white "⌛ [E]xpired entries view: " -n; if ($expiredcount -eq 0) {Write-Host -f green "0".padright(39) -n} else {Write-Host -f red "$expiredcount" -n}; linecap
startline; Write-Host -f cyan " S. " -n; Write-Host -f white "🔍 [S]earch entries for specific keywords.".padright(66) -n; linecap
horizontal
startline; Write-Host -f cyan " M. " -n; Write-Host -f white "🛠️ [M]anagement controls: " -n; Write-Host -f $managementcolour $toggle.padright(40) -n; linecap
horizontal
if ($script:management) {startline; Write-Host -f cyan " K. " -n; Write-Host -f white "🗝️ Select a different password encryption [K]ey.".padright(67) -n; linecap
startline; Write-Host -f cyan " C. " -n; Write-Host -f yellow "🔑 [C]reate a new password encryption key.".padright(66) -n; linecap
horizontal
startline; Write-Host -f cyan " D. " -n; Write-Host -f white "📑 Select a different password [D]atabase.".padright(66) -n; linecap
startline; Write-Host -f cyan " P. " -n; Write-Host -f yellow "📄 Create a new [P]assword database.".padright(66) -n; linecap
horizontal
startline;  Write-Host -f cyan " V. " -n; Write-Host -f yellow "✅ [V]alidate a PWDB file.".padright(65) -n; linecap
horizontal
startline; Write-Host -f cyan " I. " -n; Write-Host -f yellow "📥 [I]mport a CSV plaintext password database.".padright(66) -n; linecap
startline; Write-Host -f cyan " -  " -n; Write-Host -f white "📤 Export the current database to CSV. " -n; Write-Host -f red "Encryption remains intact. " -n; linecap
horizontal
startline; Write-Host -f cyan " <  " -n; Write-Host -f white "📦←︎ Backup currently loaded database and key.".padright(67) -n; linecap
startline; Write-Host -f cyan " >  " -n; Write-Host -f white "📦→︎ Restore a backup.".padright(67) -n; linecap
horizontal}

# Session options.
startline; if ($script:unlocked -eq $true) {Write-Host "🔓 " -n} else {Write-Host "🔒 " -n}
if ($script:unlocked -eq $true) {Write-Host -f red "[L]ock Session " -n} else {Write-Host -f darkgray "[L]ock Session " -n}
Write-Host -f white "/ " -n;
if ($script:unlocked -eq $true) {Write-Host -f darkgray "[U]nlock Session".padright(23) -n} else {Write-Host -f green "[U]nlock Session".padright(23) -n}
if (-not (Test-Path $script:keyfile -ErrorAction SilentlyContinue)) {Write-Host -f black -b yellow "❓ [H]elp <-- " -n; Write-Host "".padright(4) -n}
else {Write-Host -f yellow "❓ [H]elp".padright(17) -n}
Write-Host -f gray "⏏️ [ESC] " -n;; linecap
endcap

# Message and warning center.
$script:message = wordwrap $script:message; $script:warning = wordwrap $script:warning
if ($script:message.length -ge 1) {Write-Host "  🗨️" -n; indent $script:message white 2}
if ($script:warning.length -ge 1) {Write-Host "  ⚠️" -n; indent $script:warning red 2}
if ($script:message.length -ge 1 -or $script:warning.length -ge 1 ) {Write-Host -f cyan ("-" * 72)}
$lastcommand = emoji; Write-Host -f white "⚡ Choose an action: " -n}

function logchoices ($choice, $message, $warning){# Log user actions.
# Do not log if the user has turned off logging.
if ($script:disablelogging) {return}

# Redact sensitive lines from message
if ($message) {$logmessage = ($message -replace '🔐 Password:.*', '🔐 Password: [REDACTED]' -replace '🔗 URL: .*', '🔗 URL:      [REDACTED]' -replace '🆔 UserName:.*', '🆔 UserName: [REDACTED]') -split '(?m)^[-]{10,}' | Select-Object -First 1}

# Map keys to descriptions.
$map = @{'A' = 'Add an entry'; 'R' = 'Retrieve an entry'; 'X' = 'Remove an entry'; 'B' = 'Browse entries'; 'E' = 'View expired entries'; 'S' = 'Search entries'; 'L' = 'Lock'; 'U' = 'Unlock'; 'T' = 'Reset timer'; 'O' = 'Restore Default Key & Database'; 'Z' = 'Toggle Clipboard'; 'M' = 'Toggle management view'; 'K' = 'Select a key'; 'C' = 'Create a key'; 'D' = 'Select a database'; 'P' = 'Create a database'; 'V' = 'Verify a PWDB'; 'I' = 'Import a CSV'; 'OEMMINUS' = 'Export to CSV'; 'SUBTRACT' = 'Export to CSV'; 'OEMPERIOD' = 'Backup key and database'; 'OEMCOMMA' = 'Restore a key and database'; 'Q' = 'Quit'; 'H' = 'Help'; 'F1' = 'Help'; 'F4' = 'Toggle logging'; 'BACKSPACE' = 'Clear message center'}

# Create directory, if it doesn't exist.
$script:logdir = Join-Path $PSScriptRoot 'logs'
if (-not (Test-Path $logdir)) {New-Item $logdir -ItemType Directory -Force | Out-Null}

# Cleanup old logs (older than the number of days set in logretention, with the minimum set to 30 days).
Get-ChildItem -Path $logdir -Filter 'log - *.log' | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-[int]$script:logretention)} | Remove-Item -Force

# Create base file each session.
if (-not $script:logfile) {$timestamp = (Get-Date).ToString('MM-dd-yy @ HH_mm_ss'); $script:logfile = Join-Path $logdir "log - $timestamp.log"}

# Map unknown keys.
if (-not $map.ContainsKey($choice)) {Add-Content -Path $script:logfile -Value "$(Get-Date -Format 'HH:mm:ss') - UNRECOGNIZED: $choice"; return}

# Compile entry information.
$timestamp = Get-Date -Format 'HH:mm:ss'; $info = "$(if ($message) {" - MESSAGE: $logmessage"})$(if ($warning) {" - WARNING: $warning"})"; $entry = "$timestamp - $($map[$choice])$info`n" + ("-" * 100)

# Ensure log gets written by retrying 5 times for every log, to avoid race conditions.
$retries = 5
for ($i = 0; $i -lt $retries; $i++) {try {$fs = [System.IO.File]::Open($script:logfile, 'Append', 'Write', 'ReadWrite'); $sw = New-Object System.IO.StreamWriter($fs)
$sw.WriteLine($entry); $sw.Close(); $fs.Close(); break}
catch {Start-Sleep -Milliseconds 100}}}

function login {# Display initial login screen.
$script:sessionstart = Get-Date; $key = $null
Write-Host -f yellow "`n+-------------------------------+`n|🔑 Secure Paschwords Manager 🔒|`n|-------------------------------|" -n
decryptkey $script:keyfile}

function loginfailed {# Login failed.
Write-Host -f yellow "+-------------------------------+`n|" -n; Write-Host -f red " 😲 Access Denied! ABORTING!🔒 " -n; Write-Host -f yellow "|`n+-------------------------------+`n"; return}

function logoff {# Exit screen.
nowarning; nomessage; Write-Host -f red "Securing the environment..."; neuralizer; $choice=$null; rendermenu; Write-Host -f white "`n`t`t    ____________________`n`t`t   |  ________________  |`n`t`t   | |                | |`n`t`t   | |   🔒 "-n; Write-Host -f red "Locked." -n; Write-Host -f white "   | |`n`t`t   | |                | |`n`t`t   | |________________| |`n`t`t   |____________________|`n`t`t    _____|_________|_____`n`t`t   / * * * * * * * * * * \`n`t`t  / * * * * * * * * * * * \`n`t`t ‘-------------------------’`n"; return}

function loggedin {# Once key is unlocked, allow access to the dynamic menu.
$script:sessionstart = Get-Date; $choice = $null
loadjson
rendermenu

# Combine previous day's log files into single date files and remove old log files.
$today = (Get-Date).Date

Get-ChildItem -Path $logdir -Filter 'log - *.log' | Where-Object {$_.Name -match '^log - (\d{2}-\d{2}-\d{2})' -and $_.Name -notmatch 'log - \d{2}-\d{2}-\d{2}\.log$'} | Group-Object {($_.Name -match '^log - (\d{2})-(\d{2})-(\d{2})') | Out-Null
$fileDate = Get-Date "$($matches[1])-$($matches[2])-20$($matches[3])"
if ($fileDate -lt $today) {return $matches[0]} else {return $null}} | Where-Object {$_.Name} | ForEach-Object {$date = $_.Name; $output = Join-Path $logdir "log - $date.log"

$_.Group | Sort-Object LastWriteTime | ForEach-Object {Get-Content $_.FullName | Add-Content -Path $output}
$_.Group | ForEach-Object {Remove-Item $_.FullName -Force}}

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
if ($script:unlocked -eq $true -and $countdown -le 0) {neuralizer; $script:message = "Session timed out. The key has been locked."; rendermenu}

# Refresh display if session is unlocked
if ($script:unlocked -and ($countdown -lt 60 -or $script:minutes -lt $script:lastrefresh)) {rendermenu; $script:lastrefresh = $script:minutes}

# Wait for next loop.
if ($countdown -gt 60) {Start-Sleep -Milliseconds 250}
else {Start-Sleep -Seconds 1}}

# Send key presses to the menu for processing.
if ([Console]::KeyAvailable -and -not $script:quit) {$key = [Console]::ReadKey($true); $choice = $key.Key.ToString().ToUpper()

logchoices $choice $script:message $script:warning
switch ($choice) {
'A' {# Add a new entry.
if ($script:database -and $script:keyfile -and $script:unlocked) {newentry $script:database $script:keyfile; rendermenu}
else {$script:warning = "A database and key must be opened and unlocked to add an entry."; nomessage}
rendermenu}

'R' {# Retrieve an entry.
if (-not $script:keyfile) {$script:warning = "🔑 No key loaded."; nomessage}

if (-not $script:jsondatabase) {$script:warning = "📑 No database loaded. " + $script:warning; nomessage}

if ($script:keyfile -and $script:jsondatabase) {Write-Host -f green "`n`n🔓 Enter Title, 🆔 Username, 🔗 URL, 🏷  Tag or 📝 Note to identify entry: " -n; $searchterm = Read-Host}

if ([string]::IsNullOrWhiteSpace($searchterm)) {$script:warning = "No search term provided."; nomessage}

elseif ($searchterm) {retrieveentry $script:jsondatabase $script:keyfile $searchterm $noclip}
rendermenu}

'X' {# Remove an entry.
Write-Host -f green "`n`n❌ Enter Title, Username, URL, Tag or Note to identify entry: " -n; $searchterm = Read-Host; removeentry $searchterm; rendermenu}

'B' {# Browse all entries from memory.
if (-not $script:jsondatabase -or -not $script:jsondatabase.Count) {$script:warning = "No valid entries loaded in memory to display."; nomessage}
else {showentries $script:jsondatabase; nomessage; nowarning}}

'E' {# Retrieve expired entries.
if (-not $script:jsondatabase -or -not $script:jsondatabase.Count) {$script:warning = "No database loaded."; nomessage; rendermenu}

$expiredEntries = $script:jsondatabase | Where-Object {try {[datetime]::Parse($_.expires) -lt (Get-Date) <#-or [datetime]::Parse($_.created) -lt (Get-Date).AddDays(-$script:expirywarning)#>}
catch {$false}}

if (-not $expiredEntries.Count) {$script:warning = "No expired entries found."; nomessage; rendermenu}
else {showentries $expiredEntries}; nomessage; nowarning}

'S' {# Search for keyword matches.
if (-not $script:jsondatabase -or -not $script:jsondatabase.Count) {$script:warning = "No database loaded."; nomessage; rendermenu}

Write-Host -f yellow "`n`nProvide a comma separated list of keywords to find: " -n; $keywords = Read-Host

# Split keywords, trim and to lowercase for case-insensitive matching
$keywordList = $keywords.Split(',') | ForEach-Object {$_.Trim().ToLower()}

$matchedEntries = $script:jsondatabase | Where-Object {$text = ($_ | Out-String).ToLower()
foreach ($k in $keywordList) {if ($text -match [regex]::Escape($k)) {return $true}}
return $false}

if (-not $matchedEntries.Count) {$script:warning = "No matches found for provided keywords."; nomessage; rendermenu}

if (-not $keywords -or $keywords.Trim().Length -eq 0) {$matchedEntries = $null; $script:warning = "No search terms provided."; nomessage; rendermenu}

else {showentries $matchedEntries -search -keywords $keywords; nomessage; nowarning}}

'M' {# Toggle Management mode.
if ($script:management -eq $true) {$script:management = $false}
else {$script:management = $true}
nowarning; nomessage; rendermenu}

'K' {# Select a different password encryption key.
managementisdisabled
$script:keyfiles = Get-ChildItem -Path $script:keydir -Filter *.key
if (-not $script:keyfiles) {$script:warning = "No .key files found."; nomessage; rendermenu}
elseif ($script:keyfiles) {Write-Host -f white "`n`n🗝  Available AES Key Files:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $script:keyfiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $script:keyfiles[$i].Name}
Write-Host -f green "`n🗝  Enter number of the key file to use: " -n; $sel = Read-Host
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $script:keyfiles.Count) {$script:keyfile = $script:keyfiles[$sel - 1].FullName; $script:keyexists = $true; nowarning; neuralizer; $key = decryptkey $script:keyfile; if ($script:keyfile -match '(?i)((\\[^\\]+){2}\\\w+\.KEY)') {$shortkey = $matches[1]} else {$shortkey = $script:keyfile} $script:message = "$shortkey selected and made active."; nowarning; $script:disablelogging = $false
if (-not $script:key) {$script:warning += " Key decryption failed. Aborting."; nomessage}}}; rendermenu}

'C' {# Create a new password encryption key.
managementisdisabled
Write-Host -f green "`n`n🔑 Enter filename for new keyfile: " -n; $getkey = Read-Host
if ($getkey -lt 1) {$script:warning = "No filename entered."; nomessage; rendermenu}
else {if (-not $getkey.EndsWith(".key")) {$getkey += ".key"}
newkey $getkey; rendermenu}}

'D' {# Select a different database.
managementisdisabled
$dbFiles = Get-ChildItem -Path $script:databasedir -Filter *.pwdb
if (-not $dbFiles) {$script:warning = "No .pwdb files found."; nomessage; rendermenu}
else {Write-Host -f white "`n`n📑 Available Password Databases:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $dbFiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $dbFiles[$i].Name}
Write-Host -f green "`n📑 Enter number of the database file to use: " -n; $sel = Read-Host
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $dbFiles.Count) {$script:jsondatabase = $null; $script:database = $dbFiles[$sel - 1].FullName; $dbloaded = $script:database -replace '.+\\Modules\\', ''; loadjson; $script:message = "$dbloaded selected and made active."; if ($script:jsondatabase.Count -eq 0) {$script:warning = "If changing database and key combinations, always load the key before the database."} else {nowarning}}
else {$script:warning = "Invalid selection."; nomessage}; rendermenu}}

'P' {# Create a new password database.
managementisdisabled
Write-Host -f green "`n`n📄 Enter filename for new password database: " -n; $getdatabase = Read-Host
if ($getdatabase.length -lt 1) {$script:warning = "No filename entered."; nomessage; rendermenu}
else {if (-not $getdatabase.EndsWith(".pwdb")) {$getdatabase += ".pwdb"}
$path = Join-Path $script:databasedir $getdatabase
if (Test-Path $path) {$script:warning = "File already exists. Choose a different name."; nomessage}
else {$script:jsondatabase = $null; $script:jsondatabase = @(); decryptkey; $script:database = $Path
#if (-not ($script:jsondatabase -is [System.Collections.IEnumerable])) {$script:jsondatabase = @()}
savetodisk; $script:message = "📄 New database $getdatabase created."; nowarning}; rendermenu}}

'V' {# Verify a PWDB file.
managementisdisabled
Write-Host -f cyan "`n`n✅ Provide full path of PWDB file to validate: " -n; $filepath = Read-Host
if ($filepath.length -lt 1) {$script:warning = "Aborted."; nomessage; rendermenu}
elseif (-not (Test-Path $filepath)) {$script:warning = "File not found: $filepath"; nomessage; rendermenu}
else {$lineNumber = 0; $invalidLines = @(); $fixedLines = @(); Get-Content $filepath | ForEach-Object {$lineNumber++; $line = $_.Trim()
if ($line -eq '') {return}
try {$null = $line | ConvertFrom-Json -ErrorAction Stop}
catch {$fixedLine = $line -replace '"Notes"\s*:\s*"[^"]*"', '"Notes":"[Invalid JSON removed]"'
try {$null = $fixedLine | ConvertFrom-Json -ErrorAction Stop; $fixedLines += [PSCustomObject]@{LineNumber = $lineNumber; OriginalContent = $line; FixedContent = $fixedLine}}
catch {$invalidLines += [PSCustomObject]@{LineNumber = $lineNumber; Content = $line; Reason = "Invalid JSON even after 'Notes' fix: $($_.Exception.Message)"}}}}
if ($fixedLines.Count -gt 0) {Write-Host -f yellow "`nLines fixed by 'Notes' replacement:"; $fixedLines | Format-Table -AutoSize}
else {Write-Host -f green "`nNo lines needed fixing."}
if ($invalidLines.Count -gt 0) {Write-Host -f red"`nLines still invalid after fix attempt:"; $invalidLines | Format-Table -AutoSize}
else {Write-Host -f green "`nAll JSON lines are valid or fixable."}
Write-Host -f yellow "`n↩️ Return " -n; Read-Host; rendermenu}}

'I' {# Import a CSV password database.
managementisdisabled
$script:message = "Imported files must contain the fields: Title, Username, Password and URL. Timestamp is ignored and Password can be empty, but must exist. All other fields can be added as notes and/or tags. Fields added to notes will only be added if they are populated. Fields added to tags can be added to all imported entries or only those that are populated."; nowarning
if (-not $script:database -and -not $script:keyfile) {$script:warning = "You must have a database and key file loaded in order to start an import."; nomessage; return}
Write-Host -f yellow "`n`n📥 Enter the full path to the CSV file: " -n; $csvpath = Read-Host
if ($csvpath.length -lt 1) {$script:warning = "Aborted."; nomessage; rendermenu}
elseif (Test-Path $csvpath -ErrorAction SilentlyContinue) {importcsv $csvpath}
else {$script:warning = "CSV not found."; nomessage}; rendermenu}

'OEMMINUS' {# Export all entries.
managementisdisabled
nomessage; nowarning; rendermenu
Write-Host -f yellow "`n`nProvide an export path for the database.`nOtherwise the database directory will be used: " -n; $path = Read-Host
if ($path.length -lt 1) {$path = "$script:database"; $path = $path -replace '\.pwdb$', '.csv'}
Write-Host -f yellow "`nSpecify the fields and the order in which to includet them.`nThe default is (" -n; Write-Host -f white "Title, Username, URL" -n; Write-Host -f yellow "): " -n; $fields = Read-Host
if ($fields.length -lt 1) {$fields = "Title,Username,URL"}
$fields = $fields -replace "\s*,\s*", ","
Write-Host -f yellow "`nProceed? (Y/N) " -n; $confirmexport = Read-Host
if ($confirmexport -match "^[Yy]$") {export $path $fields} else {$script:warning = "Aborted."; nomessage; rendermenu}}

'SUBTRACT' {# Export all entries.
managementisdisabled
nomessage; nowarning; rendermenu; rendermenu
Write-Host -f yellow "`n`nProvide an export path for the database.`nOtherwise the database directory will be used: " -n; $path = Read-Host
if ($path.length -lt 1) {$path = "$script:database"; $path = $path -replace '\.pwdb$', '.csv'}
Write-Host -f yellow "`nSpecify the fields and the order in which to includet them.`nThe default is (" -n; Write-Host -f white "Title, Username, URL" -n; Write-Host -f yellow "): " -n; $fields = Read-Host
if ($fields.length -lt 1) {$fields = "Title,Username,URL"}
$fields = $fields -replace "\s*,\s*", ","
Write-Host -f yellow "`nProceed? (Y/N) " -n; $confirmexport = Read-Host
if ($confirmexport -match "^[Yy]$") {export $path $fields; rendermenu} else {$script:warning = "Aborted."; nomessage; rendermenu}}

'OEMCOMMA' {# Backup current database and key.
managementisdisabled
backup; rendermenu}

'OEMPERIOD' {# Retore a backup.
managementisdisabled
restore; rendermenu}

'L' {# Lock session.
$script:message = "Session locked."; nowarning; neuralizer; if ($script:noclip -eq $false) {clearclipboard 0 64}; rendermenu}

'U' {# Unlock session.
if ($script:keyfile) {""; $key = decryptkey $script:keyfile}
else {$script:warning = "🔑 No key loaded."; nomessage}
if ($script:unlocked) {loadjson; $script:message += " Session unlocked."}; nowarning; rendermenu}

'Z' {# Toggle clipboard.
if ($script:noclip -eq $true) {$script:noclip = $false; $script:message = "Retrieved passwords will be copied to the clipboard for $script:delayseconds seconds."; nowarning; rendermenu}
elseif ($script:noclip -eq $false) {$script:noclip = $true; $script:message = "Retrieved passwords will not be copied to the clipboard."; nowarning; rendermenu}}

'Q' {# Quit. (Includes funky logic to capture keys after the user confirms.)
Write-Host -f green "`n`nAre you sure you want to quit? (Y/N) " -n; $confirmquit = Read-Host
if ($confirmquit -notmatch "^[Yy]$") {$script:warning = "Aborted."; nomessage; rendermenu}
else {$script:quit = $true; logoff; while ([Console]::KeyAvailable) {return}; return}}

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
else {; logoff; while ([Console]::KeyAvailable) {return}; return}}

'T' {# Set Timer.
if (-not $script:keyfile -or -not $script:unlocked) {$script:warning = "You must have a key loaded and unlocked to reset its timer."; nomessage; rendermenu}
else {""; $key = decryptkey $script:keyfile
if (-not $script:unlocked) {neuralizer; rendermenu}
if ($script:unlocked) {loadjson; Write-Host -f yellow "`nHow many minutes should the session remain unlocked? (1-99) " -n; $usersetminutes = Read-Host; if ($usersetminutes -as [int] -and [int]$usersetminutes -ge 1 -and [int]$usersetminutes -le 99) {$script:timeoutseconds = [int]$usersetminutes * 60; $script:sessionstart = Get-Date; while ([Console]::KeyAvailable) {[Console]::ReadKey($true) > $null}; $script:lastrefresh = 99; rendermenu}
else {$script:warning = "Invalid timer value set."; nomessage; rendermenu}}}}

'O' {# Reload defaults.
if (-not $script:database -or -not $script:keyfile) {$script:database = $script:defaultdatabase; $script:keyfile = $script:defaultkey; ""; $script:key = decryptkey $script:keyfile; 
if ($script:unlocked) {$script:message = "Defaults successfully loaded and made active."; nowarning; rendermenu}
else {$script:database = $null; $script:keyfile = $null; rendermenu}}
else {rendermenu}}

'BACKSPACE' {# Clear messages.
nomessage; nowarning; rendermenu}

'ENTER' {# Clear messages.
nomessage; nowarning; rendermenu}

'F4' {# Turn off Logging.
if ($script:disablelogging) {$script:message = "Logging is already turned off for the current key activity."; nowarning; rendermenu}

else {$proveit = $null; ""; $proveit = decryptkey $script:keyfile
if (-not $proveit) {$proveit = $null; $script:warning = "Password failed or aborted. Logging is still active."; nomessage; rendermenu}
if ($proveit) {$script:disablelogging = $true; if ($script:keyfile -match '\\([^\\]+)$') {$shortkey = $matches[1]} ; $script:warning = "Logging turned off for $shortkey @ $(Get-Date)"; nomessage; rendermenu}}}

'F9' {# Configuration Details
$fixedkeydir = $keydir -replace '\\\\', '\' -replace '\\\w+\.\w+',''; $fixeddatabasedir = $databasedir -replace '\\\\', '\' -replace '\\\w+\.\w+',''; $configfileonly = $script:configpath -replace '.+\\', ''; $keyfileonly = $defaultkey -replace '.+\\', ''; $databasefileonly = $defaultdatabase -replace '.+\\', ''; $dictionaryfileonly = $dictionaryfile -replace '.+\\', ''; $timeoutminutes = [math]::Floor($timeoutseconds / 60)
$script:message = "Configuration Details:`n`nConfiguration File Path: $configfileonly`nDefault Key:             $keyfileonly`nDefault Database:        $databasefileonly`nDictionary File:         $dictionaryfileonly`n`nSession Inactivity Timer: $timeoutseconds seconds / $timeoutminutes minutes`nScript Inactivity Timer:  $script:timetobootlimit minutes`nClipboard Timer:          $delayseconds seconds`nEntry Expiration Warning: $expirywarning days`nLog Retention:            $logretention days`n`nDirectories:`n$fixedkeydir`n$fixeddatabasedir"; nowarning; rendermenu}

'F10' {# Test function while development.
"";""; sometestfunction; Read-Host; rendermenu}

default {if ($choice.length -gt 0) {$script:warning = "'$choice' is an invalid choice. Try again."}}}

# Reset on key press.
$script:sessionstart = Get-Date
$choice = $null}} while (-not $script:quit)}

#------------------------ Verify password before allowing access. ---------------------------------
initialize; setdefaults; login
if (-not $script:key -and (Test-Path $script:keyfile -ErrorAction SilentlyContinue)) {loginfailed}
else {loggedin}}

Export-ModuleMember -Function paschwords

<#
## Overview

❓ Usage: pwmanage <database.pwdb> <keyfile.key> -noclip

Most features should be self-explanatory, but here are some useful pieces of information to know:

It is best practice to save key files somewhere distant from the databases. Saving them in different directories on the same hard drive does not count as proper security management, but if this is being used as a personal password manager, then it isn't typically an issue.

The import function is extremely powerful, accepting non-standard fields and importing them as tags, notes, or both. This should make it capable of importing password databases from a wide variety of other password managers, commercial and otherwise. Press 'I' in management mode for more details.

You can use 'F4' to disable logging for the currently loaded key, but only while it's loaded. As soon as any key is loaded, including the same one, logging resumes.

You can use 'F9' to see the current script configuration details.

When the clipboard empties, it is first overwritten with junk, in order to reduce memory artefacts. Clipboard managers would make this pointless, but this method can still be effective in commercial environments, provided proper application hygeine is in place.
## PSD1 Configuration

You can configure the following items in the accomanying PSD1 file:

• The default database and key file names and their respective file paths make it easier to locate and switch databases, on the fly.

• If you use some path under DefaultPowerShellDirectory, this will be replaced in the script with the user's actual PowerShell directory.

• The standard inactivity timeout locks sessions after the specified number of seconds of inactivity.

• The standard time to boot takes over after the inactivity timer and exits the function altogether, after this second timer expires.

• The clipboard time out represents the number of seconds a retrieved password will remain in the clipboard memory before being overwritten with junk information and then cleared. Incidentally, the copy to clipboard feature can be disabled at launch by using the -noclip function, but can by also be toggled inside the function.

• The default expiration value represents the number of days after creation date that an entry will enter the reminder pool. This in no way modifies the entries. It just presents a recommended date for updating passwords. The default is set to the 365 days maximum that is allowed. Values less than this can of course be set. 60 days for example, is common in corporate environments.

• Log retention defaults to 30 days. This is also the minimum allowed, but there is no upper limit.

• The default Common.dictionary file used for the built-in Paschword Generator can be replaced with any plaintext word list.
## Paschword Generator Modes
When a new entry is added to the database, the user is presented with an option to use the built-in paschword generator, providing users with the ability to create paschwords which meet all typical security requirements, but also features several intelligent mechanisms to build  more useful and memorable paschwords.

By typing a series of options at the design prompt, users can create paschword patterns that meet their preferences. Using a hierarchical model, these option are:

• [P]IN: This option supercedes all others and creates a purely numerical paschword, with a minimum character length of 4 and maximum of 16.

• [H]uman readable: This option uses a plaintext dictionary to extract two or more words at random, in order to generate a paschword. These are then run through an alphanumeric word derivation, commonly known as 'leet' code, wherein certain letters are replaced with similar looking numbers and symbols.

• [D]ictionary words only: While not typically as secure as human readable word derivations, this method is the same as the last, but skips the 'leet' code replacement.

• [A]lphanumeric: This is your most common paschword generator, starting with a base of letters and numbers to create a random string of characters.

----------------------------------------------------------------------------------------------------
A few notes about the word derivations:

• All of the options except for PIN will randomize the case of words, so that there should always be a strong mix of upper-case and lower-case letters.

• All 3 of these options will also include at least 1 number.

• The 2 options that use the dictionary have a minimum character length of 12, while the PIN and Alphanumeric options have a minimum character length of 4.

• The maximum character length of all paschwords is 32, except for PIN, which as previously mentioned is 16.

• The included dictionary used for Human readable and Dictionary paschwords contains 4720 common English words with a minimum length of 4 letters and a maximum of 10. This list was pulled from Google's most common words list and modified to remove suffixes and most proper nouns. So, you would find words like encrypt, but not encrypted or encrypts. This was done in order to make the word list as compact and diverse as possible.

• The included dictionary may be replaced with any plaintext dictionary, if so desired. It is after all, just a base for pseudo-random paschword generation, while attempting to make the words easier for humans to decipher and remember, because it's great if you have a paschword that is 32 characters long and contains nothing but random symbols, mixed-case letters and numbers, but if you can't remember it, then this can often work to your detriment.
## Paschword Generator Modifiers
Next up are the paschword derivations, of which there are 3:

• [X] Spaces may be included, but will never appear as the first or last letter of a paschword. In the Human readable and Dictionary options, the spaces, if they appear, will always be located between words, in order to make them more useful for generating those memorable paschwords.

• [S]pecial characters includes the following characters: ~!@#$%^&*_-+=.,;:.

• [Z]uper special characters will also includes brackets: (){}[].

If the Special or Zuper special character options are chosen, a minimum of 1 character is guaranteed to exist in the paschword. This does not mean that there will be 1 Special and 1 Zuper special character, just that there will be 1 that belongs to either of those two groups, if requested.
----------------------------------------------------------------------------------------------------
The final element determines the paschword length, with a previously stated minimum of 4 and maximum of 32, but 16 in the case of a PIN.

• [#]4-32 characters in length.
----------------------------------------------------------------------------------------------------
What does this look like in practice?

P12: Would generate a 12 character PIN.

AS32: This would generate an Alphanumeric paschword, with special characters and a length of 32 characters. This is complex and random, but not very memorable.

DXS12: This is the default paschword generation model, which will be used if no characters are typed at the design prompt. It will create a 12 character paschword based on Dictionary words, include standard Special characters and may contains Spaces. This makes for very memorable paschwords, but still random enough to make it difficult for standard decipering tools like brute force or rainbow tables from being able to decipher them.

Now, you have the tool at your disposal, you can use it to mix and match as you see fit. What do you need? DS12, HXS14 AS8? You decide. The paschword generator will create one for you based on the provided critera and ask you if you're satisfied with the result before accepting it. It's fast and easy.
## Technical Details

This module has been written to be as powerful and flexible as possible, while remaining open source.

• The Key files use AES-256-CBC encryption, with a PBKDF2-derived key from the master paschword. A random IV is generated for each key file and prepended to the encrypted content.

• The paschword entries are encrypted using AES-256-CBC with a random IV. The ciphertext is also Base64-encoded for storage.

• The database files are serialized to JSON, compressed with GZIP, then prepended with the AES IV, encrypted using AES-256-CBC, and finally Base64-encoded.

• When a session is locked, the database and key are not just cleared from memory. Both are overwritten several times with junk data much larger than the size of the original elements before being set to null, as are several of the internal, temporary variables, in order to maximize security and decrease the likelihood of successful artefact capture through the use of memory forensic tools. Is this overkill? Yes, probably, but it didn't take a lot of effort on my part to make it signficantly safer in this regard.

• The Paschword generator uses a dictionary containing 4720 of the most common English words between 4 and 10 characters in length, without suffixes, in order to make diversity broader and yet, easily recognizable. Standard randomizers also exist for paschwords without any discernible patterns.
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
##>
