# Load the user configuration.
$powershell = Split-Path $profile; $basemodulepath = Join-Path $powershell "Modules\Secure"; $configpath = Join-Path $basemodulepath "Secure.psd1"
if (!(Test-Path $configpath)) {throw "Config file not found at $configpath"}
$config = Import-PowerShellDataFile -Path $configpath; $keydir = $config.PrivateData.keydir; $script:databasedir = $config.PrivateData.databasedir; $defaultkey = $config.PrivateData.defaultkey; $defaultdatabase = $config.PrivateData.defaultdatabase; $delayseconds = $config.PrivateData.delayseconds; $keydir = $keydir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $databasedir = $databasedir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $defaultkey = Join-Path $keydir $defaultkey; $defaultdatabase = Join-Path $script:databasedir $defaultdatabase; $script:message = $null; $script:warning = $null

function pwmanage ($database = $script:database, $keyfile = $script:keyfile, [switch]$noclip) {# Password Manager.

Write-Host -f yellow "`n🔑 Secure Password Manager 🔒`n-----------------------------" -n

# Check database validity.
if (-not $script:database) {$script:database = $defaultdatabase}
if ($script:database) {if (-not [System.IO.Path]::IsPathRooted($script:database)) {$script:database = Join-Path $script:databasedir $script:database}}

# Check key validity, but allow the menu to load, even if there is no default key.
$script:keyexists = $true
if (-not $script:keyfile) {$script:keyfile = $defaultkey}
if ($script:keyfile -and -not [System.IO.Path]::IsPathRooted($script:keyfile)) {$script:keyfile = Join-Path $keydir $script:keyfile}
if (-not (Test-Path $script:keyfile) -and -not (Test-Path $defaultkey)) {$script:keyexists = $false; $script:keyfile = $null; $script:database = $null}

function verifystore ($database = $script:database, $keyfile = $script:keyfile) {# Verify that a Password store and Keyfile exist.
if (-not (Test-Path "$script:database")) {$script:warning = "Password store not found."; $script:database = $null
if (-not (Test-Path "$script:keyfile")) {$script:warning += " Keyfile also not found."; $script:keyfile = $null}; $script:message = $null; return}}

verifystore $script:database $script:keyfile

function clearclipboard ($delayseconds = 30) {# Fill the clipboard with junk and then clear it after a delay.
Start-Job -ScriptBlock {param($delay, $length); Start-Sleep -Seconds $delay; $junk = -join ((33..126) | Get-Random -Count $length | ForEach-Object {[char]$_}); Set-Clipboard -Value $junk; Start-Sleep -Milliseconds 500; Set-Clipboard -Value $null} -ArgumentList $delayseconds, 64 | Out-Null}

function decryptkey ($keyfile = $script:keyfile) {# Decrypt a keyfile.
$encPath = "$script:keyfile"; $script:message = $null; $script:warning = $null
if (-not (Test-Path $encPath)) {$script:warning = "Encrypted key file not found."; $script:message = $null}
$raw = [IO.File]::ReadAllBytes($encPath); $salt = $raw[0..15]; $iv = $raw[16..31]; $cipher = $raw[32..($raw.Length - 1)]; Write-Host -f green "`n🔐 Password: " -n; $secureMaster = Read-Host -AsSecureString; $master = [System.Net.NetworkCredential]::new("", $secureMaster).Password; $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($master, $salt, 10000); $protectKey = $pbkdf2.GetBytes(32); $aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $protectKey; $aes.IV = $iv; $decryptor = $aes.CreateDecryptor()
try {$decrypted = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length); $marker = [System.Text.Encoding]::UTF8.GetString($decrypted[0..3])
if ($marker -ne "SCHV") {throw "`nMarker mismatch`n"}
$realKey = $decrypted[4..($decrypted.Length - 1)]; return $realKey}
catch {$script:warning = "Incorrect master password or corrupted key file.`nClearing key and database settings to avoid data corruption."; $script:message = $null; $script:keyfile = $null; $script:database = $null}}

# Verify password before allowing access.
if ($script:keyexists -eq $true) {$key = $null; $key = decryptkey $script:keyfile; if (-not $key) {Write-Host -f red "Decryption failed. Aborting.`n"; return}}

function newentry ($database = $script:database, $keyfile = $script:keyfile) {# Create a new entry.
verifystore $script:database $script:keyfile; $script:message = $null; $script:warning = $null; $answer = $null; $confirmDup = $null

# Obtain input.
Write-Host -f yellow "`n📜 Enter Title: " -n; $title = Read-Host; Write-Host -f yellow "🆔 Username: " -n; $username = Read-Host; Write-Host -f yellow "🔐 Password: " -n; $password = Read-Host -AsSecureString; Write-Host -f yellow "🔗 URL: " -n; $url = Read-Host; Write-Host -f yellow "📝 Notes (CTRL-Z + Enter to end): " -n; $notes = [Console]::In.ReadToEnd(); $key = decryptkey $script:keyfile

# Convert password, whether blank or not.
try {$passwordPlain = [System.Net.NetworkCredential]::new("", $password).Password} catch {$passwordPlain = ""}
if ([string]::IsNullOrEmpty($passwordPlain)) {$passwordPlain = ""}
if ($passwordPlain.length -ge 1) {$passwordSecure = ConvertTo-SecureString $passwordPlain -AsPlainText -Force; $secure = $passwordSecure | ConvertFrom-SecureString -Key $key}
else {$secure = ""}

# Load existing entries or empty array if none.
$listPath = "$script:database"; $entries = @(); $existing = $null
if (Test-Path $listPath) {$raw = Get-Content $listPath; $entries = foreach ($line in $raw) {$line | ConvertFrom-Json}
if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) {$entries = @($entries)}}

# Check for existing entry matching username and URL.
$existing = $entries | Where-Object {$_.Username -eq $username -and $_.URL -eq $url}
if ($existing) {Write-Host -f yellow "🔁 An entry already exists for '$username' at '$url'."; Write-Host -f yellow "Overwrite it? (Y/N) " -n; $answer = Read-Host
if ($answer -notmatch '^[Yy]') {Write-Host -f yellow "Please update the entry:`n"
Write-Host -f yellow "📜 Enter Title ($($existing.Title)): " -n; $title = Read-Host; if ([string]::IsNullOrEmpty($title)) {$title = $existing.Title}
Write-Host -f yellow "🆔 Username ($($existing.Username)): " -n; $username = Read-Host; if ([string]::IsNullOrEmpty($username)) {$username = $existing.Username}

# Choose which password to use.
Write-Host -f green "🔐 Do you want to keep the original password or use the new one you just entered? (new/old) " -n; $keep = Read-Host
if ($keep -match "^(?i)old$") {$secure = $existing.Password}
elseif ($keep -match "^(?i)new$") {}
else {$script:warning = "Invalid choice. Aborting."; $script:message = $null; return}

Write-Host -f yellow "🔗 URL ($($existing.URL)): " -n; $url = Read-Host; if ([string]::IsNullOrEmpty($url)) {$url = $existing.URL}
Write-Host -f yellow "📝 Notes (CTRL-Z + Enter to end): " -n; $notes = [Console]::In.ReadToEnd(); if ([string]::IsNullOrEmpty($notes)) {$notes = $existing.Notes}

# Check if it's a real change.
if ($username -eq $existing.Username -and $url -eq $existing.URL -and $notes -eq $existing.Notes) {Write-Host -f yellow "🤔 No changes detected. Save duplicate entry? (Y/N) " -n; $confirmDup = Read-Host
if ($confirmDup -notmatch '^[Yy]') {$script:warning = "Duplicate entry not saved."; $script:message = $null; return}}

# Remove old entry and save new.
$entry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Title = $title; Username = $username; Password = $secure; URL = $url; Notes = $notes}; $entries = $entries | Where-Object {!($_.Username -eq $username -and $_.URL -eq $url)}; $entries += $entry; $entries | ForEach-Object {$_ | ConvertTo-Json -Depth 3 -Compress} | Set-Content -Path $listPath; $script:message = "New entry saved successfully."; $script:warning = $null; return}}

$entry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Title = $title; Username = $username; Password = $secure; URL = $url; Notes = $notes}
$entries += $entry; $entries | ForEach-Object {$_ | ConvertTo-Json -Depth 3 -Compress} | Set-Content -Path $listPath; $script:message = "New entry saved successfully."; $script:warning = $null}

function retrieveentry ($database = $script:database, $keyfile = $script:keyfile, $searchterm, [switch]$noclip) {# Retrieve the password for a single entry.
verifystore $script:database $keyfile

# Validate minimum search length
if ($searchterm.Length -lt 3) {$script:warning = "Requested match is too small. Aborting search."; $script:message = $null; return}

# Decrypt keyfile
$script:message = $null; $script:warning = $null; $key = decryptkey $keyfile; $entrymatches = @()
Get-Content $script:database | ForEach-Object {$line = $_
try {$entry = $line | ConvertFrom-Json}
catch {$fixedLine = $line -replace '"Notes"\s*:\s*"[^"]*"', '"Notes":"[Invalid JSON removed]"'
try {$entry = $fixedLine | ConvertFrom-Json}
catch {Write-Host "Skipped invalid JSON line." -f yellow; return}}

# Match on Title or Username
if ($entry.Title -match $searchterm -or $entry.Url -match $searchterm -or $entry.Notes -match $searchterm) {$entrymatches += $entry}}
$total = $entrymatches.Count

# Check matches count
if ($total -eq 0) {$script:warning = "🔐 No password found for the entry '$searchterm'"; $script:message = $null; return}
elseif ($total -eq 1) {$selected = $entrymatches[0]}
elseif ($total -le 25) {$invalidentry = "`n" 
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $total; $i++) {$m = $entrymatches[$i]
$notesAbbrev = if ($m.Notes.Length -gt 40) {$m.Notes.Substring(0,37) + "..."} else {$m.Notes}; $notesAbbrev = $notesAbbrev -replace "\r?\n?", "";
$urlAbbrev = if ($m.URL.Length -gt 45) {$m.Notes.Substring(0,42) + "..."} else {$m.URL}
Write-Host -f Cyan "$($i + 1). ".padright(4) -n; Write-Host -f yellow "📜 Title: " -n; Write-Host -f white $($m.Title).padright(38) -n; Write-Host -f yellow " 🆔 User: " -n; Write-Host -f white $($m.Username).padright(30) -n; Write-Host -f yellow " 🔗 URL: " -n; Write-Host -f white $urlAbbrev.padright(46) -n; Write-Host -f yellow " 📝 Notes: " -n; Write-Host -f white $notesAbbrev}
Write-Host -f red $invalidentry; Write-Host -f yellow "🔍 Select an entry to view or Enter to cancel: " -n; $choice = Read-Host
if ($choice -eq "") {$script:warning = "Password retrieval cancelled by user."; $script:message = $null; return}
$parsedChoice = 0; $refParsedChoice = [ref]$parsedChoice
if ([int]::TryParse($choice, $refParsedChoice) -and $refParsedChoice.Value -ge 1 -and $refParsedChoice.Value -le $total) {$selected = $entrymatches[$refParsedChoice.Value - 1]; break}
else {$invalidentry = "`nInvalid entry. Try again."}}
while ($true)}
else {$script:warning = "Too many matches ($total). Please enter a more specific search."; $script:message = $null; return}

# Decrypt password field
$plain = "🚫 <no password saved> 🚫"
if ($selected.Password) {try {$secure = $selected.Password | ConvertTo-SecureString -Key $key; $plain = [System.Net.NetworkCredential]::new("", $secure).Password}
catch {$plain = "⚠️ <unable to decrypt password> ⚠️"}}

# Copy to clipboard unless -noclip switch is set
if (-not $noclip) {$plain | Set-Clipboard; clearclipboard}

# Compose output message
$script:message = "`n🗓️ Creation Date: $($selected.Timestamp)`n📜 Title:         $($selected.Title)`n🆔 UserName:      $($selected.Username)`n🔐 Password:      $plain`n🔗 URL:           $($selected.URL)`n📝 Notes:         $($selected.Notes)"; $script:warning = $null}

function newkey ($keyfile = $script:keyfile) {# Create an AES key, protected with a master password.
if (-not $script:keyfile) {$script:warning = "No key file identified."; $script:message = $null}

# Generate AES key
$aesKey = New-Object byte[] 32; [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)

# Prepend magic marker "SCHV"
$marker = [System.Text.Encoding]::UTF8.GetBytes("SCHV"); $keyWithMarker = $marker + $aesKey

$script:keyfile = Join-Path $keydir $script:keyfile
if (Test-Path $script:keyfile) {$script:warning = "That key file already exists."; $script:message = $null; return}

Write-Host -f yellow "🔐 Enter a master password to protect your key:" -n; $secureMaster = Read-Host -AsSecureString; $master = [System.Net.NetworkCredential]::new("", $secureMaster).Password

# Generate salt and derive key using PBKDF2
$salt = New-Object byte[] 16; [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($salt); $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($master, $salt, 10000); $protectKey = $pbkdf2.GetBytes(32)

# Encrypt keyWithMarker using protectKey
$aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $protectKey; $aes.GenerateIV(); $iv = $aes.IV; $encryptor = $aes.CreateEncryptor(); $encryptedKey = $encryptor.TransformFinalBlock($keyWithMarker, 0, $keyWithMarker.Length)

# Store salt + IV + ciphertext
$output = [byte[]]($salt + $iv + $encryptedKey); [IO.File]::WriteAllBytes("$script:keyfile", $output); $script:message = "Encrypted AES key created."; $script:keyexists = $true; $script:warning = $null}

function importcsv ($csvpath, $database = $script:database, $keyfile = $script:keyfile) {# Import CSV file with plaintext passwords.
verifystore $script:database $script:keyfile

if (-not (Test-Path $csvpath)) {$script:warning = "CSV file not found: $csvpath"; $script:message = $null}
$key = decryptkey $script:keyfile
if (-not $key) {$script:warning = "Key decryption failed. Aborting import."; $script:message = $null}

# Load current entries
$entries = @()
if (Test-Path $script:database) {$entries = @(Get-Content $script:database | ForEach-Object {$_ | ConvertFrom-Json})}

# Import new entries from CSV
$imported = Import-Csv $csvpath
$added = 0; $skipped = 0; $overwritten = 0; $duplicates = 0

foreach ($entry in $imported) {$title = $entry.Title; $username = $entry.Username; $plainPassword = $entry.Password; $url = $entry.URL; $notes = $entry.Notes
$match = $entries | Where-Object {$_.Username -eq $username -and $_.URL -eq $url}
if ($match) {$duplicates++; Write-Host -f yellow "`nDuplicate detected for 🆔 '$username' at 🔗 '$url'"; Write-Host -f cyan "📜 Title: $($match.Title) => $title"; Write-Host -f cyan "📝 Notes: $($match.Notes) => $notes"; Write-Host -f cyan "Options: (S)kip / (O)verwrite / (K)eep both [default: Keep]: " -n; $choice = Read-Host
switch ($choice.ToUpper()) {"O" {$entries = $entries | Where-Object {$_ -ne $match}; $overwritten++}
"S" {Write-Host -f red "Skipping entry."; $skipped++; continue}
"K" {Write-Host -f yellow "Keeping both."}
default {Write-Host -f yellow "Keeping both."}}}

# Encrypt and add entry
if ([string]::IsNullOrWhiteSpace($plainPassword)) {Write-Host -f yellow "Entry for 🆔 '$username' at 🔗 '$url' has no password. Adding with 🚫 empty password."; $encryptedPassword = ""}
else {$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force; $encryptedPassword = $securePassword | ConvertFrom-SecureString -Key $key}
$newEntry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Title = $title; Username = $username; Password = $encryptedPassword; URL = $url; Notes = $notes}
$entries += $newEntry; $added++}

# Save updated database
$entries | ForEach-Object {$_ | ConvertTo-Json -Compress} | Set-Content -Path $script:database -Encoding UTF8

# Summary
Write-Host -f green "`n✅ Import complete.`n"; Write-Host -f green " New entries added : $added"; Write-Host -f green " Duplicates skipped : $skipped"; Write-Host -f green " Overwritten entries: $overwritten"; Write-Host -f green " Total duplicates : $duplicates`n"}

function showentries ($entries, $pagesize = 30) {# Browse entire database.
$total = $entries.Count; $page = 0
while ($true) {cls; if ($sortField) {$entries = if ($descending) {$entries | Sort-Object $sortField -Descending} else {$entries | Sort-Object $sortField}}; $start = $page * $PageSize; $chunk = $entries[$start..([math]::Min($start + $PageSize - 1, $total - 1))]; $chunk | Format-Table -AutoSize Title, Username, URL;
$arrow = if ($descending) {"▾"} else {if (-not $sortfield) {""} else {"▴"}}
Write-Host -f yellow ("-" * 120); Write-Host -f cyan "📑 Page $($page + 1)/$([math]::Ceiling($total / $PageSize))".padright(16) -n; Write-Host -f yellow "| ⏮️(F)irst (P)revious (N)ext (L)ast⏭️ |" -n; Write-Host -f green " Sort by: 📜(T)itle 🆔(U)ser 🔗(W)eb URL " -n; Write-Host -f yellow "| "-n; Write-Host -f green "$arrow $sortField".padright(10) -n; Write-Host -f yellow " | " -n; Write-Host -f cyan "↩️(Q)uit " -n; $key = Read-Host
switch ($key.ToUpper()) {"F" {$page = 0}
"N" {if (($start + $PageSize) -lt $total) {$page++}}
"P" {if ($page -gt 0) {$page--}}
"L" {$page = [int][math]::Floor(($total - 1) / $PageSize)}
"T" {if ($sortField -eq "Title") {$descending = -not $descending} else {$sortField = "Title"; $descending = $false}; $page = 0}
"U" {if ($sortField -eq "Username") {$descending = -not $descending} else {$sortField = "Username"; $descending = $false}; $page = 0}
"W" {if ($sortField -eq "URL") {$descending = -not $descending} else {$sortField = "URL"; $descending = $false}; $page = 0}
"Q" {return}}}}

function removeentry ($database = $script:database, $searchterm) {# Remove an entry.

# Validate minimum search length
if ($searchterm.Length -lt 3) {$script:warning = "Search term too short. Aborting removal."; $script:message = $null; return}

# Load entries
$entries = Get-Content $script:database | ForEach-Object {try {$_ | ConvertFrom-Json}
catch {$fixedLine = $_ -replace '"Notes"\s*:\s*"[^"]*"', '"Notes":"[Invalid JSON removed]"'
try {$fixedLine | ConvertFrom-Json}
catch {return}}}

# Filter matches by Title or URL
$matches = $entries | Where-Object {$_.Title -match $searchterm -or $_.URL -match $searchterm -or $_.Notes -match $searchterm}
$count = $matches.Count
if ($count -eq 0) {$script:warning = "No entries found matching '$searchterm'."; $script:message = $null; return}
elseif ($count -gt 25) {$script:warning = "Too many matches ($count). Please refine your search."; $script:message = $null; return}

# Select entries.
if ($count -eq 1) {$selected = $matches[0]}
else {$invalidentry = "`n"
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $count; $i++) {$m = $matches[$i]
$notesAbbrev = if ($m.Notes.Length -gt 40) { $m.Notes.Substring(0,37) + "..." } else { $m.Notes }; $notesAbbrev = $notesAbbrev -replace "\r?\n?", ""
$urlAbbrev = if ($m.URL.Length -gt 45) { $m.URL.Substring(0,42) + "..." } else { $m.URL }
Write-Host -f Cyan "$($i + 1). ".PadRight(4) -n; Write-Host -f yellow "📜 Title: " -n; Write-Host -f white $($m.Title).PadRight(38) -n; Write-Host -f yellow " 🆔 User: " -n; Write-Host -f white $($m.Username).PadRight(30) -n; Write-Host -f yellow " 🔗 URL: " -n; Write-Host -f white $urlAbbrev.PadRight(46) -n; Write-Host -f yellow " 📝 Notes: " -n; Write-Host -f white $notesAbbrev}
Write-Host -f red $invalidentry; Write-Host -f yellow "❌ Select an entry to remove or Enter to cancel: " -n; $choice = Read-Host
if ($choice -eq "") {$script:warning = "Entry removal cancelled."; $script:message = $null; return}
$parsedChoice = 0; $refParsedChoice = [ref]$parsedChoice
if ([int]::TryParse($choice, $refParsedChoice) -and $refParsedChoice.Value -ge 1 -and $refParsedChoice.Value -le $count) {$selected = $matches[$refParsedChoice.Value - 1]; break}
else {$invalidentry = "`nInvalid entry. Try again."}}
while ($true)}

# Confirm removal
Write-Host -f cyan "`nYou selected:`n"; Write-Host -f yellow "📜 Title: " -n; Write-Host -f white "$($selected.Title)"; Write-Host -f yellow "🆔 User:  " -n; Write-Host -f white "$($selected.Username)"; Write-Host -f yellow "🔗 URL:   " -n; Write-Host -f white "$($selected.URL)"; Write-Host -f yellow "📝 Notes: " -n; Write-Host -f white "$($selected.Notes)"; Write-Host -f cyan "`nType 'YES' to confirm removal: " -n; $confirm = Read-Host; if ($confirm -ne "YES") {$script:warning = "Removal aborted."; $script:message = $null; return}

# Remove entry from file: write back all entries except the selected one
$updatedEntries = $entries | Where-Object {$_ -ne $selected}; $updatedEntries | ForEach-Object {$_ | ConvertTo-Json -Compress} | Set-Content $script:database; $script:message =  "Entry removed successfully."; $script:warning = $null}

do {# Menu system.
cls; Write-Host -f white "`n🔑 Secure Password Manager 🔒"; Write-Host -f cyan ("-" * 70)
if ($script:database) {$displaydatabase = Split-Path -Leaf $script:database -ErrorAction SilentlyContinue} else {$displaydatabase = "none loaded"}
if ($script:keyfile) {$displaykey = Split-Path -Leaf $script:keyfile -ErrorAction SilentlyContinue} else {$displaykey = "none loaded"}
Write-Host -f white "Current Database: " -n; Write-Host -f green "$displaydatabase"
Write-Host -f white "Current Key: " -n; Write-Host -f green "$displaykey"
if ($displaydatabase -match '^(?i)(.+?)\.pwdb$') {$db = $matches[1]}
if ($displaykey -match '^(?i)(.+?)\.key$') {$key = $matches[1]}
if (($displaykey -eq "none loaded" -or $displaydatabase -eq "none loaded") -and ($script:database -or $script:keyfile)) {$script:warning = "Make sure to load both a database and a keyfile before continuing."}
if ($db -and $key -and $db -ne $key) {Write-Host -f red "`nWarning: " -n; Write-Host -f yellow "The key and database filenames do not match.`n"; $script:warning = "Continuing with an incorrect key and database pairing could lead to data corruption.`nEnsure you have the correct file combination before making any file changes."}
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "A. " -n; Write-Host -f yellow "➕ Add a new entry."
Write-Host -f cyan "R. " -n; Write-Host -f white "🔓 Retrieve an entry."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "NK. " -n; Write-Host -f yellow "🔑 Create a new password encryption key."
Write-Host -f cyan "ND. " -n; Write-Host -f yellow "📄 Create a new password database."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "V. " -n; Write-Host -f yellow "✅ Validate a PWDB file."
Write-Host -f cyan "I. " -n; Write-Host -f yellow "📥 Import a CSV plaintext password database (KeePass 1.x)."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "B. " -n; Write-Host -f white "🔍 Browse all entries."
Write-Host -f cyan "X. " -n; Write-Host -f red "❌ Remove an entry."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "K. " -n; Write-Host -f white "🗝️ Select a different password encryption key."
Write-Host -f cyan "D. " -n; Write-Host -f white "📑 Select a different password database."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "C. " -n; Write-Host -f gray "♻️ Clear message center"-n
if ($noclip) {Write-Host -f gray "."} else {Write-Host -f gray " and clipboard."}
Write-Host -f cyan "H. " -n; Write-Host -f yellow "❓ Help."
Write-Host -f cyan "Q. " -n; Write-Host -f darkgray "⏏️ Exit."
if ($script:message.length -gt 1) {Write-Host -f cyan ("-" * 70); Write-Host -f white "`n🗨️ $script:message`n"}
if ($script:warning.length -gt 1) {Write-Host -f cyan ("-" * 70); Write-Host -f red "`n⚠️ $script:warning`n"}
Write-Host -f cyan ("-" * 70)
Write-Host -f white "`n⚡ Choose an action: " -n; $choice = Read-Host

switch ($choice) {'A' {# Add a new entry.
newentry $script:database $script:keyfile}

'R' {# Retrieve an entry.
Write-Host -f green "`n🔓 Enter Title, 🔗 URL or 📝 Note to identify entry: " -n; $searchterm = Read-Host; retrieveentry $script:database $script:keyfile $searchterm}

'NK' {# Create a new password encryption key.
Write-Host -f green "`n🔑 Enter filename for new keyfile: " -n; $script:keyfile = Read-Host
if ([string]::IsNullOrWhiteSpace($script:keyfile)) {$script:warning = "`nNo filename entered."; $script:message = $null}
if (-not $script:keyfile.EndsWith(".key")) {$script:keyfile += ".key"}
newkey $script:keyfile}

'ND' {# Create a new password database.
Write-Host -f green "`n📄 Enter filename for new password database: " -n; $script:database = Read-Host
if ([string]::IsNullOrWhiteSpace($script:database)) {$script:warning = "No filename entered."; $script:message = $null}
if (-not $script:database.EndsWith(".pwdb")) {$script:database += ".pwdb"}
$path = Join-Path $script:databasedir $script:database
if (Test-Path $path) {$script:warning = "File already exists. Choose a different name."; $script:message = $null}
else {New-Item -Path $path -ItemType File | Out-Null; $script:message = "$path created and made active."; $script:warning = $null; $script:database = $path}}

'V' {Write-Host -f cyan "`n✅ Provide full path of PWDB file to validate: " -n; $FilePath = Read-Host
if (-not (Test-Path $FilePath)) {$script:warning = "File not found: $FilePath"; $script:message = $null}
$lineNumber = 0; $invalidLines = @(); $fixedLines = @(); Get-Content $FilePath | ForEach-Object {$lineNumber++; $line = $_.Trim()
if ($line -eq '') {return}
try {$null = $line | ConvertFrom-Json -ErrorAction Stop}
catch {$fixedLine = $line -replace '"Notes"\s*:\s*"[^"]*"', '"Notes":"[Invalid JSON removed]"'
try {$null = $fixedLine | ConvertFrom-Json -ErrorAction Stop; $fixedLines += [PSCustomObject]@{LineNumber = $lineNumber; OriginalContent = $line; FixedContent = $fixedLine}}
catch {$invalidLines += [PSCustomObject]@{LineNumber = $lineNumber; Content = $line; Reason = "Invalid JSON even after 'Notes' fix: $($_.Exception.Message)"}}}}
if ($fixedLines.Count -gt 0) {Write-Host "Lines fixed by 'Notes' replacement:" -f yellow; $fixedLines | Format-Table -AutoSize}
else {Write-Host "No lines needed fixing." -f green}
if ($invalidLines.Count -gt 0) {Write-Host "Lines still invalid after fix attempt:" -f red; $invalidLines | Format-Table -AutoSize}
else {Write-Host "All JSON lines are valid or fixable." -f green}
Write-Host -f cyan "↩️ Enter to continue. " -n; $null = Read-Host}

'I' {# Import a CSV password database.
Write-Host -f yellow "`n📥 Enter the full path to the CSV file: " -n; $csvpath = Read-Host
if (Test-Path $csvpath -ErrorAction SilentlyContinue) {importcsv $csvpath $script:database $script:keyfile}
else {$script:warning = "CSV not found."; $script:message = $null}}

'B' {# Browse all entries.
$entries = [System.Collections.ArrayList]::new()
Get-Content $script:database | ForEach-Object {try {$obj = $_ | ConvertFrom-Json
if ($obj) {$entries.Add($obj) | Out-Null}}
catch {Write-Host -f red "`nSkipping an invalid JSON line. Please check the file for corruption or incorrectly formatted entries.`nIf you make changes to the file, those lines will be lost."}}
if (-not $entries.Count) {$script:warning = "No valid entries found to display."; $script:message = $null; break}
showentries $entries; $script:message = $null; $script:warning = $null}

'X' {# Remove an entry.
Write-Host -f green "`n❌ Enter Title, URL or Note to identify entry: " -n; $searchterm = Read-Host; removeentry $script:database $searchterm}

'K' {# Select a different password encryption key.
$script:keyfiles = Get-ChildItem -Path $keydir -Filter *.key
if (-not $script:keyfiles) {Write-Host -f red "No .key files found."; return}
Write-Host -f white "`n🗝  Available AES Key Files:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $script:keyfiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $script:keyfiles[$i].Name}
Write-Host -f green "`n🗝 Enter number of the key file to use: " -n; $sel = Read-Host
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $script:keyfiles.Count) {$script:keyfile = $script:keyfiles[$sel - 1].FullName; $script:message = "$script:keyfile selected."; $script:keyexists = $true; $script:warning = $null; $key = $null; $key = decryptkey $script:keyfile; if (-not $key) {Write-Host -f red "Decryption failed. Aborting.`n"; return}}}

'D' {# Select a different database.
$dbFiles = Get-ChildItem -Path $script:databasedir -Filter *.pwdb
if (-not $dbFiles) {Write-Host -f red "No .pwdb files found."; return}
Write-Host -f white "`n📑 Available Password Databases:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $dbFiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $dbFiles[$i].Name}
Write-Host -f green "`n📑 Enter number of the database file to use: " -n; $sel = Read-Host
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $dbFiles.Count) {$script:database = $dbFiles[$sel - 1].FullName; $script:message = "$script:database selected."; $script:warning = $null}
else {$script:warning = "Invalid selection."; $script:message = $null}}

'C' {# Clear message center.
$script:message = $null; $script:warning = $null; if (-not $noclip) {clearclipboard 0 64}}

'H' {$script:message = "❓ Usage: pwmanage <database.pwdb> <keyfile.key> -noclip`n`nIf no database/keyfile are specified, the defaults `"secure.pwdb`" and `"secure.key`" will be used.`n`nWhen a password is retrieved, it will automatically be copied to the clipboard for 30 seconds,`nunless the -noclip option is used at launch time.`n`nYou can configure the default password, default key file and directories where these are saved`nby modifying the entries in the `"Secure.psd1`" file located in the same directory as the module.`n`nIt is of course, best practice to save the key files somewhere distant from the databases.`nYou could even save the database files on cloud storage, but I recommended saving the keys locally.`n`nThe initial configurations of the directories within the PSD1 file point to:`n`n`"DefaultPowerShellDirectory\Modules\Secure\keys`" and `"DefaultPowerShellDirectory\Modules\Secure\databases`"`n`nThe term `"DefaultPowerShellDirectory`" is a placeholder that is evaluated within the module,`nredirecting these to your personal PowerShell directory. As stated above, I advise moving these`nsomewhere else once you've setup the database and plan to use it long-term."; if ($script:keyexists -eq $false) {$script:warning = "First time use: You will need to create key and database files with the options above.`nThe defaults configured in the PSD1 file use the filename `"secure`" for both."}}

'Q' {"`n`t🔒`n"; return}
default {Write-Host -f red "`nInvalid choice. Try again.`n"}}} while ($true); ""}

Export-ModuleMember -Function pwmanage
