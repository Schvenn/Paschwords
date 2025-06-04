function pwmanage ($database = $script:database, $keyfile = $script:keyfile, [switch]$noclip) {# Password Manager.

function initialize {# Load the user configuration.
$script:powershell = Split-Path $profile; $basemodulepath = Join-Path $script:powershell "Modules\Secure"; $script:configpath = Join-Path $basemodulepath "Secure.psd1"
if (!(Test-Path $script:configpath)) {throw "Config file not found at $script:configpath"}

$config = Import-PowerShellDataFile -Path $configpath
$script:keydir = $config.PrivateData.keydir; $script:defaultkey = $config.PrivateData.defaultkey; $script:keydir = $script:keydir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $script:defaultkey = Join-Path $script:keydir $script:defaultkey
$script:databasedir = $config.PrivateData.databasedir; $script:defaultdatabase = $config.PrivateData.defaultdatabase; $script:databasedir = $script:databasedir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell); $script:defaultdatabase = Join-Path $script:databasedir $script:defaultdatabase
$script:delayseconds = $config.PrivateData.delayseconds
$script:timeoutseconds = $config.PrivateData.timeoutseconds; if ([int]$script:timeoutseconds -gt 5940) {$script:timeoutseconds = 5940}
$script:expirywarning = $config.PrivateData.expirywarning
$script:logretention = $config.PrivateData.logretention; if ([int]$script:logretention -lt 30) {$script:logretention = 30}
$script:message = $null; $script:warning = $null; $script:unlocked = $false; $script:sessionstart = Get-Date; $script:lastrefresh = 1000; $script:management = $false; $script:quit = $false; $script:noclip = $noclip}

function setdefaults {# Set Key and Database defaults.
# Check database validity.
if (-not $script:database) {$script:database = $script:defaultdatabase}
if ($script:database) {if (-not [System.IO.Path]::IsPathRooted($script:database)) {$script:database = Join-Path $script:databasedir $script:database}}

# Check key validity, but allow the menu to load, even if there is no default key.
$script:keyexists = $true
if (-not $script:keyfile) {$script:keyfile = $script:defaultkey}
if ($script:keyfile -and -not [System.IO.Path]::IsPathRooted($script:keyfile)) {$script:keyfile = Join-Path $script:keydir $script:keyfile}
if (-not (Test-Path $script:keyfile) -and -not (Test-Path $script:defaultkey)) {$script:keyexists = $false; $script:keyfile = $null; $script:database = $null}}

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

function decryptkey ($keyfile = $script:keyfile) {# Decrypt a keyfile.
$encPath = "$script:keyfile"; nomessage; nowarning

if (-not (Test-Path $encPath)) {$script:warning = "Encrypted key file not found."; nomessage}
$raw = [IO.File]::ReadAllBytes($encPath); $salt = $raw[0..15]; $iv = $raw[16..31]; $cipher = $raw[32..($raw.Length - 1)]

Write-Host -f green "`n`t🔐 Password: " -n; $secureMaster = Read-Host -AsSecureString
$master = [System.Net.NetworkCredential]::new("", $secureMaster).Password; $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($master, $salt, 10000); $protectKey = $pbkdf2.GetBytes(32); $aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $protectKey; $aes.IV = $iv; $decryptor = $aes.CreateDecryptor()
try {$decrypted = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length); $marker = [System.Text.Encoding]::UTF8.GetString($decrypted[0..3])

if ($marker -ne "SCHV") {throw "`nMarker mismatch`n"}
$script:realKey = $decrypted[4..($decrypted.Length - 1)]; $script:unlocked = $true; $script:sessionstart = Get-Date; return $script:realKey}

catch {if ($script:warning -notmatch "Clearing key") {if ($script:warning) {$script:warning += "`n"}; $script:warning += "Incorrect master password or corrupted key file. Clearing key and database settings to avoid data corruption."}; nomessage; $script:keyfile = $null; $script:database = $null}}

function newentry ($database = $script:database, $keyfile = $script:keyfile) {# Create a new entry.
$answer = $null; $confirmDup = $null

# Obtain and validate input.
Write-Host -f yellow "`n`n📜 Enter Title: " -n; $title = Read-Host; 
if (-not $title) {$script:warning = "Every entry must have a Title, as well as a Username and URL. Aborted."; nomessage; rendermenu; return}
Write-Host -f yellow "🆔 Username: " -n; $username = Read-Host
if (-not $username) {$script:warning = "Every entry must have a Username, as well as a Title and URL. Aborted."; nomessage; rendermenu; return}
Write-Host -f yellow "🔐 Password: " -n; $password = Read-Host -AsSecureString
Write-Host -f yellow "🔗 URL: " -n; $url = Read-Host
if (-not $url) {$script:warning = "Every entry must have a URL, as well as a Title and Username. Aborted."; nomessage; rendermenu; return}
Write-Host -f yellow "🏷️ Tags: " -n; $tags = Read-Host; $tags = ($tags -split ',') | ForEach-Object {$_.Trim()} | Where-Object {$_} | Join-String -Separator ', '
Write-Host -f yellow "📝 Notes (Enter, then CTRL-Z + Enter to end): " -n; $notes = [Console]::In.ReadToEnd(); 
if ($script:unlocked -eq $true) {$key = $script:realKey} else {$key = decryptkey $script:keyfile}

# Convert password, whether blank or not.
try {$passwordPlain = [System.Net.NetworkCredential]::new("", $password).Password} catch {$passwordPlain = ""}
if ([string]::IsNullOrEmpty($passwordPlain)) {$passwordPlain = ""}
if ($passwordPlain.length -ge 1) {$passwordSecure = ConvertTo-SecureString $passwordPlain -AsPlainText -Force; $secure = $passwordSecure | ConvertFrom-SecureString -Key $key}
else {$secure = ""}

# Load existing entries or empty array if none.
$entries = @(); $existing = $null

if (Test-Path $database) {$raw = Get-Content $database; $entries = foreach ($line in $raw) {$line | ConvertFrom-Json}
if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) {$entries = @($entries)}}

# Check for existing entry matching username and URL.
$existing = $entries | Where-Object {$_.Username -eq $username -and $_.URL -eq $url}
if ($existing) {Write-Host -f yellow "`n🔁 An entry already exists for '$username' at '$url'."; Write-Host -f yellow "`nDuplicate it? (Y/N) " -n; $answer = Read-Host
if ($answer -notmatch '^[Yy]') {Write-Host -f yellow "`nPlease update the entry:`n"
Write-Host -f yellow "📜 Enter Title ($($existing.Title)): " -n; $title = Read-Host; if ([string]::IsNullOrEmpty($title)) {$title = $existing.Title}
Write-Host -f yellow "🆔 Username ($($existing.Username)): " -n; $username = Read-Host; if ([string]::IsNullOrEmpty($username)) {$username = $existing.Username}

# Choose which password to use.
Write-Host -f green "🔐 Do you want to keep the original password or use the new one you just entered? (new/old) " -n; $keep = Read-Host
if ($keep -match "^(?i)old$") {$secure = $existing.Password}
elseif ($keep -match "^(?i)new$") {}
else {$script:warning = "Invalid choice. Aborting."; nomessage; rendermenu; return}

Write-Host -f yellow "🔗 URL ($($existing.URL)): " -n; $url = Read-Host; if ([string]::IsNullOrEmpty($url)) {$url = $existing.URL}
Write-Host -f yellow "🏷️ Tags ($($existing.tags)): " -n; $tags = Read-Host; if ([string]::IsNullOrEmpty($tags)) {$tags = $existing.tags}
Write-Host -f yellow "📝 Notes (CTRL-Z + Enter to end): " -n; $notes = [Console]::In.ReadToEnd(); if ([string]::IsNullOrEmpty($notes)) {$notes = $existing.notes}

# Check if it's a real change.
if ($username -eq $existing.Username -and $url -eq $existing.URL -and $tags -eq $existing.tags -and $notes -eq $existing.notes) {Write-Host -f yellow "🤔 No changes detected. Overwrite entry? (Y/N) " -n; $confirmDup = Read-Host

if ($confirmDup -notmatch '^[Yy]') {$script:warning = "Entry not saved."; nomessage; return}}

# Remove old entry and save new.
$entry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Title = $title; Username = $username; Password = $secure; URL = $url; Tags = $tags; Notes = $notes}; $entries = $entries | Where-Object {!($_.Username -eq $username -and $_.URL -eq $url)}; $entries += $entry; $entries | ForEach-Object {$_ | ConvertTo-Json -Depth 3 -Compress} | Set-Content -Path $database; $script:message = "Modified entry saved successfully."; nowarning; return}}

$entry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Title = $title; Username = $username; Password = $secure; URL = $url; Tags = $tags; Notes = $notes}
$entries += $entry; $entries | ForEach-Object {$_ | ConvertTo-Json -Depth 3 -Compress} | Set-Content -Path $database; $script:message = "Entry saved successfully."; nowarning}

function retrieveentry ($database = $script:database, $keyfile = $script:keyfile, $searchterm, [switch]$noclip) {# Retrieve the password for a single entry.

# Validate minimum search length
if ($searchterm.Length -lt 3) {$script:warning = "Requested match is too small. Aborting search."; nomessage; return}

# Decrypt keyfile
nomessage; nowarning
if ($script:unlocked -eq $true) {$key = $script:realKey} else {$key = decryptkey $script:keyfile}
$entrymatches = @()
Get-Content $script:database | ForEach-Object {$line = $_
try {$entry = $line | ConvertFrom-Json}
catch {$fixedLine = $line -replace '"Notes"\s*:\s*"[^"]*"', '"Notes":"[Invalid JSON removed]"'
try {$entry = $fixedLine | ConvertFrom-Json}
catch {Write-Host "Skipped invalid JSON line." -f yellow; return}}

# Match on Title or Username
if ($entry.Title -match $searchterm -or $entry.Url -match $searchterm -or $entry.Tags -match $searchTerm -or $entry.Notes -match $searchterm) {$entrymatches += $entry}}
$total = $entrymatches.Count

# Check matches count
if (-not $key) {$script:warning = "🔑 No key loaded.`n" + $script:warning; nomessage; return}
if ($total -eq 0) {$script:warning = "🔐 No password found for the entry '$searchterm'"; nomessage; return}
elseif ($total -eq 1) {$selected = $entrymatches[0]}
elseif ($total -le 25) {$invalidentry = "`n" 
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $total; $i++) {$m = $entrymatches[$i]
$notesAbbrev = if ($m.Notes.Length -gt 40) {$m.Notes.Substring(0,37) + "..."} else {$m.Notes}; $notesAbbrev = $notesAbbrev -replace "\r?\n?", "";
$urlAbbrev = if ($m.URL.Length -gt 45) {$m.Notes.Substring(0,42) + "..."} else {$m.URL}
$tagsAbbrev = if ($m.tags.Length -gt 42) {$m.tags.Substring(0,39) + "..."} else {$m.tags}
Write-Host -f Cyan "$($i + 1). ".padright(4) -n; Write-Host -f yellow "📜 Title: " -n; Write-Host -f white $($m.Title).padright(38) -n; Write-Host -f yellow " 🆔 User: " -n; Write-Host -f white $($m.Username).padright(30) -n; Write-Host -f yellow " 🔗 URL: " -n; Write-Host -f white $urlAbbrev.padright(46); Write-Host -f yellow "🏷️ Tags:  "-n; Write-Host -f white $tagsAbbrev.padright(42) -n; Write-Host -f yellow " 📝 Notes: " -n; Write-Host -f white $notesAbbrev; Write-Host -f gray ("-" * 100)}
Write-Host -f red $invalidentry; Write-Host -f yellow "🔍 Select an entry to view or Enter to cancel: " -n; $choice = Read-Host
if ($choice -eq "") {$script:warning = "Password retrieval cancelled by user."; nomessage; return}
$parsedChoice = 0; $refParsedChoice = [ref]$parsedChoice
if ([int]::TryParse($choice, $refParsedChoice) -and $refParsedChoice.Value -ge 1 -and $refParsedChoice.Value -le $total) {$selected = $entrymatches[$refParsedChoice.Value - 1]; break}
else {$invalidentry = "`nInvalid entry. Try again."}}
while ($true)}
else {$script:warning = "Too many matches ($total). Please enter a more specific search."; nomessage; return}

# Decrypt password field
$plain = "🚫 <no password saved> 🚫"
if ($selected.Password -and $selected.Password -ne "") {try {$secure = $selected.Password | ConvertTo-SecureString -Key $key; $plain = [System.Net.NetworkCredential]::new("", $secure).Password}
catch {$plain = "⚠️ <unable to decrypt password> ⚠️"}}

# Copy to clipboard unless -noclip switch is set
if ($script:noclip -eq $false) {$plain | Set-Clipboard; clearclipboard}

# Compose output message
$script:message = "`n🗓️ Creation Date: $($selected.Timestamp)`n📜 Title:         $($selected.Title)`n🆔 UserName:      $($selected.Username)`n🔐 Password:      $plain`n🔗 URL:           $($selected.URL)`n🏷️ Tags:          $($selected.Tags)`n📝 Notes:         $($selected.Notes)"; nowarning}

function newkey ($keyfile = $script:keyfile) {# Create an AES key, protected with a master password.
if (-not $script:keyfile) {$script:warning = "No key file identified."; nomessage}

# Generate AES key
$aesKey = New-Object byte[] 32; [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)

# Prepend magic marker "SCHV"
$marker = [System.Text.Encoding]::UTF8.GetBytes("SCHV"); $keyWithMarker = $marker + $aesKey

$script:keyfile = Join-Path $script:keydir $script:keyfile
if (Test-Path $script:keyfile) {$script:warning = "That key file already exists."; nomessage; rendermenu; return}

$script:unlocked = $false; Write-Host -f yellow "🔐 Enter a master password to protect your key:" -n; $secureMaster = Read-Host -AsSecureString; $master = [System.Net.NetworkCredential]::new("", $secureMaster).Password

# Generate salt and derive key using PBKDF2
$salt = New-Object byte[] 16; [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($salt); $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($master, $salt, 10000); $protectKey = $pbkdf2.GetBytes(32)

# Encrypt keyWithMarker using protectKey
$aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $protectKey; $aes.GenerateIV(); $iv = $aes.IV; $encryptor = $aes.CreateEncryptor(); $encryptedKey = $encryptor.TransformFinalBlock($keyWithMarker, 0, $keyWithMarker.Length)

# Store salt + IV + ciphertext
$output = [byte[]]($salt + $iv + $encryptedKey); [IO.File]::WriteAllBytes("$script:keyfile", $output); $script:message = "Encrypted AES key created."; $script:keyexists = $true; $script:disablelogging = $false; nowarning}

function importcsv ($csvpath, $database = $script:database, $keyfile = $script:keyfile) {# Import CSV file into database.

# Error-checking.
$key = decryptkey $keyfile
if (-not $key) {$script:warning = "Key decryption failed. Aborting import."; nomessage; return}

# Load current entries.
$entries = @()
if (Test-Path $database) {$entries = @(Get-Content $database | ForEach-Object {$_ | ConvertFrom-Json})}
$imported = Import-Csv $csvpath
$requiredFields = @('Title', 'Username', 'Password', 'URL'); $optionalFields = @('Notes', 'Tags')

# Detect extra fields not accounted for.
$csvFields = $imported[0].PSObject.Properties.Name; $extraFields = $csvFields | Where-Object {$requiredFields -notcontains $_ -and $_ -notin @('Timestamp','Notes','Tags')}; $fieldAppendNotes = @{}; $fieldTagMode = @{}
if ($extraFields.Count -gt 0) {foreach ($field in $extraFields) {Write-Host -f green "`nExtra field detected: " -n; Write-Host -f white "$field"; Write-Host -f yellow "Append '" -n; Write-Host -f white "$field" -n; Write-Host -f yellow "' to Notes? (Y/N) " -n;$appendNoteAns = Read-Host; $fieldAppendNotes[$field] = ($appendNoteAns.ToUpper() -eq 'Y'); Write-Host -f cyan "Add '" -n; Write-Host -f white "$field" -n; Write-Host -f cyan "' as a tag? (Y/N) " -n;$addTagAns = Read-Host
if ($addTagAns.ToUpper() -eq 'Y') {Write-Host -f cyan "Add tag to all or only populated entries? " -n; Write-Host -f white "([A]ll/[P]opulated) " -n; $mode = Read-Host
if ($mode -and ($mode.ToLower() -in @('a','p'))) {$fieldTagMode[$field] = $mode.ToLower()}
else {Write-Host -f red "Invalid option. Skipping tag for '$field'."; $fieldTagMode[$field] = 'none'}}}}

# Track tags added counts per extra field for summary.
$tagAddCounts = @{}; foreach ($field in $extraFields) {$tagAddCounts[$field] = 0}; $added = 0; $skipped = 0; $overwritten = 0; $duplicates = 0
foreach ($entry in $imported) {# Reset variables for each iteration
$title = $null; $username = $null; $plainPassword = $null; $url = $null; $notes = $null; $tags = $null

# Ensure required fields exist, add if missing.
if (-not $entry.PSObject.Properties.Name -contains 'Title') {$entry | Add-Member -MemberType NoteProperty -Name Title -Value ""}
if (-not $entry.PSObject.Properties.Name -contains 'Username') {Write-Host -f red "Skipping entry: Missing Username"; $skipped++; continue}
if (-not $entry.PSObject.Properties.Name -contains 'Password') {$entry | Add-Member -MemberType NoteProperty -Name Password -Value ""}
if (-not $entry.PSObject.Properties.Name -contains 'URL') {Write-Host -f red "Skipping entry: Missing URL"; $skipped++; continue}
if (-not $entry.PSObject.Properties.Name -contains 'Notes') {$entry | Add-Member -MemberType NoteProperty -Name Notes -Value ""}
if (-not $entry.PSObject.Properties.Name -contains 'Tags') {$entry | Add-Member -MemberType NoteProperty -Name Tags -Value ""}
$title = if ($entry.Title -is [string] -and $entry.Title.Trim()) {$entry.Title.Trim()} else {""}
$username = if ($entry.username -is [string] -and $entry.username.Trim()) {$entry.username.Trim()} else {""}
$plainPassword = $entry.Password  # this one is OK as-is
$url = if ($entry.url -is [string] -and $entry.url.Trim()) {$entry.url.Trim()} else {""}
$notes = if ($entry.Notes) {$entry.Notes.Trim()} else {""}
$tags = if ($entry.Tags) {$entry.Tags.Trim()} else {""}

# Validate required non-empty fields: Username and URL.
if ([string]::IsNullOrWhiteSpace($username)) {Write-Host -f cyan "`nUsername is empty for an entry (Title: '" -n; Write-Host -f white "$title" -n; Write-Host -f cyan "', URL: '" -n; Write-Host -f white "$url" -n; Write-Host -f cyan "'). Enter a Username or press Enter to skip: " -n; $username = Read-Host 
if ([string]::IsNullOrWhiteSpace($username)) {Write-Host -f yellow "Skipping entry due to empty Username."; $skipped++; continue}}

if ([string]::IsNullOrWhiteSpace($url)) {Write-Host -f cyan "`nURL is empty for an entry (Title: '" -n; Write-Host -f white "$title" -n; Write-Host -f cyan "', Username: '" -n; Write-Host -f white "$username" -n; Write-Host -f cyan "'). Enter a URL or press Enter to skip: " -n; $url = Read-Host 
if ([string]::IsNullOrWhiteSpace($url)) {Write-Host -f yellow "Skipping entry due to empty URL."; $skipped++; continue}}

# If Title is empty, try to extract domain from URL.
if ([string]::IsNullOrWhiteSpace($title)) {$domain = if ($url -match '(?i)^(HTTPS?:\/\/)?(WWW\.)?(([A-Z\d-]+\.)*[A-Z\d-]+\.[A-Z]{2,10})(\W|$)') {$matches[3].ToLower()} else {""}
if ([string]::IsNullOrWhiteSpace($domain)) {Write-Host -f cyan "`nTitle is missing and could not auto-extract from URL: " -n; Write-Host -f white "$url" -n; Write-Host -f cyan ". Please enter a Title or press Enter to skip: " -n; $title = Read-Host
if ([string]::IsNullOrWhiteSpace($title)) {Write-Host -f yellow "Skipping entry due to missing Title."; $skipped++; continue}}
else {$title = $domain; Write-Host -f yellow "Title auto-set to domain: " -n; Write-Host -f white "$title"}}

# Append extra fields to Notes if requested.
foreach ($field in $extraFields) {if ($entry.PSObject.Properties.Name -contains $field) {$val = $entry.$field
if (-not [string]::IsNullOrWhiteSpace($val) -and $fieldAppendNotes[$field]) {$notes += "`n$field`: $val"}}}

# Add tags for extra fields.
foreach ($field in $extraFields) {if ($fieldTagMode[$field] -ne 'none' -and $entry.PSObject.Properties.Name -contains $field) {$val = $entry.$field; $shouldAdd = $false
switch ($fieldTagMode[$field]) {'a' {$shouldAdd = $true}
'p' {$shouldAdd = -not [string]::IsNullOrWhiteSpace($val)}}
if ($shouldAdd) {$existingTags = $tags -split ',\s*' | Where-Object {$_ -ne ''}
if (-not ($existingTags -contains $field)) {$tags = if ([string]::IsNullOrWhiteSpace($tags)) {$field}
else {"$tags,$field"}
$tagAddCounts[$field]++}}}}

# Check for duplicates by Username and URL.
$match = $entries | Where-Object {$_.Username -eq $username -and $_.URL -eq $url}
if ($match) {$duplicates++; Write-Host -f yellow "`nDuplicate detected for 🆔 '" -n; Write-Host -f white "$username" -n; Write-Host -f yellow "' at 🔗 '" -n; Write-Host -f white "$url" -n; Write-Host -f yellow "'`n"; Write-Host -f cyan "📜 Title: " -n; Write-Host -f white "$($match.Title)" -n; Write-Host -f cyan " => " -n; Write-Host -f white "$title"; Write-Host -f cyan "🏷️  Tags: " -n; Write-Host -f white "$($match.Tags)" -n; Write-Host -f cyan " => " -n; Write-Host -f white "$tags"; Write-Host -f cyan "📝 Notes: " -n; Write-Host -f white "$($match.Notes)" -n; Write-Host -f cyan " => " -n; Write-Host -f white "$notes"; Write-Host -f white "`nOptions: (S)kip / (O)verwrite / (K)eep both [default: Keep]: " -n; $choice = Read-Host
switch ($choice.ToUpper()) {"O" {$entries = $entries | Where-Object {$_ -ne $match}; Write-Host -f red "`nOverwritten."; $overwritten++}
"S" {Write-Host -f red "`nSkipping entry."; $skipped++; continue}
"K" {Write-Host -f green "`nKeeping both."}
default {Write-Host -f green "`nKeeping both."}}}

# Encrypt password, but allow empty values.
if ([string]::IsNullOrWhiteSpace($plainPassword)) {Write-Host -f yellow "`nEntry for 🆔 '" -n; Write-Host -f white "$username" -n; Write-Host -f yellow "' at 🔗 '" -n; Write-Host -f white "$url" -n; Write-Host -f yellow "' has no password. Adding with 🚫 empty password."; $encryptedPassword = ""}
else {$securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force; $encryptedPassword = $securePassword | ConvertFrom-SecureString -Key $key}

$newEntry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Title = $title; Username = $username; Password = $encryptedPassword; URL = $url; Tags = $tags; Notes = $notes}
$entries += $newEntry; $added++}

# Save updated database.
$entries | ForEach-Object {$_ | ConvertTo-Json -Compress} | Set-Content -Path $database -Encoding UTF8

# Summary.
Write-Host -f green "`n✅ Import complete.`n"; Write-Host -f yellow "New entries added:" -n; Write-Host -f white " $added"; Write-Host -f gray "Duplicates skipped:" -n; Write-Host -f white " $skipped"; Write-Host -f red "Overwritten entries:" -n; Write-Host -f white " $overwritten"; Write-Host -f yellow "Total duplicates:" -n; Write-Host -f white " $duplicates"

$tagsAdded = ($tagAddCounts.GetEnumerator() | Where-Object {$_.Value -gt 0})
if ($tagsAdded.Count -gt 0) {Write-Host -f yellow "Tag types added:" -n; Write-Host -f white " $($tagsAdded.Count)"
Write-Host -f yellow "Tags added:" -n; Write-Host -f white " $($tagsAdded.Name -join ', ')"}; Write-Host -f cyan "`n↩️Return" -n; Read-Host}

function export ($path, $fields) {# Export current database to a CSV file.
if (-not $script:database) {$script:warning = "No database is currently loaded in memory."; nomessage; rendermenu; return}

$validFields = 'Timestamp','Title','Username','Password','URL','Tags','Notes'; $fieldList = $Fields -split ',' | ForEach-Object {$_.Trim()}; $invalidFields = $fieldList | Where-Object { $_ -notin $validFields }
if ($invalidFields) {$script:warning = "Invalid field(s): $($invalidFields -join ', ')"; $script:message = "Allowed fields: $($validFields -join ', ')"; return}

$entries = Get-Content $script:database | ForEach-Object {if ($_ -match '\S') {try { ConvertFrom-Json $_ } catch { Write-Warning "Skipping invalid JSON line: $_"}}}
if (-not $entries) {$script:warning = "No valid entries found in the JSON database."; nomessage; return}

$filtered = $entries | ForEach-Object {$obj = [ordered]@{}
foreach ($field in $fieldList) {$obj[$field] = $_.$field}
[pscustomobject]$obj}

$filtered | Export-Csv -Path $Path -NoTypeInformation -Force
if ($path -match '(?i)((\\[^\\]+){2}\\\w+\.CSV)') {$shortname = $matches[1]}; $script:message = "Exported JSON database to: $shortname"; nowarning; rendermenu; return}

function backup {# Backup currently loaded key and database pair to the database directory.
$script:message = $null; $script:warning = $null; $baseName = [System.IO.Path]::GetFileNameWithoutExtension($script:database); $timestamp = Get-Date -Format "MM-dd-yyyy @ HH_mm_ss"; $zipName = "$baseName ($timestamp).zip"; $zipPath = Join-Path $script:databasedir $zipName

try {$tempDir = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $tempDir | Out-Null
Copy-Item $script:database -Destination $tempDir; Copy-Item $script:keyfile -Destination $tempDir; Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath $zipPath -Force; Remove-Item $tempDir -Recurse -Force; $script:message = "Backup created: $zipName"; nowarning} catch {$script:warning = "Backup failed: $_"; nomessage}; return}

function restore {# Restore a backup.
$script:message = $null; $script:warning = $null

# Find backup files matching "<Name> (mm-dd-yyyy @ hh_mm_ss).zip".
$pattern = '^[A-Za-z0-9_]+ \(\d{2}-\d{2}-\d{4} @ \d{2}_\d{2}_\d{2}\)\.zip$'
$backups = Get-ChildItem -Path $script:databasedir -Filter '*.zip' | Where-Object { $_.Name -match $pattern } | Sort-Object Name

if (-not $backups) {$script:warning = "No backup files found in: $script:databasedir"; nomessage; return}

# Present numbered list in cyan (number) / white (filename).
Write-Host -f yellow "`nAvailable backups:`n"
for ($i = 0; $i -lt $backups.Count; $i++) {Write-Host -f cyan ("{0}. " -f ($i + 1)) -n; Write-Host  -f white $backups[$i].Name}

# Prompt user for selection.
Write-Host -f yellow "`nSelect a backup to restore (1-$($backups.Count)) " -n; $selection = Read-Host
if (-not [int]::TryParse($selection, [ref]$null) -or $selection -lt 1 -or $selection -gt $backups.Count) {$script:warning = "Invalid selection. Restore aborted."; nomessage; return}

$chosenFile = $backups[$selection - 1].FullName
try {$tempDir = Join-Path $env:TEMP ([Guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $tempDir | Out-Null; Expand-Archive -Path $chosenFile -DestinationPath $tempDir -Force; $dbLeaf  = Split-Path $script:database -Leaf; $keyLeaf = Split-Path $script:keyfile -Leaf; $extractedDb  = Join-Path $tempDir $dbLeaf; $extractedKey = Join-Path $tempDir $keyLeaf

# Restore PWDB.
$ans = $null
if (Test-Path $extractedDb) {$destDb = Join-Path $script:databasedir $dbLeaf
if (Test-Path $destDb) {Write-Host -f red "Overwrite existing database '$dbLeaf'? (Y/N) " -n; $ans = Read-Host
if ($ans -notmatch '[Yy]$') {$script:warning = "Database file overwrite declined. Restore aborted."; nomessage; Remove-Item $tempDir -Recurse -Force; return}}
Copy-Item -Path $extractedDb -Destination $script:databasedir -Force}
else {$script:warning = "Database file '$dbLeaf' not found inside ZIP."; Remove-Item $tempDir -Recurse -Force; return}

# Restore Key.
$ans = $null
if (Test-Path $extractedKey) {$destKey = Join-Path $script:keydir $keyLeaf
if (Test-Path $destKey) {Write-Host -f red  "Overwrite existing key file '$keyLeaf'? (Y/N) " -n; $ans = Read-Host
if ($ans -notmatch '[Yy]$')  {$script:warning = "Key file overwrite declined. Restore aborted."; Remove-Item $tempDir -Recurse -Force; return}}
Copy-Item -Path $extractedKey -Destination $script:keydir -Force}
else {$script:warning = "Key file '$keyLeaf' not found inside ZIP."; nomessage; Remove-Item $tempDir -Recurse -Force; return}

# Cleanup and set success message
if ($chosenFile -match '(?i)((\\[^\\]+){2}\\[^\\]+\.ZIP)') {$shortfile = $matches[1]} else {$shortfile = $chosenFile}
Remove-Item $tempDir -Recurse -Force; $script:message = "Restored '$dbLeaf' and '$keyLeaf' from backup: $shortFile"; nowarning; return}
catch {$script:warning = "Restore failed:`n$_"; nomessage
if (Test-Path $tempDir) {Remove-Item $tempDir -Recurse -Force}; return}}

function showentries ($entries, $pagesize = 30, [switch]$expired, [switch]$search, $keywords) {# Browse entire database.
$sortField = $null; $arrow = $null; $descending = $null

# Expired entries filter.
$entries = if ($expired) {$entries | Where-Object {[datetime]$_.Timestamp -lt (Get-Date).AddDays(-$script:expirywarning)}} else {$entries}

# Search filter.
if ($search) {$pattern = "(?i)(" + ($keywords -replace "\s*,\s*", "|") + ")"; $filtered = @()
foreach ($entry in $entries) {$joined = ($entry.PSObject.Properties | ForEach-Object {$_.Value}) -join "`n"
if ($joined -match $pattern) {$filtered += $entry}}; $entries = $filtered}

# Browse.
$total = $entries.Count; $page = 0
if ($total -eq 0) {$script:warning = "No entries to view."; nomessage; rendermenu; return}
while ($true) {cls; if ($sortField) {$entries = if ($descending) {$entries | Sort-Object $sortField -Descending} else {$entries | Sort-Object $sortField}} 
$start = $page * $pagesize; $chunk = $entries[$start..([math]::Min($start + $pagesize - 1, $total - 1))]; 

if ($expired) {Write-Host -f white "Expired Entries: " -n; Write-Host -f gray "The following entries are more than $script:expirywarning days ($((Get-Date).AddDays(-$script:expirywarning).ToShortDateString())) old since last update."; Write-Host -f yellow ("-" * 130)}

$chunk | Select-Object @{Name='Title';Expression={$_.Title}}, @{Name='Username';Expression={$_.Username}}, @{Name='URL';Expression={if ($_.URL.Length -gt 40) {$_.URL.Substring(0, 37) + '...'} else {$_.URL}}}, @{Name='Tags';Expression={if ($_.Tags.Length -gt 35) {$_.Tags.Substring(0, 32) + '...'} else {$_.Tags}}} |
Format-Table -AutoSize; $arrow = if ($descending) {"▾"} else {if (-not $sortfield) {""} else {"▴"}}
Write-Host -f yellow ("-" * 130); Write-Host -f cyan "📑 Page $($page + 1)/$([math]::Ceiling($total / $pagesize))".padright(16) -n; Write-Host -f yellow "| ⏮️(F)irst (P)revious (N)ext (L)ast⏭️ |" -n; Write-Host -f green " Sort by: 📜(T)itle 🆔(U)ser 🔗(W)eb URL 🏷 Ta[G]s" -n; Write-Host -f yellow "| "-n; Write-Host -f green "$arrow $sortField".padright(10) -n; Write-Host -f yellow " | " -n; Write-Host -f cyan "↩️[ESC] " -n

$key = [Console]::ReadKey($true)
switch ($key.Key) {
'F' {$page = 0}; 'HOME' {$page = 0}
'N' {if (($start + $pagesize) -lt $total) {$page++}}; 'PAGEDOWN' {if (($start + $pagesize) -lt $total) {$page++}}; 'DOWNARROW' {if (($start + $pagesize) -lt $total) {$page++}}; 'RIGHTARROW' {if (($start + $pagesize) -lt $total) {$page++}}; 'ENTER' {if (($start + $pagesize) -lt $total) {$page++}}
'P' {if ($page -gt 0) {$page--}}; 'PAGEUP' {if ($page -gt 0) {$page--}}; 'UPARROW' {if ($page -gt 0) {$page--}}; 'LEFTARROW' {if ($page -gt 0) {$page--}}; 'BACKSPACE' {if ($page -gt 0) {$page--}}
'L' {$page = [int][math]::Floor(($total - 1) / $pagesize)}; 'END' {$page = [int][math]::Floor(($total - 1) / $pagesize)}

'T' {if ($sortField -eq "Title") {$descending = -not $descending} else {$sortField = "Title"; $descending = $false}; $page = 0}
'U' {if ($sortField -eq "Username") {$descending = -not $descending} else {$sortField = "Username"; $descending = $false}; $page = 0}
'W' {if ($sortField -eq "URL") {$descending = -not $descending} else {$sortField = "URL"; $descending = $false}; $page = 0}
'G' {if ($sortField -eq "Tags") {$descending = -not $descending} else {$sortField = "Tags"; $descending = $false}; $page = 0}

'Q' {nowarning; nomessage; rendermenu; return}; 'ESCAPE' {nowarning; nomessage; rendermenu; return}
default {}}}}

function removeentry ($database = $script:database, $searchterm) {# Remove an entry.

# Validate minimum search length
if ($searchterm.Length -lt 3) {$script:warning = "Search term too short. Aborting removal."; nomessage; return}

# Load entries
$entries = Get-Content $script:database | ForEach-Object {try {$_ | ConvertFrom-Json}
catch {$fixedLine = $_ -replace '"Notes"\s*:\s*"[^"]*"', '"Notes":"[Invalid JSON removed]"'
try {$fixedLine | ConvertFrom-Json}
catch {return}}}

# Filter matches by Title or URL
$matches = $entries | Where-Object {$_.Title -match $searchterm -or $_.URL -match $searchterm -or $_.Tags -match $searchterm -or $_.Notes -match $searchterm}
$count = $matches.Count
if ($count -eq 0) {$script:warning = "No entries found matching '$searchterm'."; nomessage; return}
elseif ($count -gt 25) {$script:warning = "Too many matches ($count). Please refine your search."; nomessage; return}

# Select entries.
if ($count -eq 1) {$selected = $matches[0]}
else {$invalidentry = "`n"
do {cls; Write-Host -f yellow "`nMultiple matches found:`n"
for ($i = 0; $i -lt $count; $i++) {$m = $matches[$i]
$notesAbbrev = if ($m.Notes.Length -gt 40) {$m.Notes.Substring(0,37) + "..."} else {$m.Notes}; $notesAbbrev = $notesAbbrev -replace "\r?\n?", ""
$urlAbbrev = if ($m.URL.Length -gt 45) {$m.URL.Substring(0,42) + "..."} else {$m.URL}
$tagsAbbrev = if ($m.tags.Length -gt 42) {$m.tags.Substring(0,39) + "..."} else {$m.tags}
Write-Host -f Cyan "$($i + 1). ".PadRight(4) -n; Write-Host -f yellow "📜 Title: " -n; Write-Host -f white $($m.Title).PadRight(38) -n; Write-Host -f yellow " 🆔 User: " -n; Write-Host -f white $($m.Username).PadRight(30) -n; Write-Host -f yellow " 🔗 URL: " -n; Write-Host -f white $urlAbbrev.PadRight(46); Write-Host -f yellow " 🏷 Tags: " -n; Write-Host -f white $tagsAbbrev.padright(42) -n; Write-Host -f yellow " 📝 Notes: " -n; Write-Host -f white $notesAbbrev; Write-Host -f gray ("-" * 100)
}
Write-Host -f red $invalidentry; Write-Host -f yellow "❌ Select an entry to remove or Enter to cancel: " -n; $choice = Read-Host
if ($choice -eq "") {$script:warning = "Entry removal cancelled."; nomessage; return}
$parsedChoice = 0; $refParsedChoice = [ref]$parsedChoice
if ([int]::TryParse($choice, $refParsedChoice) -and $refParsedChoice.Value -ge 1 -and $refParsedChoice.Value -le $count) {$selected = $matches[$refParsedChoice.Value - 1]; break}
else {$invalidentry = "`nInvalid entry. Try again."}}
while ($true)}

# Confirm removal
Write-Host -f cyan "`nYou selected:`n"; Write-Host -f yellow "📜 Title: " -n; Write-Host -f white "$($selected.Title)"; Write-Host -f yellow "🆔 User:  " -n; Write-Host -f white "$($selected.Username)"; Write-Host -f yellow "🔗 URL:   " -n; Write-Host -f white "$($selected.URL)"; Write-Host -f yellow "🏷  Tags:  " -n; Write-Host -f white "$($selected.Tags)"; Write-Host -f yellow "📝 Notes: " -n; Write-Host -f white "$($selected.Notes)"; Write-Host -f cyan "`nType 'YES' to confirm removal: " -n; $confirm = Read-Host; if ($confirm -ne "YES") {$script:warning = "Removal aborted."; nomessage; return}

# Remove entry from file: write back all entries except the selected one
$updatedEntries = $entries | Where-Object {$_ -ne $selected}; $updatedEntries | ForEach-Object {$_ | ConvertTo-Json -Compress} | Set-Content $script:database; $script:message =  "Entry removed successfully."; nowarning}

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
startline; Write-Host -f white "🔑 Secure Password Manager 🔒".padright(53) -n
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
startline; Write-Host -f cyan " B. " -n; Write-Host -f white "🧐 [B]rowse all entries.".padright(66) -n; linecap
startline; Write-Host -f cyan " E. " -n; Write-Host -f white "⌛ [E]xpired entries view.".padright(65) -n; linecap
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
startline; Write-Host -f cyan " I. " -n; Write-Host -f yellow "📥 [I]mport a CSV plaintext password database.".padright(66) -n; linecap
horizontal
startline; Write-Host -f cyan " -. " -n; Write-Host -f white "📤 Export the current database to CSV. " -n; Write-Host -f red "Encryption remains intact. " -n; linecap
startline; Write-Host -f cyan " >. " -n; Write-Host -f white "📦←︎ Backup currently loaded database and key.".padright(67) -n; linecap
startline; Write-Host -f cyan " <. " -n; Write-Host -f white "📦→︎ Restore a backup.".padright(67) -n; linecap
horizontal}

# Session options.
startline; if ($script:unlocked -eq $true) {Write-Host "🔓 " -n} else {Write-Host "🔒 " -n}
if ($script:unlocked -eq $true) {Write-Host -f red "[L]ock Session " -n} else {Write-Host -f darkgray "[L]ock Session " -n}
Write-Host -f white "/ " -n;
if ($script:unlocked -eq $true) {Write-Host -f darkgray "[U]nlock Session".padright(23) -n} else {Write-Host -f green "[U]nlock Session".padright(23) -n}
Write-Host -f yellow "❓ [H]elp.".padright(17) -n; Write-Host -f gray "⏏️ [ESC] " -n;; linecap
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

# Map keys to descriptions.
$choice = $key.Key.ToString().ToUpperInvariant()
$map = @{'A' = 'Add an entry'; 'R' = 'Retrieve an entry'; 'X' = 'Remove an entry'; 'B' = 'Browse entries'; 'E' = 'View expired entries'; 'S' = 'Search entries'; 'L' = 'Lock'; 'U' = 'Unlock'; 'T' = 'Reset timer'; 'O' = 'Restore Default Key & Database'; 'Z' = 'Toggle Clipboard'; 'M' = 'Toggle management view'; 'K' = 'Select a key'; 'C' = 'Create a key'; 'D' = 'Select a database'; 'P' = 'Create a database'; 'V' = 'Verify a PWDB'; 'I' = 'Import a CSV'; 'OEMMINUS' = 'Export to CSV'; 'SUBTRACT' = 'Export to CSV'; 'OEMPERIOD' = 'Backup key and database'; 'OEMCOMMA' = 'Restore a key and database'; 'Q' = 'Quit'; 'H' = 'Help'; 'F1' = 'Help'; 'F4' = 'Toggle logging'; 'BACKSPACE' = 'Clear message center'}
if (-not $map.ContainsKey($choice)) {Add-Content -Path $script:logfile -Value "$(Get-Date -Format 'HH:mm:ss') - UNRECOGNIZED: $choice"; return}

# Create directory, if it doesn't exist.
$script:logdir = Join-Path $PSScriptRoot 'logs'
if (-not (Test-Path $logdir)) {New-Item $logdir -ItemType Directory -Force | Out-Null}

# Cleanup old logs (older than the number of days set in logretention, with the minimum set to 30 days).
Get-ChildItem -Path $logdir -Filter 'log - *.log' | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-[int]$script:logretention)} | Remove-Item -Force

# Create base file each session.
if (-not $script:logfile) {$timestamp = (Get-Date).ToString('MM-dd-yy @ HH_mm_ss'); $script:logfile = Join-Path $logdir "log - $timestamp.log"}

# Compile entry information.
$timestamp = Get-Date -Format 'HH:mm:ss'; $info = "$(if ($message) {" - MESSAGE: $message"})$(if ($warning) {" - WARNING: $warning"})"; $entry = "$timestamp - $($map[$choice])$info`n" + ("-" * 100)

# Ensure log gets written by retrying 5 times for every log, to avoid race conditions.
$retries = 5
for ($i = 0; $i -lt $retries; $i++) {try {$fs = [System.IO.File]::Open($script:logfile, 'Append', 'Write', 'ReadWrite'); $sw = New-Object System.IO.StreamWriter($fs)
$sw.WriteLine($entry); $sw.Close(); $fs.Close(); break}
catch {Start-Sleep -Milliseconds 100}}}

function login {# Display initial login screen.
$script:sessionstart = Get-Date; $key = $null
Write-Host -f yellow "`n+-----------------------------+`n|🔑 Secure Password Manager 🔒|`n|-----------------------------|" -n
$script:key = decryptkey $script:keyfile; return $script:key}

function loginfailed {# Login failed.
Write-Host -f yellow "+-----------------------------+`n|" -n; Write-Host -f red "😲 Access Denied! ABORTING!🔒" -n; Write-Host -f yellow "|`n+-----------------------------+`n"; return}

function logoff {# Exit screen.
nowarning; nomessage; $choice=$null; rendermenu; Write-Host -f white "`n`t`t    ____________________`n`t`t   |  ________________  |`n`t`t   | |                | |`n`t`t   | |   🔒 "-n; Write-Host -f red "Locked." -n; Write-Host -f white "   | |`n`t`t   | |                | |`n`t`t   | |________________| |`n`t`t   |____________________|`n`t`t    _____|_________|_____`n`t`t   / * * * * * * * * * * \`n`t`t  / * * * * * * * * * * * \`n`t`t ‘-------------------------’`n"; return}

function loggedin {# Once key is unlocked, allow access to the dynamic menu.
$script:sessionstart = Get-Date; $choice = $null
rendermenu

do {# Wait for a keypress, which would refresh the screen and refresh it at the necessary times in between.
while (-not [Console]::KeyAvailable -and -not $script:quit) {
# End function, upon user request.
if ($script:quit) {return}

# Set session timer variables.
$timeout = (Get-Date).AddSeconds(10); $countdown = [int]($script:timeoutseconds - ((Get-Date) - $script:sessionstart).TotalSeconds); if ($countdown -lt 0) {$countdown = 0}; $script:minutes = [int]([math]::Floor($countdown / 60)); $script:seconds = $countdown % 60

# Lock session when timer runs out and break from continual refreshes.
if ($script:unlocked -eq $true -and $countdown -le 0) {$script:unlocked = $false; $script:message = "Session timed out. The key has been locked."; rendermenu; break}

# Refresh display if session is unlocked
if ($script:unlocked -and ($countdown -lt 60 -or $script:minutes -lt $script:lastrefresh)) {rendermenu; $script:lastrefresh = $script:minutes}

# Wait for next loop.
if ($countdown -gt 60) {Start-Sleep -Milliseconds 250}
else {Start-Sleep -Seconds 1}}

# Sent key presses to the menu for processing.
if ([Console]::KeyAvailable -and -not $script:quit) {$key = [Console]::ReadKey($true); $choice = $key.Key.ToString().ToUpper()

logchoices $choice $script:message $script:warning
switch ($choice) {
'A' {# Add a new entry.
if ($script:database -and $script:keyfile -and $script:unlocked) {newentry $script:database $script:keyfile; rendermenu}
else {$script:warning = "A database and key must be opened and unlocked to add an entry."; nomessage}
rendermenu}

'R' {# Retrieve an entry.
if (-not $script:keyfile) {$script:warning = "🔑 No key loaded."; nomessage}
if ($script:database) {Write-Host -f green "`n`n🔓 Enter Title, 🔗 URL, 🏷  Tag or 📝 Note to identify entry: " -n; $searchterm = Read-Host; retrieveentry $script:database $script:keyfile $searchterm}
if (-not $script:database) {$script:warning = "📑 No database loaded. " + $script:warning; nomessage}; 
rendermenu}

'X' {# Remove an entry.
Write-Host -f green "`n`n❌ Enter Title, URL, Tag or Note to identify entry: " -n; $searchterm = Read-Host; removeentry $script:database $searchterm; rendermenu}

'B' {# Browse all entries.
$entries = [System.Collections.ArrayList]::new()
if (-not $script:database) {$script:warning = "No database loaded."; nomessage; rendermenu}
if ($script:database) {Get-Content $script:database | ForEach-Object {try {$obj = $_ | ConvertFrom-Json
if ($obj) {$entries.Add($obj) | Out-Null}}
catch {Write-Host -f red "`nSkipping an invalid JSON line. Please check the file for corruption or incorrectly formatted entries.`nIf you make changes to the file, those lines will be lost."}}
if (-not $entries.Count) {$script:warning = "No valid entries found to display."; nomessage}
showentries $entries; nomessage; nowarning}}

'E' {# Retrieve expired entries.
$entries = [System.Collections.ArrayList]::new()
if (-not $script:database) {$script:warning = "No database loaded."; nomessage; rendermenu}
if ($script:database) {Get-Content $script:database | ForEach-Object {try {$obj = $_ | ConvertFrom-Json
if ($obj) {$entries.Add($obj) | Out-Null}}
catch {Write-Host -f red "`nSkipping an invalid JSON line. Please check the file for corruption or incorrectly formatted entries.`nIf you make changes to the file, those lines will be lost."}}
if (-not $entries.Count) {$script:warning = "No valid entries found to display."; nomessage}
showentries $entries -expired; nomessage; nowarning}}

'S' {# Search for keyword matches.
$entries = [System.Collections.ArrayList]::new()
if (-not $script:database) {$script:warning = "No database loaded."; nomessage; rendermenu}
if ($script:database) {Write-Host -f yellow "`n`nProvide a comma separated list of keywords to find: " -n; $keywords = Read-Host
if ($keywords.length -eq 0) {$script:warning = "No search terms provided."; nomessage}
Get-Content $script:database | ForEach-Object {try {$obj = $_ | ConvertFrom-Json
if ($obj) {$entries.Add($obj) | Out-Null}}
catch {Write-Host -f red "`nSkipping an invalid JSON line. Please check the file for corruption or incorrectly formatted entries.`nIf you make changes to the file, those lines will be lost."}}
if (-not $entries.Count) {$script:warning = "No valid entries found to display."; nomessage}
showentries $entries -search -keywords $keywords; nomessage; nowarning}}

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
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $script:keyfiles.Count) {$script:keyfile = $script:keyfiles[$sel - 1].FullName; $script:keyexists = $true; nowarning; $key = $null; $script:unlocked = $false; $key = decryptkey $script:keyfile; if ($script:keyfile -match '(?i)((\\[^\\]+){2}\\\w+\.KEY)') {$shortkey = $matches[1]} else {$shortkey = $script:keyfile} $script:message = "$shortkey selected and made active."; $script:disablelogging = $false
if (-not $key) {$script:warning += " Key decryption failed. Aborting."; nomessage}}}; rendermenu}

'C' {# Create a new password encryption key.
managementisdisabled
Write-Host -f green "`n`n🔑 Enter filename for new keyfile: " -n; $getkey = Read-Host
if ($getkey -lt 1) {$script:warning = "No filename entered."; nomessage; rendermenu}
else {if (-not $getkey.EndsWith(".key")) {$getkey += ".key"}
$script:keyfile = $getkey
newkey $script:keyfile; $rendermenu}}

'D' {# Select a different database.
managementisdisabled
$dbFiles = Get-ChildItem -Path $script:databasedir -Filter *.pwdb
if (-not $dbFiles) {$script:warning = "No .pwdb files found."; nomessage; rendermenu}
else {Write-Host -f white "`n`n📑 Available Password Databases:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $dbFiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $dbFiles[$i].Name}
Write-Host -f green "`n📑 Enter number of the database file to use: " -n; $sel = Read-Host
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $dbFiles.Count) {$script:database = $dbFiles[$sel - 1].FullName; $dbloaded = $script:database -replace '.+\\Modules\\', ''; $script:message = "$dbloaded selected and made active."; nowarning}
else {$script:warning = "Invalid selection."; nomessage}; rendermenu}}

'P' {# Create a new password database.
managementisdisabled
Write-Host -f green "`n`n📄 Enter filename for new password database: " -n; $getdatabase = Read-Host
if ($getdatabase.length -lt 1) {$script:warning = "No filename entered."; nomessage; rendermenu}
else {if (-not $getdatabase.EndsWith(".pwdb")) {$getdatabase += ".pwdb"}
$path = Join-Path $script:databasedir $getdatabase
if (Test-Path $path) {$script:warning = "File already exists. Choose a different name."; nomessage}
else {New-Item -Path $path -ItemType File | Out-Null; if ($script:database -match '(?i)((\\[^\\]+){2}\\\w+\.PWDB)') {$shortdb = $matches[1]} else {$shortdb = $script:database}; $script:message = "$shortdb created and made active."; nowarning; $script:database = $path}; rendermenu}}

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
elseif (Test-Path $csvpath -ErrorAction SilentlyContinue) {importcsv $csvpath $script:database $script:keyfile}
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

'OEMPERIOD' {# Backup current database and key.
managementisdisabled
backup; rendermenu}

'OEMCOMMA' {# Retore a backup.
managementisdisabled
restore; rendermenu}

'L' {# Lock session.
$script:message = "Session locked."; nowarning; $script:unlocked = $false; if ($script:noclip -eq $false) {clearclipboard 0 64}; rendermenu}

'U' {# Unlock session.
if ($script:keyfile) {""; $key = decryptkey $script:keyfile}
else {$script:warning = "🔑 No key loaded."; nomessage}
if ($script:unlocked) {$script:message = "Session unlocked."}; nowarning; rendermenu}

'Z' {# Toggle clipboard.
if ($script:noclip -eq $true) {$script:noclip = $false; $script:message = "Retrieved passwords will be copied to the clipboard for $script:delayseconds seconds."; nowarning; rendermenu}
elseif ($script:noclip -eq $false) {$script:noclip = $true; $script:message = "Retrieved passwords will not be copied to the clipboard."; nowarning; rendermenu}}

'Q' {# Quit. (Includes funky logic to capture keys after the user confirms.)
Write-Host -f green "`n`nAre you sure you want to quit? (Y/N) " -n; $confirmquit = Read-Host
if ($confirmquit -notmatch "^[Yy]$") {$script:warning = "Aborted."; nomessage; rendermenu}
else {$script:quit = $true; logoff; while ([Console]::KeyAvailable) {return}; return}}

'H' {# Help.
nowarning
$script:message = "❓ Usage: pwmanage <database.pwdb> <keyfile.key> -noclip`n
`n
If no database/keyfile are specified, the defaults `"secure.pwdb`" and `"secure.key`" will be used.`n
`n
When a password is retrieved, it will automatically be copied to the clipboard for 30 seconds, unless the -noclip option is used at launch time.`n
`n
You can configure the default password, default key file and directories where these are saved by modifying the entries in the `"Secure.psd1`" file located in the same directory as the module.`n
`n
You can also set the clipboard timer length, session timer and default expiration time of entries in this file, as well.`n
`n
It is of course, best practice to save the key files somewhere distant from the databases. You could even save the database files on cloud storage, but I recommended saving the keys locally.`n
`n
The import function is extremely powerful, accepting non-standard fields such as tags and/or notes. Press 'I' in management mode for more details.
`n
The initial configurations of the directories within the PSD1 file point to: `"DefaultPowerShellDirectory\Modules\Secure\keys`" and `"DefaultPowerShellDirectory\Modules\Secure\databases`". The term `"DefaultPowerShellDirectory`" though, is a placeholder that is evaluated within the module, redirecting these to your personal PowerShell directory. As stated above, I advise moving these somewhere else once you've setup the database and plan to use it long-term.`n
`n
You can now use F4 to disable logging for the currently loaded key, but only while it's loaded."; if ($script:keyexists -eq $false) {$script:warning = "First time use: You will need to create key and database files with the options above. The defaults configured in the PSD1 file use the filename `"secure`" for both."}; rendermenu}

'F1' {# Help.
nowarning
$script:message = "❓ Usage: pwmanage <database.pwdb> <keyfile.key> -noclip`n
`n
If no database/keyfile are specified, the defaults `"secure.pwdb`" and `"secure.key`" will be used.`n
`n
When a password is retrieved, it will automatically be copied to the clipboard for 30 seconds, unless the -noclip option is used at launch time.`n
`n
You can configure the default password, default key file and directories where these are saved by modifying the entries in the `"Secure.psd1`" file located in the same directory as the module.`n
`n
You can also set the clipboard timer length, session timer and default expiration time of entries in this file, as well.`n
`n
It is of course, best practice to save the key files somewhere distant from the databases. You could even save the database files on cloud storage, but I recommended saving the keys locally.`n
`n
The import function is extremely powerful, accepting non-standard fields such as tags and/or notes. Press 'I' in management mode for more details.
`n
The initial configurations of the directories within the PSD1 file point to: `"DefaultPowerShellDirectory\Modules\Secure\keys`" and `"DefaultPowerShellDirectory\Modules\Secure\databases`". The term `"DefaultPowerShellDirectory`" though, is a placeholder that is evaluated within the module, redirecting these to your personal PowerShell directory. As stated above, I advise moving these somewhere else once you've setup the database and plan to use it long-term.`n
`n
You can now use F4 to disable logging for the currently loaded key, but only while it's loaded."; if ($script:keyexists -eq $false) {$script:warning = "First time use: You will need to create key and database files with the options above. The defaults configured in the PSD1 file use the filename `"secure`" for both."}; rendermenu}

'ESCAPE' {# Quit. (Includes funky logic to capture keys after the user confirms.)
Write-Host -f green "`n`nAre you sure you want to quit? (Y/N) " -n; $confirmquit = Read-Host
if ($confirmquit -notmatch "^[Yy]$") {$script:warning = "Aborted."; nomessage; rendermenu}
else {$script:quit = $true; logoff; while ([Console]::KeyAvailable) {return}; return}}

'T' {# Set Timer.
if (-not $script:keyfile -or -not $script:unlocked) {$script:warning = "You must have a key loaded and unlocked to reset its timer."; nomessage; rendermenu}
else {$script:unlocked = $false; ""; $key = decryptkey $script:keyfile
if (-not $script:unlocked) {rendermenu}
if ($script:unlocked) {Write-Host -f yellow "`nHow many minutes should the session remain unlocked? (1-99) " -n; $usersetminutes = Read-Host; if ($usersetminutes -as [int] -and [int]$usersetminutes -ge 1 -and [int]$usersetminutes -le 99) {$script:timeoutseconds = [int]$usersetminutes * 60; $script:sessionstart = Get-Date; while ([Console]::KeyAvailable) {[Console]::ReadKey($true) > $null}; $script:lastrefresh = 99; rendermenu}
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

default {if ($choice.length -gt 0) {$script:warning = "'$choice' is an invalid choice. Try again."}}}

$script:sessionstart = Get-Date  # Reset on key press
$choice = $null}} while (-not $script:quit)}

#------------------------ Verify password before allowing access. ------------------------------------
initialize; setdefaults; login
if (-not $script:key) {loginfailed}
else {loggedin}}

Export-ModuleMember -Function pwmanage
