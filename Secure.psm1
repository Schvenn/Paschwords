# Load the user configuration.
$powershell = Split-Path $profile
$baseModulePath = Join-Path $powershell "Modules\Secure"; $configPath = Join-Path $baseModulePath "Secure.psd1"
if (!(Test-Path $configPath)) {throw "Config file not found at $configPath"}
$config = Import-PowerShellDataFile -Path $configPath
$keydir = $config.PrivateData.keydir; $script:databasedir = $config.PrivateData.databasedir; $defaultkey = $config.PrivateData.defaultkey; $defaultdatabase = $config.PrivateData.defaultdatabase

$keydir = $keydir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell)
$databasedir = $databasedir -replace 'DefaultPowerShellDirectory', [regex]::Escape($powershell)


$defaultkey = Join-Path $keydir $defaultkey; $defaultdatabase = Join-Path $script:databasedir $defaultdatabase; $script:message = $null; $script:warning = $null

function pwmanage ($script:database, $script:keyfile, [switch]$noclip) {# Password Manager.

# Check database validity.
if (-not $script:database) {$script:database = $defaultdatabase}
if ($script:database) {if (-not [System.IO.Path]::IsPathRooted($script:database)) {$script:database = Join-Path $script:databasedir $script:database}}

# Check key validity, but allow the menu to load, even if there is no default key.
$script:keyexists = $true
if (-not $script:keyfile) {$script:keyfile = $defaultkey}
if ($script:keyfile -and -not [System.IO.Path]::IsPathRooted($script:keyfile)) {$script:keyfile = Join-Path $keydir $script:keyfile}
if (-not (Test-Path $script:keyfile) -and -not (Test-Path $defaultkey)) {$script:keyexists = $false; $script:keyfile = $null; $script:database = $null}

function verifystore ($script:database, $script:keyfile) {# Verify that a Password store and Keyfile exist.
if (-not (Test-Path "$script:database")) {$script:warning = "Password store not found."; $script:database = $null
if (-not (Test-Path "$script:keyfile")) {$script:warning += " Keyfile also not found."; $script:keyfile = $null}; $script:message = $null; return}}
verifystore $script:database $script:keyfile

function clearclipboard {param ([int]$DelaySeconds = 30, [int]$JunkLength = 64)
Start-Job -ScriptBlock {param($delay, $length); Start-Sleep -Seconds $delay; $junk = -join ((33..126) | Get-Random -Count $length | ForEach-Object {[char]$_}); Set-Clipboard -Value $junk; Start-Sleep -Milliseconds 500; Set-Clipboard -Value $null} -ArgumentList $DelaySeconds, $JunkLength | Out-Null}

function decryptkey ($script:keyfile) {# Decrypt keyfile.
$encPath = "$script:keyfile"; $script:message = $null; $script:warning = $null
if (-not (Test-Path $encPath)) {$script:warning = "Encrypted key file not found."; $script:message = $null}
$raw = [IO.File]::ReadAllBytes($encPath); $salt = $raw[0..15]; $iv = $raw[16..31]; $cipher = $raw[32..($raw.Length - 1)]; Write-Host -f green "`nPassword: " -n; $secureMaster = Read-Host -AsSecureString; $master = [System.Net.NetworkCredential]::new("", $secureMaster).Password; $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($master, $salt, 10000); $protectKey = $pbkdf2.GetBytes(32); $aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $protectKey; $aes.IV = $iv; $decryptor = $aes.CreateDecryptor()
try {$decrypted = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length); $marker = [System.Text.Encoding]::UTF8.GetString($decrypted[0..3])
if ($marker -ne "SCHV") {throw "`nMarker mismatch`n"}
$realKey = $decrypted[4..($decrypted.Length - 1)]; return $realKey}
catch {$script:warning = "Incorrect master password or corrupted key file.`nClearing key and database settings to avoid data corruption."; $script:message = $null; $script:keyfile = $null; $script:database = $null}}

# Verify password before allowing access.
if ($script:keyexists -eq $true) {$key = $null; $key = decryptkey $script:keyfile; if (-not $key) {Write-Host -f red "Decryption failed. Aborting.`n"; return}}

function getpw  ($script:database, $script:keyfile, $url) {# Retrieve an entry.
verifystore $script:database $script:keyfile

# Error-checking
if ($url.length -lt 3) {$script:warning = "Requested match is too small. Aborting search."; $script:message = $null; return}

# Read each line from the Passwords list and try to find a match for the URL
$script:message = $null; $script:warning = $null; $key = decryptkey $script:keyfile
if ($script:message.length -gt 1) {return $script:message}
if ($script:warning.length -gt 1) {return $script:warning}
$foundEntry = $false; Get-Content "$script:database" | ForEach-Object {try {$entry = $_ | ConvertFrom-Json
if ($entry.URL -match $url) {$foundEntry = $true; $secure = $entry.Password | ConvertTo-SecureString -Key $key; $plain = [System.Net.NetworkCredential]::new("", $secure).Password; if (-not $noclip) {$plain | Set-Clipboard; clearclipboard}
$script:message = "Entry save date: $($entry.Timestamp)`nUserName:        $($entry.Username)`nPassword:        $plain`nURL:             $($entry.URL)`nNotes:           $($entry.Notes)"; $script:warning = $null; return}}
catch {$script:warning = "Skipping malformed or undecryptable entry."; $script:message = $null; return}}
if (-not $foundEntry) {$script:warning = "No password found for the URL '$url'"; $script:message = $null; return}}

function newpw ($script:database, $script:keyfile) {# Create a new password.
verifystore $script:database $script:keyfile; $script:message = $null; $script:warning = $null; $answer = $null; $confirmDup = $null

Write-Host -f yellow "`nEnter username" -n; $username = Read-Host " "
Write-Host -f yellow "Password" -n; $password = Read-Host " " -AsSecureString
Write-Host -f yellow "URL" -n; $url = Read-Host " "
Write-Host -f yellow "Notes" -n; $notes = Read-Host " "
$key = decryptkey $script:keyfile

# Load existing entries or empty array if none.
$listPath = "$script:database"; $entries = @(); $existing = $null
if (Test-Path $listPath) {$raw = Get-Content $listPath; $entries = foreach ($line in $raw) {$line | ConvertFrom-Json}
if ($entries -isnot [System.Collections.IEnumerable] -or $entries -is [string]) {$entries = @($entries)}}

# Check for existing entry matching username and URL.
$existing = $entries | Where-Object {$_.Username -eq $username -and $_.URL -eq $url}

if ($existing) {Write-Host -f yellow "An entry already exists for '$username' at '$url'."; Write-Host -f yellow "Overwrite it? (Y/N)" -n; $answer = Read-Host " "
if ($answer -notmatch '^[Yy]') {Write-Host -f yellow "Please update the entry:`n"

Write-Host -f yellow "Enter username ($($existing.Username))" -n; $username = Read-Host " "; if ([string]::IsNullOrEmpty($username)) {$username = $existing.Username}

$existingSecure = $existing.Password | ConvertTo-SecureString -Key $key; $existingPlain = [System.Net.NetworkCredential]::new("", $existingSecure).Password; Write-Host -f yellow "Password" -n;  $passwordPlain = Read-Host " "; if ([string]::IsNullOrEmpty($passwordPlain)) {$passwordPlain = $existingPlain}; $passwordSecure = ConvertTo-SecureString $passwordPlain -AsPlainText -Force

Write-Host -f yellow "URL ($($existing.URL))" -n; $url = Read-Host " "; if ([string]::IsNullOrEmpty($url)) {$url = $existing.URL}
Write-Host -f yellow "Notes ($($existing.Notes))" -n; $notes = Read-Host " "; if ([string]::IsNullOrEmpty($notes)) {$notes = $existing.Notes}

# Detect if changes were made
if ($username -eq $existing.Username -and $passwordPlain -eq $existingPlain -and $url -eq $existing.URL -and $notes -eq $existing.Notes) {Write-Host -f yellow "No changes detected. Save duplicate entry? (Y/N)" -n; $confirmDup = Read-Host " "
if ($confirmDup -notmatch '^[Yy]') {$script:warning = "Duplicate entry not saved."; $script:message = $null; return}}

# Convert updated password to encrypted string for storage
$secure = $passwordSecure | ConvertFrom-SecureString -Key $key
$entry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Username = $username; Password = $secure; URL = $url; Notes = $notes}; $entry | ConvertTo-Json -Depth 3 -Compress | Add-Content -Path $listPath; $script:message = "Password entry saved successfully."; $script:warning = $null; return}

# If overwriting, remove the old entry before saving new one
$entries = $entries | Where-Object {!($_.Username -eq $username -and $_.URL -eq $url)}}
# No existing entry, encrypt password as usual
else {$passwordSecure = $password}
# If new entry or overwrite confirmed, prepare password encryption
if (-not $passwordSecure) {$passwordSecure = $password}; $secure = $passwordSecure | ConvertFrom-SecureString -Key $key; 
$entry = [PSCustomObject]@{Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Username = $username; Password = $secure; URL = $url; Notes = $notes}

# Save all entries + new one to file, overwriting existing file
$entries += $entry; $entries | ForEach-Object {$_ | ConvertTo-Json -Depth 3 -Compress} | Set-Content -Path $listPath; $script:message = "Password entry saved successfully."; $script:warning = $null}

function newkey ($script:keyfile) {# Create AES key, protected with a master password.
if (-not $script:keyfile) {$script:warning = "No key file identified."; $script:message = $null}

# Generate AES key
$aesKey = New-Object byte[] 32; [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)

# Prepend magic marker "SCHV"
$marker = [System.Text.Encoding]::UTF8.GetBytes("SCHV"); $keyWithMarker = $marker + $aesKey

$script:keyfile = Join-Path $keydir $script:keyfile
if (Test-Path $script:keyfile) {$script:warning = "That key file already exists."; $script:message = $null; return}

Write-Host -f yellow "Enter a master password to protect your key:" -n; $secureMaster = Read-Host -AsSecureString; $master = [System.Net.NetworkCredential]::new("", $secureMaster).Password

# Generate salt and derive key using PBKDF2
$salt = New-Object byte[] 16; [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($salt); $pbkdf2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($master, $salt, 10000); $protectKey = $pbkdf2.GetBytes(32)

# Encrypt keyWithMarker using protectKey
$aes = [Security.Cryptography.Aes]::Create(); $aes.Key = $protectKey; $aes.GenerateIV(); $iv = $aes.IV; $encryptor = $aes.CreateEncryptor(); $encryptedKey = $encryptor.TransformFinalBlock($keyWithMarker, 0, $keyWithMarker.Length)

# Store salt + IV + ciphertext
$output = [byte[]]($salt + $iv + $encryptedKey); [IO.File]::WriteAllBytes("$script:keyfile", $output); $script:message = "Encrypted AES key created."; $script:keyexists = $true; $script:warning = $null}

do {# Menu system.
cls
Write-Host -f white "`nSecure Password Manager:"
Write-Host -f cyan ("-" * 70)
if ($script:database) {$displaydatabase = Split-Path -Leaf $script:database -ErrorAction SilentlyContinue} else {$displaydatabase = "none loaded"}
if ($script:keyfile) {$displaykey = Split-Path -Leaf $script:keyfile -ErrorAction SilentlyContinue} else {$displaykey = "none loaded"}
Write-Host -f white "Current Database: " -n; Write-Host -f green "$displaydatabase"
Write-Host -f white "Current Key: " -n; Write-Host -f green "$displaykey"
if ($displaydatabase -match '^(?i)(.+?)\.pwdb$') {$db = $matches[1]}
if ($displaykey -match '^(?i)(.+?)\.key$') {$key = $matches[1]}
if (($displaykey -eq "none loaded" -or $displaydatabase -eq "none loaded") -and ($script:database -or $script:keyfile)) {$script:warning = "Make sure to load both a database and a keyfile before continuing."}
if ($db -and $key -and $db -ne $key) {Write-Host -f red "`nWarning: " -n; Write-Host -f yellow "The key and database filenames do not match.`n"; $script:warning = "Continuing with an incorrect key and database pairing could lead to data corruption.`nEnsure you have the correct file combination before making any file changes."}
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "1. " -n; Write-Host -f yellow "Add a new entry."
Write-Host -f cyan "2. " -n; Write-Host -f white "Retrieve an entry."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "3. " -n; Write-Host -f yellow "Create a new password encryption key."
Write-Host -f cyan "4. " -n; Write-Host -f yellow "Create a new password database."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "5. " -n; Write-Host -f white "List all entries."
Write-Host -f cyan "6. " -n; Write-Host -f red "Remove an entry."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "7. " -n; Write-Host -f white "Select a different password encryption key."
Write-Host -f cyan "8. " -n; Write-Host -f white "Select a different password database."
Write-Host -f cyan ("-" * 70)
Write-Host -f cyan "C. " -n; Write-Host -f gray "Clear message center"-n
if ($noclip) {Write-Host -f gray "."} else {Write-Host -f gray " and clipboard."}
Write-Host -f cyan "H. " -n; Write-Host -f yellow "Help."
Write-Host -f cyan "Q. " -n; Write-Host -f darkgray "Exit."
if ($script:message.length -gt 1) {Write-Host -f cyan ("-" * 70); Write-Host -f white "`n$script:message`n"}
if ($script:warning.length -gt 1) {Write-Host -f cyan ("-" * 70); Write-Host -f red "`n$script:warning`n"}
Write-Host -f cyan ("-" * 70)
Write-Host -f white "`nChoose an option" -n; $choice = Read-Host " "

switch ($choice) {'1' {# Add a new entry.
newpw $script:database $script:keyfile}

'2' {# Retrieve an entry.
Write-Host -f green "`nEnter URL" -n; $url = Read-Host " "; getpw $script:database $script:keyfile $url}

'3' {# Create a new password encryption key.
Write-Host -f green "`nEnter filename for new keyfile" -n; $script:keyfile = Read-Host " "
if ([string]::IsNullOrWhiteSpace($script:keyfile)) {Write-Host -f red "`nNo filename entered. Aborting.`n`n"; return}
if (-not $script:keyfile.EndsWith(".key")) {$script:keyfile += ".key"}
newkey $script:keyfile}

'4' {# Create a new password database.
Write-Host -f green "`nEnter filename for new password database" -n; $script:database = Read-Host " "
if ([string]::IsNullOrWhiteSpace($script:database)) {Write-Host -f red "`nNo filename entered. Aborting.`n`n"; return}
if (-not $script:database.EndsWith(".pwdb")) {$script:database += ".pwdb"}
$path = Join-Path $script:databasedir $script:database
if (Test-Path $path) {$script:warning = "File already exists. Choose a different name."; $script:message = $null}
else {New-Item -Path $path -ItemType File | Out-Null; $script:message = "$path created and made active."; $script:warning = $null; $script:database = $path}}

'5' {# List all entries.
$entries = [System.Collections.ArrayList]::new()
Get-Content $script:database | ForEach-Object {try {$obj = $_ | ConvertFrom-Json
if ($obj) { $entries.Add($obj) | Out-Null}}
catch {Write-Host -f red "`nSkipping an invalid JSON line. Please check the file for corruption or incorrectly formatted entries.`nIf you make changes to the file, those lines will be lost."}}
if (-not $entries) {$script:warning = "No valid entries found to remove."; $script:message = $null}
Write-Host -f cyan "`nStored entries:`n"
for ($i = 0; $i -lt $entries.Count; $i++) {$entry = $entries[$i]; Write-Host -f yellow "User:  " -n; Write-Host -f white "$($entry.Username)"; Write-Host -f yellow "Notes: " -n; Write-Host -f white "$($entry.Notes)"; Write-Host -f yellow "URL:   " -n; Write-Host -f white "$($entry.URL)`n"}
Write-Host -f white "Enter to continue" -n; $useless = Read-Host " "; $script:message = $null; $script:warning = $null}

'6' {# Remove an entry.
$entries = [System.Collections.ArrayList]::new()
Get-Content $script:database | ForEach-Object {try {$obj = $_ | ConvertFrom-Json
if ($obj) { $entries.Add($obj) | Out-Null}}
catch {Write-Host -f red "`nSkipping an invalid JSON line. Please check the file for corruption or incorrectly formatted entries.`nIf you make changes to the file, those lines will be lost."}}
if (-not $entries) {$script:warning = "No valid entries found to remove."; $script:message = $null}
Write-Host -f cyan "`nStored entries:`n"
for ($i = 0; $i -lt $entries.Count; $i++) {$entry = $entries[$i]; Write-Host -f cyan "$($i + 1)." -n; Write-Host -f yellow "User: " -n; Write-Host -f white "$($entry.Username)" -n; Write-Host -f yellow ", Notes: " -n; Write-Host -f white "$($entry.Notes)," -n; Write-Host -f yellow " URL: " -n; Write-Host -f white "$($entry.URL)"}
Write-Host -f white "`nSelect an entry to remove" -n; $index = Read-Host " "
if ($index -notmatch '^\d+$' -or $index -lt 1 -or $index -gt $entries.Count) {$script:warning = "Invalid selection."; $script:message = $null}
elseif ($index -match '^\d+$' -and $index -ge 1 -and $index -le $entries.Count) {$entries.RemoveAt($index - 1); Remove-Item $script:database -ErrorAction SilentlyContinue
foreach ($entry in $entries) {$entry | ConvertTo-Json -Compress | Add-Content -Path $script:database -Encoding UTF8}
$script:message = "Entry removed successfully."; $script:warning = $null}}

'7' {# Select a different password encryption key.
$script:keyfiles = Get-ChildItem -Path $keydir -Filter *.key
if (-not $script:keyfiles) {Write-Host -f red "No .key files found."; return}
Write-Host -f white "`nAvailable AES Key Files:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $script:keyfiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $script:keyfiles[$i].Name}
Write-Host -f green "`nEnter number of the key file to use" -n; $sel = Read-Host " "
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $script:keyfiles.Count) {$script:keyfile = $script:keyfiles[$sel - 1].FullName; $script:message = "$script:keyfile selected."; $script:keyexists = $true; $script:warning = $null; $key = $null; $key = decryptkey $script:keyfile; if (-not $key) {Write-Host -f red "Decryption failed. Aborting.`n"; return}}}

'8' {# Select a different database.
$dbFiles = Get-ChildItem -Path $script:databasedir -Filter *.pwdb
if (-not $dbFiles) {Write-Host -f red "No .pwdb files found."; return}
Write-Host -f white "`nAvailable Password Databases:"; Write-Host -f yellow ("-" * 70)
for ($i = 0; $i -lt $dbFiles.Count; $i++) {Write-Host -f cyan "$($i+1). " -n; Write-Host -f white $dbFiles[$i].Name}
Write-Host -f green "`nEnter number of the database file to use" -n; $sel = Read-Host " "
if ($sel -match '^\d+$' -and $sel -ge 1 -and $sel -le $dbFiles.Count) {$script:database = $dbFiles[$sel - 1].FullName; $script:message = "$script:database selected."; $script:warning = $null}
else {$script:warning = "Invalid selection."; $script:message = $null}}

'c' {# Clear message center.
$script:message = $null; $script:warning = $null; if (-not $noclip) {clearclipboard 0 64}}

'h' {$script:message = "Usage: pwmanage <database.pwdb> <keyfile.key> -noclip`n`nIf no database/keyfile are specified, the defaults `"secure.pwdb`" and `"secure.key`" will be used.`n`nWhen a password is retrieved, it will automatically be copied to the clipboard for 30 seconds,`nunless the -noclip option is used at launch time.`n`nYou can configure the default password, default key file and directories where these are saved`nby modifying the entries in the `"Secure.psd1`" file located in the same directory as the module.`n`nIt is of course, best practice to save the key files somewhere distant from the databases.`nYou could even save the database files on cloud storage, but I recommended saving the keys locally.`n`nThe initial configurations of the directories within the PSD1 file point to:`n`n`"DefaultPowerShellDirectory\Modules\Secure\keys`" and `"DefaultPowerShellDirectory\Modules\Secure\databases`"`n`nThe term `"DefaultPowerShellDirectory`" is a placeholder that is evaluated within the module,`nredirecting these to your personal PowerShell directory. As stated above, I advise moving these`nsomewhere else once you've setup the database and plan to use it long-term."; if ($script:keyexists -eq $false) {$script:warning = "First time use: You will need to create key and database files with the options above.`nThe defaults configured in the PSD1 file use the filename `"secure`" for both."}}

'q' {""; return}
default {Write-Host -f red "`nInvalid choice. Try again.`n"}}} while ($true); ""}
