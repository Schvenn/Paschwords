param ($sourcefile)

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

function protectbytesaeshmac ([byte[]]$Data, [byte[]]$Key) {# Derived from password, split into encryption & HMAC keys.
$aesKey = $Key[0..31]; $hmacKey = $Key[32..63]; $iv = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv); $aes = [System.Security.Cryptography.Aes]::Create(); $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; $aes.Key = $aesKey; $aes.IV = $iv; $encryptor = $aes.CreateEncryptor(); $cipherText = $encryptor.TransformFinalBlock($Data, 0, $Data.Length); $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey); $hmacData = $iv + $cipherText; $hmacBytes = $hmac.ComputeHash($hmacData); $encryptor.Dispose(); $aes.Dispose(); $hmac.Dispose(); return $hmacBytes + $hmacData}

function encryptmodulefile ([string]$sourcepath, [SecureString]$Password) {# Encrypt file
# Error-checking.
Write-Host "Encrypting from $sourcepath"; $sourcepath = Resolve-Path $sourcepath; $script:outputpath = $sourcepath -replace "\.\w+$", ".enc"
if (-not (Test-Path $sourcepath)) {Write-Host -ForegroundColor Red "Source file not found!"; return}

# Generate salt and key.
$Salt = [byte[]]::new(16); [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Salt); $Key = derivekeyfrompassword $Password $Salt

# Compress.
$content = [System.IO.File]::ReadAllText($sourcepath); [byte[]]$raw = [System.Text.Encoding]::UTF8.GetBytes($content); $ms = [System.IO.MemoryStream]::new(); $gzip = [System.IO.Compression.GzipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress); $gzip.Write($raw, 0, $raw.Length); $gzip.Close(); [byte[]]$compressed = $ms.ToArray()

# Add HMAC.
$protected = protectbytesaeshmac -Data $compressed -Key $Key

try {[IO.File]::WriteAllBytes($script:outputpath, $Salt + $protected); Write-Host -ForegroundColor Green "Write operation succeeded"; $powershell = Split-Path $profile; Add-Content -Path "$powershell\Modules\Paschwords\.privilege\validhashes.sha256" -Value "# Paschwords.enc ($(Get-Date))`n$((Get-FileHash -Algorithm SHA256 $powershell\Modules\Paschwords\Paschwords.enc).Hash)"}
catch {Write-Host -ForegroundColor Red "Write operation failed: $_"}}

# User interaction.
if (-not $sourcefile) {Write-Host -f cyan "`nUsage: encryptpasswordsmodule sourcefile`n"}
Write-Host -f green "`nEnter password used to encrypt the module " -n; $password = Read-Host -AsSecureString
encryptmodulefile $sourcefile $password
Write-Host -f green "🔐 Module encrypted successfully: " -n; Write-Host -f white "$script:outputpath`n"; $password = $null
#Write-Host -f white "Do you now want to delete the unencrypted version of the module? " -n; $confirmdelete = Read-Host
if ($confirmdelete -match "^[Yy]") {Remove-Item $sourcefile -Force}
