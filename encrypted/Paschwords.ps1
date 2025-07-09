param ([string]$database, [string]$keyfile, [switch]$noclip, [switch]$notime)

# Returns the derived key for HMAC.
function getsecurekey ([object]$Password, [byte[]]$Salt) {if ($Password -is [string]) {$secure = ConvertTo-SecureString $Password -AsPlainText -Force}
elseif ($Password -is [SecureString]) {$secure = $Password}
else {throw "The Password must be a string or SecureString."}

$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)}
finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)}

$pbkdf2 = [Security.Cryptography.Rfc2898DeriveBytes]::new($plain, $Salt, 100000, [Security.Cryptography.HashAlgorithmName]::SHA256)

try {return $pbkdf2.GetBytes(64)}
finally {$pbkdf2.Dispose()}}

# Verify HMAC, expand, and return plaintext bytes.
function expandblock ([byte[]]$Protected, [byte[]]$Key) {

# Split byte object by bytes in order to maintain array.
function slicebytes([byte[]]$bytes, [int]$start, [int]$length) {$result = New-Object byte[] $length; [Array]::Copy($bytes, $start, $result, 0, $length); return $result}

# Ensure HMAC integrity remained intact.
function comparehmac($a, $b) {if ($a.Length -ne $b.Length) {return $false}; $result = 0; 
for ($i = 0; $i -lt $a.Length; $i++) {$result = $result -bor ($a[$i] -bxor $b[$i])}
return ($result -eq 0)}

$aesKey = slicebytes $Key 0 32; $hmacKey = slicebytes $Key 32 32; $hmacStored = slicebytes $Protected 0 32; $iv = slicebytes $Protected 32 16; $cipher = slicebytes $Protected 48 ($Protected.Length - 48); $hmacData = $iv + $cipher; $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey); $hmacComputed = $hmac.ComputeHash($hmacData)
if (-not (comparehmac $hmacStored $hmacComputed)) {Write-Host -f red "`t  ❌ Module failed verification. Please check integrity and try again.`n"; return}
$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; $aes.Key = $aesKey; $aes.IV = $iv; $expander = $aes.Createdecryptor()
try {return $expander.TransformFinalBlock($cipher, 0, $cipher.Length)}
finally {$hmac.Dispose(); $expander.Dispose(); $aes.Dispose()}}

# Initialize environment.
sl $powershell\Modules\Paschwords; $file = Resolve-Path 'paschwords.data'; [byte[]]$raw = [IO.File]::ReadAllBytes($file); $salt = $raw[0..15]; $blob = $raw[16..($raw.Length - 1)]

# User interaction.
Write-Host -f green "`n`t  Enter password to expand the module " -n; $password = Read-Host -AsSecureString
if ([string]::IsNullOrEmpty($password) -or $password.length -lt 1) {Write-Host -f red "`t  No password provided. Aborting.`n"; return}

# Get key, salt and verify HMAC.
$key = getsecurekey -Password $password -Salt $salt; $plaintextBytes = expandblock -Protected $blob -Key $key; 

if (-not [string]::IsNullOrEmpty($plaintextBytes) -and $plaintextBytes.length -gt 0) {# Unzip.
$ms = [System.IO.MemoryStream]::new($plaintextBytes); $gzip = [System.IO.Compression.GzipStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress); $out = [System.IO.MemoryStream]::new(); $buffer = New-Object byte[] 4096
while (($read = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {$out.Write($buffer, 0, $read)}
$gzip.Close(); [byte[]]$decompressed = $out.ToArray(); $code = [System.Text.Encoding]::UTF8.GetString($decompressed)
$gzip.Dispose(); $ms.Dispose(); $out.Dispose()

# Build command line and run Paschwords.
$sb = [ScriptBlock]::Create($code); . $sb; paschwords -database $database -keyfile $keyfile @args; $password = $null; $key = $null; ""}
