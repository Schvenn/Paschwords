param ([string]$NtpServer = 'pool.ntp.org', [int]$AllowedDriftSeconds = 600)

try {$ntpData = New-Object byte[] 48; $ntpData[0] = 0x1B; $address = [System.Net.Dns]::GetHostAddresses($NtpServer)[0]; $endpoint = New-Object System.Net.IPEndPoint $address, 123; $socket = New-Object System.Net.Sockets.UdpClient; $socket.Client.ReceiveTimeout = 3000; $socket.Send($ntpData, $ntpData.Length, $endpoint) | Out-Null; $response = $socket.Receive([ref]$endpoint); $socket.Close(); $intPartBytes = $response[40..43]; [Array]::Reverse($intPartBytes); $fracPartBytes = $response[44..47]; [Array]::Reverse($fracPartBytes); $intPart = [BitConverter]::ToUInt32($intPartBytes, 0); $fracPart = [BitConverter]::ToUInt32($fracPartBytes, 0)

$ntpEpoch = [datetime]::SpecifyKind([datetime]"1900-01-01", [System.DateTimeKind]::Utc); $seconds = $intPart + ($fracPart / [math]::Pow(2, 32)); $ntpTime = $ntpEpoch.AddSeconds($seconds); $localTime = [datetime]::UtcNow; $drift = [Math]::Abs(($ntpTime - $localTime).TotalSeconds)

#Write-Host -f white "`nNTP time: $ntpTime`nLocal time: $localTime`nDifference: $drift seconds`n"
return ($drift -le $AllowedDriftSeconds)}
catch {Write-Host "Time check failed."; return $false}
