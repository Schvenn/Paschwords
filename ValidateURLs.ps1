param([string]$filename, [switch]$safe, $useragent)

$script:urlStart = Get-Date

if (-not $useragent) {$useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
if ($safe) {$headers = @{"User-Agent" = $useragent}}
else {$headers = @{}}

if (-not $filename) {Write-Host -f white "`nThis tool evaluates a list of URLs to ensure they are still active. To use it, provide a text file containing a list of URLs you need to validate, one entry per line.`n"; Write-Host -f cyan "`tUsage: validateurls <filename> -safe <user-agent>`n";return}
if (-not (Test-Path $filename)) {Write-Host -f red "`nFile not found: $filename`n"; return}

$urls = Get-Content $filename | Where-Object {$_.Trim() -ne ""}; $total = $urls.Count; $validated = 0; $invalid = 0; $retryList = @(); $count2xx = 0; $count401 = 0; $count403 = 0; $count429 = 0; $count500 = 0; $count503 = 0; $countOtherInvalid = 0; $validList = @(); $invalidList = @(); $startTime = Get-Date; $timings = [System.Collections.Generic.Queue[double]]::new(); $windowSize = 3

function timespan($ts) {return "{0:00}:{1:00}" -f $ts.Minutes, $ts.Seconds}

function renderscreen {$elapsed = (Get-Date) - $startTime; $processed = $validated + $invalid; $remaining = $total - $processed

if ($processed -gt 0) {$average = ($timings | Measure-Object -Average).Average; $estimated = [timespan]::FromSeconds($average * $remaining)}
else {$estimated = [timespan]::Zero}

cls; Write-Host -f yellow "URL Validator v1.3:"
Write-Host -f yellow ("-" * 50)
Write-Host -f cyan "User-Agent:`t`t"-n; Write-Host -f white "$useragent"
Write-Host -f yellow ("-" * 50)
Write-Host -f cyan "Time elapsed:`t`t"-n; Write-Host -f white "$(timespan $elapsed)"
Write-Host -f cyan "Time remaining:`t`t"-n; Write-Host -f white "$(timespan $estimated)"
Write-Host -f cyan "Current URL:`t`t"-n; Write-Host -f white "$($currentURL)"
Write-Host -f cyan "Total URLs to validate:`t"-n; Write-Host -f white "$total"
Write-Host -f cyan "Validated URLs:`t`t"-n; Write-Host -f white "$validated"
Write-Host -f cyan "Invalid URLs:`t`t"-n; Write-Host -f white "$invalid"
Write-Host -f cyan "URLs remaining:`t`t"-n; Write-Host -f white "$remaining`n"
Write-Host -f yellow "Response Codes:"
Write-Host -f yellow ("-" * 50)
Write-Host -f cyan "2##: Success:`t`t  "-n; Write-Host -f white "$count2xx"
Write-Host -f cyan "401: Unauthorized:`t  "-n; Write-Host -f white "$count401"
Write-Host -f cyan "403: Forbidden:`t`t  "-n; Write-Host -f white "$count403"
Write-Host -f cyan "429: Too Many Requests:   "-n; Write-Host -f white "$count429"
Write-Host -f cyan "500: Server Error:`t  "-n; Write-Host -f white "$count500"
Write-Host -f cyan "503: Service Unavailable: "-n; Write-Host -f white "$count503"
Write-Host -f cyan "Other Invalid:`t`t  "-n; Write-Host -f white "$countOtherInvalid`n"}

function testurl($url) {$usedGet = $false; try {$response = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop}
catch {$usedGet = $true; try {$response = Invoke-WebRequest -Uri $url -Method Get -Headers $headers -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop}
catch {return @{Valid=$false; Status=0}}}
return @{Valid=$true; Status=[int]$response.StatusCode}}

function Process-Result($url, $status) {switch ($status) {{$_ -ge 200 -and $_ -lt 300} {$script:validated++; $script:count2xx++; $script:validList += $url; break}
401 {$script:validated++; $script:count401++; $script:validList += $url; break}
403 {$script:validated++; $script:count403++; $script:validList += $url; break}
429 {$script:count429++; $script:retryList += $url; break}
500 {$script:count500++; $script:retryList += $url; break}
503 {$script:count503++; $script:retryList += $url; break}
default {$script:invalid++; $script:countOtherInvalid++; $script:invalidList += $url; break}}}

# Main loop
foreach ($url in $urls) {$currentURL = $url; $result = testurl $url; Process-Result $url $result.Status; $urlDuration = ((Get-Date) - $urlStart).TotalSeconds; $timings.Enqueue($urlDuration)
if ($timings.Count -gt $windowSize) {$null = $timings.Dequeue()}
renderscreen
if ($safe) {Start-Sleep -Milliseconds (Get-Random -Minimum 600 -Maximum 1200)}
else {Start-Sleep -Milliseconds 100}}

# Retry 429/500/503 once
if ($retryList.Count -gt 0) {$retrying = $retryList; $retryList = @()
foreach ($url in $retrying) {$currentURL = $url; $result = testurl $url; Process-Result $url $result.Status; $urlDuration = ((Get-Date) - $urlStart).TotalSeconds; $timings.Enqueue($urlDuration)
if ($timings.Count -gt $windowSize) {$null = $timings.Dequeue()}
renderscreen; Start-Sleep -Milliseconds 100}}

# Export results
$directory = split-path (resolve-path $filename); $timestamp = Get-Date -Format "yyyy-MM-dd @ HH-mm-ss"
$validList | Set-Content "$directory\validatedurls, $timestamp.txt"; $invalidList | Set-Content "$directory\expiredurls, $timestamp.txt"

Write-Host -f yellow "Validation complete. Results saved to " -n; Write-Host -f white "validatedurls.txt" -n; Write-Host -f yellow " and " -n; Write-Host -f white "expiredurls.txt" -n; Write-Host -f yellow "."
Write-Host -f cyan "`n↩️ EXIT " -n; Read-Host
