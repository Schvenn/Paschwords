param([string]$filename)

if (-not $filename) {Write-Host -f white "`nThis tool evaluates a list of URLs to ensure they are still active. To use it, provide a text file containing a list of URLs you need to validate, one entry per line.`n"; Write-Host -f cyan "`tUsage: validateurls <filename>`n";return}
if (-not (Test-Path $filename)) {Write-Host -f red "`nFile not found: $filename`n"; return}

$urls = Get-Content $filename | Where-Object {$_.Trim() -ne ""}; $total = $urls.Count; $validated = 0; $invalid = 0; $retryList = @(); $count2xx = 0; $count401 = 0; $count403 = 0; $count429 = 0; $count500 = 0; $count503 = 0; $countOtherInvalid = 0; $validList = @(); $invalidList = @(); $startTime = Get-Date; $timings = [System.Collections.Generic.Queue[double]]::new(); $windowSize = 20

function Format-TimeSpan($ts) {return "{0:00}:{1:00}" -f $ts.Minutes, $ts.Seconds}

function Show-Status {$elapsed = (Get-Date) - $startTime; $processed = $validated + $invalid; $remaining = $total - $processed

if ($processed -gt 0) {$average = ($timings | Measure-Object -Average).Average; $estimated = [timespan]::FromSeconds($average * $remaining)}
else {$estimated = [timespan]::Zero}

cls; Write-Host -f cyan "URL Validator:"
Write-Host -f yellow ("-" * 50)
Write-Host ("Time elapsed:`t`t$(Format-TimeSpan $elapsed)")
Write-Host ("Time remaining:`t`t$(Format-TimeSpan $estimated)")
Write-Host ("Current URL:`t`t$($currentURL)")
Write-Host ("Total URLs to validate:`t$total")
Write-Host ("Validated URLs:`t`t$validated")
Write-Host ("Invalid URLs:`t`t$invalid")
Write-Host ("URLs remaining:`t`t$remaining`n")
Write-Host -f cyan "Response Codes:"
Write-Host -f yellow ("-" * 50)
Write-Host ("2##: Success:`t`t  $count2xx")
Write-Host ("401: Unauthorized:`t  $count401")
Write-Host ("403: Forbidden:`t`t  $count403")
Write-Host ("429: Too Many Requests:   $count429")
Write-Host ("500: Server Error:`t  $count500")
Write-Host ("503: Service Unavailable: $count503")
Write-Host ("Other Invalid:`t`t  $countOtherInvalid")}

function Test-Url($url) {$usedGet = $false; try {$response = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop}
catch {$usedGet = $true; try {$response = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop}
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
foreach ($url in $urls) {$currentURL = $url; $result = Test-Url $url; Process-Result $url $result.Status; Show-Status; Start-Sleep -Milliseconds 100}

# Retry 429/500/503 once
if ($retryList.Count -gt 0) {$retrying = $retryList; $retryList = @()
foreach ($url in $retrying) {$currentURL = $url; $result = Test-Url $url; Process-Result $url $result.Status; Show-Status; Start-Sleep -Milliseconds 100}}

# Export results
$directory = split-path (resolve-path $filename); $timestamp = Get-Date -Format "yyyy-MM-dd @ HH-mm-ss"
$validList | Set-Content "$directory\validatedurls, $timestamp.txt"; $invalidList | Set-Content "$directory\expiredurls, $timestamp.txt"

Write-Host -f green "`nValidation complete. Results saved to " -n; Write-Host -f white "validatedurls.txt" -n; Write-Host -f green " and " -n; Write-Host -f white "expiredurls.txt" -n; Write-Host -f green ".`n"
