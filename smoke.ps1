$ErrorActionPreference = 'Stop'
$uri = 'https://devoops.onrender.com/sort-ticket'
$body = '{"ticket_id":"T-CHECK","channel":"app","locale":"en","message":"I sent 5000 taka to a wrong number please help me get it back"}'

try {
    $r = Invoke-RestMethod -Method Post -Uri $uri -ContentType 'application/json' -Body $body
    Write-Host 'STATUS: 200 OK'
    $r | ConvertTo-Json -Depth 5
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Write-Host ("STATUS: {0} {1}" -f $code, $_.Exception.Response.ReasonPhrase)
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $reader.ReadToEnd()
}