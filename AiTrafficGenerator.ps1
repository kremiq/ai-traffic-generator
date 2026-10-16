<#
.SYNOPSIS
    Generates traffic to AI applications (chatbots, AI APIs, AI tools) so a secure
    web gateway / AI gateway can be tested: app detection, allow/block policies, DLP.

.DESCRIPTION
    Without parameters a window opens: tick the apps, choose the traffic types and a
    prompt, press Start. With -NoGui the same runs in the console (for scheduled tasks).

    Traffic types:
      Web      GET the app's web pages (browser User-Agent). Apps with a prompt URL
               (e.g. https://chatgpt.com/?q=...) also get one request carrying the prompt.
      Api      POST the prompt to the app's API. Without an API key the API answers
               401, which still means the request (with the prompt in its body) passed
               the gateway - enough for app detection and DLP tests. With the key in the
               environment variable named in ai-apps.json, you get a real answer.
      Browser  Opens the app (with the prompt where supported) in the default browser,
               for real browser traffic.

    Apps, URLs, API formats, prompts and block-page markers live in ai-apps.json.

.EXAMPLE
    .\AiTrafficGenerator.ps1
    Opens the window.

.EXAMPLE
    .\AiTrafficGenerator.ps1 -NoGui -Apps chatgpt,claude,gemini -Mode Web,Api -Rounds 3 -OutCsv results.csv

.EXAMPLE
    .\AiTrafficGenerator.ps1 -NoGui -Category Chatbot -RandomPrompt -DurationMinutes 30 -DelayMs 2000

.EXAMPLE
    .\AiTrafficGenerator.ps1 -List
    Lists the app IDs from the catalogue.
#>
[CmdletBinding()]
param(
    [switch]$NoGui,
    [switch]$List,
    [string]$Catalog,
    [string[]]$Apps = @('all'),
    [string[]]$Category,
    [string[]]$Mode = @('Web', 'Api'),
    [int]$Rounds = 1,
    [int]$DurationMinutes = 0,
    [int]$DelayMs = 500,
    [int]$Concurrency = 4,
    [int]$TimeoutSec = 20,
    [string]$Prompt,
    [switch]$RandomPrompt,
    [switch]$Shuffle,
    [string]$Proxy,
    [string]$OutCsv
)

$ErrorActionPreference = 'Stop'
if (-not $Catalog) { $Catalog = Join-Path $PSScriptRoot 'ai-apps.json' }
Add-Type -AssemblyName System.Net.Http

# .NET Framework (Windows PowerShell 5.1) on older Windows may not offer TLS 1.2 by default.
$protocols = [Net.ServicePointManager]::SecurityProtocol
if ($protocols -ne [Net.SecurityProtocolType]::SystemDefault -and -not ($protocols -band [Net.SecurityProtocolType]::Tls12)) {
    [Net.ServicePointManager]::SecurityProtocol = $protocols -bor [Net.SecurityProtocolType]::Tls12
}

$AllModes = @('Web', 'Api', 'Browser')

# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------

function Get-Prop($Object, [string]$Name, $Default = $null) {
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function Read-Catalog([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "Catalogue not found: $Path" }
    $cat = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($app in @($cat.apps)) {
        foreach ($field in 'id', 'name') {
            if (-not (Get-Prop $app $field)) { throw "Every app in $Path needs an '$field'." }
        }
    }
    return $cat
}

function Get-AppModes($App) {
    $modes = @()
    if (@(Get-Prop $App 'web' @()).Count -gt 0 -or (Get-Prop $App 'promptUrl')) { $modes += 'Web'; $modes += 'Browser' }
    if (Get-Prop $App 'api') { $modes += 'Api' }
    return $modes
}

# Splits "a,b" into a, b: powershell.exe -File passes comma lists as one string.
function Split-List([string[]]$Values) {
    return @($Values | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# ---------------------------------------------------------------------------
# Building requests
# ---------------------------------------------------------------------------

function ConvertTo-JsonText([string]$Text) {
    $json = ConvertTo-Json -InputObject $Text -Compress
    return $json.Substring(1, $json.Length - 2)
}

function New-Job($App, [string]$Mode, [string]$Method, [string]$Url, [string]$PromptText, [string]$Body = $null, [hashtable]$Headers = @{}, [string]$Note = '') {
    return [pscustomobject]@{
        AppId = $App.id; App = $App.name; Mode = $Mode; Method = $Method; Url = $Url
        Body = $Body; Headers = $Headers; Prompt = $PromptText; Note = $Note
    }
}

function New-AppJobs($App, [string[]]$Modes, [string]$PromptText) {
    $jobs = @()
    $encoded = [Uri]::EscapeDataString($PromptText)
    $promptUrl = Get-Prop $App 'promptUrl'
    $web = @(Get-Prop $App 'web' @())

    if ($Modes -contains 'Web') {
        foreach ($url in $web) { $jobs += New-Job $App 'Web' 'GET' $url '' }
        if ($promptUrl -and $PromptText) { $jobs += New-Job $App 'Web' 'GET' ($promptUrl.Replace('{{prompt}}', $encoded)) $PromptText }
    }

    $api = Get-Prop $App 'api'
    if ($Modes -contains 'Api' -and $api) {
        $model = Get-Prop $api 'model' ''
        $body = (ConvertTo-Json -InputObject $api.body -Depth 20 -Compress).Replace('{{model}}', (ConvertTo-JsonText $model)).Replace('{{prompt}}', (ConvertTo-JsonText $PromptText))
        $headers = @{}
        $extra = Get-Prop $api 'headers'
        if ($extra) { foreach ($p in $extra.PSObject.Properties) { $headers[$p.Name] = [string]$p.Value } }
        $note = 'no API key'
        $auth = Get-Prop $api 'auth'
        if ($auth) {
            $key = [Environment]::GetEnvironmentVariable([string](Get-Prop $auth 'env' ''))
            if ($key) {
                $headers[(Get-Prop $auth 'header' 'Authorization')] = (Get-Prop $auth 'prefix' '') + $key
                $note = 'API key from ' + $auth.env
            }
        }
        $jobs += New-Job $App 'Api' 'POST' ($api.url.Replace('{{model}}', $model)) $PromptText $body $headers $note
    }

    if ($Modes -contains 'Browser') {
        $url = if ($promptUrl -and $PromptText) { $promptUrl.Replace('{{prompt}}', $encoded) } elseif ($web.Count) { $web[0] } else { $null }
        if ($url) { $jobs += New-Job $App 'Browser' 'OPEN' $url $PromptText }
    }
    return $jobs
}

function Get-RoundPrompt($Settings) {
    if ($Settings.RandomPrompt -and $Settings.Prompts.Count) { return ($Settings.Prompts | Get-Random) }
    return $Settings.PromptText
}

function New-RoundJobs($Settings) {
    $jobs = @()
    foreach ($app in $Settings.Apps) { $jobs += New-AppJobs $app $Settings.Modes (Get-RoundPrompt $Settings) }
    if ($Settings.Shuffle -and $jobs.Count -gt 1) { $jobs = @($jobs | Get-Random -Count $jobs.Count) }
    return $jobs
}

# ---------------------------------------------------------------------------
# Sending and classifying
# ---------------------------------------------------------------------------

function New-HttpClient([int]$TimeoutSec, [string]$Proxy) {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $true
    $handler.AutomaticDecompression = [Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
    if ($Proxy) {
        $handler.Proxy = New-Object System.Net.WebProxy($Proxy)
        $handler.UseProxy = $true
    }
    # Corporate proxies that require Windows sign-in (.NET Framework 4.7.1+ / PowerShell 7).
    if ($handler.PSObject.Properties['DefaultProxyCredentials']) { $handler.DefaultProxyCredentials = [Net.CredentialCache]::DefaultCredentials }
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds([Math]::Max(1, $TimeoutSec))
    $client.MaxResponseContentBufferSize = 50MB
    return $client
}

function Start-AiRequest($State, $Job) {
    $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::new($Job.Method), $Job.Url)
    [void]$request.Headers.TryAddWithoutValidation('User-Agent', $State.Settings.UserAgent)
    if ($Job.Mode -eq 'Web') {
        [void]$request.Headers.TryAddWithoutValidation('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        [void]$request.Headers.TryAddWithoutValidation('Accept-Language', 'en-US,en;q=0.9')
    } else {
        [void]$request.Headers.TryAddWithoutValidation('Accept', 'application/json')
    }
    foreach ($name in $Job.Headers.Keys) { [void]$request.Headers.TryAddWithoutValidation($name, $Job.Headers[$name]) }
    if ($null -ne $Job.Body) {
        $request.Content = New-Object System.Net.Http.StringContent($Job.Body, [Text.Encoding]::UTF8, 'application/json')
    }
    return [pscustomobject]@{
        Job = $Job; Request = $request; Watch = [Diagnostics.Stopwatch]::StartNew()
        Task = $State.Client.SendAsync($request, $State.Cancel.Token)
    }
}

function New-Result($Job, $Status, [string]$Result, [string]$Detail, $Ms, [string]$FinalUrl = '') {
    if ($Job.Note) { $Detail = if ($Detail) { "$Detail ($($Job.Note))" } else { $Job.Note } }
    return [pscustomobject][ordered]@{
        Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); App = $Job.App; Mode = $Job.Mode
        Method = $Job.Method; Url = $Job.Url; Status = $Status; Result = $Result; Ms = $Ms
        Detail = $Detail; FinalUrl = $FinalUrl; Prompt = $Job.Prompt
    }
}

function Get-ErrorText($Exception) {
    $messages = @()
    while ($Exception) {
        if ($Exception -isnot [AggregateException]) { $messages += $Exception.Message }
        $Exception = $Exception.InnerException
    }
    return (($messages | Select-Object -Unique) -join ' -> ')
}

function Get-AnswerText([string]$Body) {
    try { $o = $Body | ConvertFrom-Json } catch { return $null }
    $readers = @(
        { $o.choices[0].message.content },          # OpenAI-compatible APIs
        { $o.content[0].text },                     # Anthropic
        { $o.candidates[0].content.parts[0].text }, # Gemini
        { $o.message.content[0].text },             # Cohere
        { $o.error.message },
        { if ($o.error -is [string]) { $o.error } },
        { $o.detail },
        { $o.message }
    )
    foreach ($read in $readers) {
        try { $text = & $read; if ($text -is [string] -and $text) { return $text } } catch { }
    }
    return $null
}

function Limit-Text([string]$Text, [int]$Max = 300) {
    $Text = ($Text -replace '\s+', ' ').Trim()
    if ($Text.Length -gt $Max) { return $Text.Substring(0, $Max) + '...' }
    return $Text
}

function Complete-AiRequest($State, $InFlight) {
    $job = $InFlight.Job
    $task = $InFlight.Task
    $ms = $InFlight.Watch.ElapsedMilliseconds
    try {
        if ($task.IsCanceled) {
            if ($State.Stopping) { return New-Result $job '' 'Canceled' 'Stopped by user' $ms }
            return New-Result $job '' 'Timeout' "No answer within $($State.Settings.TimeoutSec) s" $ms
        }
        if ($task.IsFaulted) {
            $err = Get-ErrorText $task.Exception
            if ($err -match 'timed out|timeout|canceled') { return New-Result $job '' 'Timeout' $err $ms }
            if ($err -match 'proxy.*\b407\b|Proxy Authentication Required') {
                return New-Result $job '' 'Error' "The proxy wants a sign-in (HTTP 407): $err" $ms
            }
            if ($err -match 'proxy.*\b(403|451)\b') {
                return New-Result $job '' 'Blocked' "The proxy refused the connection: $err" $ms
            }
            if ($err -match 'trust relationship|certificate|SSL|TLS|authentication failed') {
                return New-Result $job '' 'TLS error' "$err | Is the gateway's root certificate installed in Windows (Trusted Root Certification Authorities)?" $ms
            }
            if ($err -match 'No such host|not known|could not be resolved|name or service') {
                return New-Result $job '' 'Blocked?' "DNS lookup failed (DNS policy block?): $err" $ms
            }
            if ($err -match 'forcibly closed|reset|refused|aborted|unexpected EOF|closed') {
                return New-Result $job '' 'Blocked?' "Connection refused/reset (network policy block?): $err" $ms
            }
            return New-Result $job '' 'Error' $err $ms
        }

        $response = $task.Result
        try {
            $status = [int]$response.StatusCode
            $body = $response.Content.ReadAsStringAsync().Result
            $finalUrl = [string]$response.RequestMessage.RequestUri
            $sample = if ($body.Length -gt 300000) { $body.Substring(0, 300000) } else { $body }

            foreach ($marker in $State.Settings.Markers) {
                if ($sample.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    return New-Result $job $status 'Blocked' "Block page detected ('$marker')" $ms $finalUrl
                }
            }

            $detail = ''
            $challenged = $response.Headers.Contains('cf-mitigated') -or ($status -eq 403 -and $sample -match 'Just a moment|challenge-platform|Attention Required')
            if ($challenged) {
                $detail = "HTTP $status bot challenge from the app's own site protection - the request passed the gateway"
            } elseif ($job.Mode -eq 'Api') {
                $answer = Get-AnswerText $body
                if ($status -eq 401 -or $status -eq 403) { $detail = "HTTP $status from the API (not authorized) - the request passed the gateway" }
                elseif ($status -lt 400) { $detail = 'Answer' }
                else { $detail = "HTTP $status from the API" }
                if ($answer) { $detail += ': ' + (Limit-Text $answer) }
            } else {
                $title = [regex]::Match($sample, '<title[^>]*>([^<]*)</title>', 'IgnoreCase').Groups[1].Value
                $detail = "HTTP $status" + $(if ($title) { ' - ' + (Limit-Text ([Net.WebUtility]::HtmlDecode($title)) 120) } else { '' })
            }
            $requestedHost = ([Uri]$job.Url).Host
            if ($finalUrl -and ([Uri]$finalUrl).Host -ne $requestedHost) { $detail += " | redirected to $finalUrl" }
            return New-Result $job $status 'Allowed' $detail $ms $finalUrl
        } finally {
            $response.Dispose()
        }
    } finally {
        $InFlight.Request.Dispose()
    }
}

function Open-InBrowser($Job) {
    try {
        Start-Process $Job.Url
        return New-Result $Job '' 'Opened' 'Opened in the default browser' 0
    } catch {
        return New-Result $Job '' 'Error' (Get-ErrorText $_.Exception) 0
    }
}

# ---------------------------------------------------------------------------
# Engine: shared by the window (timer) and the console (loop)
# ---------------------------------------------------------------------------

function New-RunState($Settings) {
    $endTime = $null
    if ($Settings.DurationMinutes -gt 0) { $endTime = (Get-Date).AddMinutes($Settings.DurationMinutes) }
    $state = @{
        Settings = $Settings
        Client = New-HttpClient $Settings.TimeoutSec $Settings.Proxy
        Cancel = New-Object System.Threading.CancellationTokenSource
        Queue = New-Object 'System.Collections.Generic.Queue[object]'
        InFlight = New-Object 'System.Collections.Generic.List[object]'
        Results = New-Object 'System.Collections.Generic.List[object]'
        Round = 0
        NextStart = [datetime]::MinValue
        EndTime = $endTime
        Stopping = $false
        Done = $false
    }
    return $state
}

function Test-MoreRounds($State) {
    if ($State.EndTime) { return (Get-Date) -lt $State.EndTime }
    if ($State.Settings.Rounds -le 0) { return $true }
    return $State.Round -lt $State.Settings.Rounds
}

function Add-NextRound($State) {
    if (-not (Test-MoreRounds $State)) { return $false }
    $jobs = @(New-RoundJobs $State.Settings)
    if ($jobs.Count -eq 0) { $State.Stopping = $true; return $false }
    $State.Round++
    foreach ($job in $jobs) { $State.Queue.Enqueue($job) }
    return $true
}

# Collects finished requests and starts new ones; returns the new results.
function Invoke-EngineStep($State) {
    $new = New-Object 'System.Collections.Generic.List[object]'
    for ($i = $State.InFlight.Count - 1; $i -ge 0; $i--) {
        $inFlight = $State.InFlight[$i]
        if ($inFlight.Task.IsCompleted) {
            $State.InFlight.RemoveAt($i)
            $new.Add((Complete-AiRequest $State $inFlight))
        }
    }
    while (-not $State.Stopping -and $State.InFlight.Count -lt $State.Settings.Concurrency -and (Get-Date) -ge $State.NextStart) {
        if ($State.Queue.Count -eq 0 -and -not (Add-NextRound $State)) { break }
        $job = $State.Queue.Dequeue()
        $State.NextStart = (Get-Date).AddMilliseconds($State.Settings.DelayMs)
        if ($job.Mode -eq 'Browser') {
            $new.Add((Open-InBrowser $job))
        } else {
            try { $State.InFlight.Add((Start-AiRequest $State $job)) }
            catch { $new.Add((New-Result $job '' 'Error' (Get-ErrorText $_.Exception) 0)) }
        }
    }
    if ($State.InFlight.Count -eq 0 -and ($State.Stopping -or ($State.Queue.Count -eq 0 -and -not (Test-MoreRounds $State)))) {
        $State.Done = $true
    }
    foreach ($result in $new) { $State.Results.Add($result) }
    return , $new
}

function Stop-Run($State) {
    $State.Stopping = $true
    $State.Queue.Clear()
    $State.Cancel.Cancel()
}

function Close-Run($State) {
    $State.Client.Dispose()
    $State.Cancel.Dispose()
}

function Get-Summary($Results) {
    $groups = $Results | Group-Object Result | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Count)" }
    return "Requests: $($Results.Count)" + $(if ($groups) { ' | ' + ($groups -join ' | ') } else { '' })
}

function Export-Results($Results, [string]$Path) {
    $Results | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

$ResultColors = @{
    'Allowed' = 'Green'; 'Blocked' = 'Red'; 'Blocked?' = 'Magenta'; 'TLS error' = 'Yellow'
    'Timeout' = 'Yellow'; 'Error' = 'Yellow'; 'Opened' = 'Cyan'; 'Canceled' = 'Gray'
}

# ---------------------------------------------------------------------------
# Console mode
# ---------------------------------------------------------------------------

function Invoke-Console($Cat) {
    $modes = @(Split-List $Mode)
    foreach ($m in $modes) { if ($AllModes -notcontains $m) { throw "Unknown mode '$m'. Use: $($AllModes -join ', ')" } }

    $ids = @(Split-List $Apps)
    $categories = @(Split-List $Category)
    $selected = @($Cat.apps | Where-Object {
        ($ids -contains 'all' -or $ids -contains $_.id) -and
        ($categories.Count -eq 0 -or $categories -contains (Get-Prop $_ 'category' ''))
    })
    $unknown = @($ids | Where-Object { $_ -ne 'all' -and -not ($Cat.apps.id -contains $_) })
    if ($unknown.Count) { throw "Unknown app ID(s): $($unknown -join ', '). Run with -List to see them." }
    if ($selected.Count -eq 0) { throw 'No apps selected.' }

    $prompts = @($Cat.prompts | ForEach-Object { $_.text })
    $promptText = if ($Prompt) { $Prompt } elseif ($prompts.Count) { $prompts[0] } else { 'Hello' }
    $settings = @{
        Apps = $selected; Modes = $modes; Prompts = $prompts; PromptText = $promptText
        RandomPrompt = [bool]$RandomPrompt; Shuffle = [bool]$Shuffle; Rounds = $Rounds
        DurationMinutes = $DurationMinutes; DelayMs = [Math]::Max(0, $DelayMs)
        Concurrency = [Math]::Max(1, $Concurrency); TimeoutSec = $TimeoutSec; Proxy = $Proxy
        UserAgent = [string](Get-Prop $Cat 'userAgent' 'Mozilla/5.0'); Markers = @(Get-Prop $Cat 'blockMarkers' @())
    }

    $until = if ($DurationMinutes -gt 0) { "for $DurationMinutes min" } elseif ($Rounds -le 0) { 'until Ctrl+C' } else { "$Rounds round(s)" }
    Write-Host "AI traffic generator: $($selected.Count) app(s), modes $($modes -join '/'), $until. Ctrl+C stops." -ForegroundColor Cyan

    $state = New-RunState $settings
    try {
        while (-not $state.Done) {
            foreach ($r in (Invoke-EngineStep $state)) {
                $color = $ResultColors[$r.Result]; if (-not $color) { $color = 'White' }
                $line = '{0} {1,-9} {2,-22} {3,-7} {4,-4} {5} [{6} ms] {7}' -f $r.Time.Substring(11), $r.Result, (Limit-Text $r.App 22), $r.Mode, $r.Status, (Limit-Text $r.Url 70), $r.Ms, $r.Detail
                Write-Host $line -ForegroundColor $color
            }
            if (-not $state.Done) { Start-Sleep -Milliseconds 50 }
        }
    } finally {
        if (-not $state.Done) { Stop-Run $state }
        Close-Run $state
        Write-Host (Get-Summary $state.Results) -ForegroundColor Cyan
        if ($OutCsv -and $state.Results.Count) {
            Export-Results $state.Results $OutCsv
            Write-Host "Results saved to $OutCsv" -ForegroundColor Cyan
        }
    }
}

# ---------------------------------------------------------------------------
# Window
# ---------------------------------------------------------------------------

function Show-Window {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $ui = @{ Catalog = $null; Apps = @(); State = $null; AllResults = (New-Object 'System.Collections.Generic.List[object]') }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'AI Traffic Generator'
    $form.Size = New-Object System.Drawing.Size(1250, 820)
    $form.MinimumSize = New-Object System.Drawing.Size(900, 600)
    $form.StartPosition = 'CenterScreen'
    $form.AutoScaleMode = 'Dpi'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'; $split.Orientation = 'Horizontal'
    $form.Controls.Add($split)

    $top = New-Object System.Windows.Forms.SplitContainer
    $top.Dock = 'Fill'
    $split.Panel1.Controls.Add($top)

    # --- Apps -----------------------------------------------------------------
    $appsBox = New-Object System.Windows.Forms.GroupBox
    $appsBox.Text = 'AI applications'; $appsBox.Dock = 'Fill'; $appsBox.Padding = New-Object System.Windows.Forms.Padding(6)
    $top.Panel1.Controls.Add($appsBox)

    $appList = New-Object System.Windows.Forms.CheckedListBox
    $appList.Dock = 'Fill'; $appList.CheckOnClick = $true; $appList.IntegralHeight = $false
    $appsBox.Controls.Add($appList)

    $appButtons = New-Object System.Windows.Forms.FlowLayoutPanel
    $appButtons.Dock = 'Top'; $appButtons.AutoSize = $true; $appButtons.WrapContents = $false
    $appsBox.Controls.Add($appButtons)
    $appList.BringToFront()  # dock the list below the buttons

    $btnAll = New-Object System.Windows.Forms.Button; $btnAll.Text = 'All'; $btnAll.AutoSize = $true
    $btnNone = New-Object System.Windows.Forms.Button; $btnNone.Text = 'None'; $btnNone.AutoSize = $true
    $cmbCategory = New-Object System.Windows.Forms.ComboBox; $cmbCategory.DropDownStyle = 'DropDownList'; $cmbCategory.Width = 170
    $appButtons.Controls.AddRange(@($btnAll, $btnNone, $cmbCategory))

    # --- Options --------------------------------------------------------------
    $optBox = New-Object System.Windows.Forms.GroupBox
    $optBox.Text = 'Traffic'; $optBox.Dock = 'Fill'; $optBox.Padding = New-Object System.Windows.Forms.Padding(6)
    $top.Panel2.Controls.Add($optBox)

    $grid = New-Object System.Windows.Forms.TableLayoutPanel
    $grid.Dock = 'Fill'; $grid.ColumnCount = 2
    [void]$grid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
    [void]$grid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    $optBox.Controls.Add($grid)

    function Add-Row([string]$Label, $Control, [string]$RowStyle = 'AutoSize') {
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $Label; $l.AutoSize = $true; $l.Anchor = 'Left'; $l.Margin = New-Object System.Windows.Forms.Padding(3, 7, 8, 3)
        $row = $grid.RowCount
        $grid.RowCount++
        if ($RowStyle -eq 'Fill') { [void]$grid.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100))) }
        else { [void]$grid.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize'))) }
        $grid.Controls.Add($l, 0, $row)
        $grid.Controls.Add($Control, 1, $row)
    }
    function New-Flow { $f = New-Object System.Windows.Forms.FlowLayoutPanel; $f.AutoSize = $true; $f.WrapContents = $true; $f.Dock = 'Fill'; $f.Margin = New-Object System.Windows.Forms.Padding(0); return $f }
    function New-Check([string]$Text, [bool]$Checked) { $c = New-Object System.Windows.Forms.CheckBox; $c.Text = $Text; $c.AutoSize = $true; $c.Checked = $Checked; return $c }
    function New-Number([int]$Min, [int]$Max, [int]$Value, [int]$Step = 1) {
        $n = New-Object System.Windows.Forms.NumericUpDown
        $n.Minimum = $Min; $n.Maximum = $Max; $n.Value = $Value; $n.Increment = $Step; $n.Width = 80
        return $n
    }
    function New-Caption([string]$Text) { $l = New-Object System.Windows.Forms.Label; $l.Text = $Text; $l.AutoSize = $true; $l.Margin = New-Object System.Windows.Forms.Padding(3, 7, 3, 3); return $l }

    $modeFlow = New-Flow
    $chkWeb = New-Check 'Web pages (GET)' $true
    $chkApi = New-Check 'API calls (POST prompt)' $true
    $chkBrowser = New-Check 'Open in browser' $false
    $modeFlow.Controls.AddRange(@($chkWeb, $chkApi, $chkBrowser))
    Add-Row 'Send' $modeFlow

    $promptFlow = New-Flow
    $cmbPrompt = New-Object System.Windows.Forms.ComboBox; $cmbPrompt.DropDownStyle = 'DropDownList'; $cmbPrompt.Width = 260
    $chkRandom = New-Check 'Random preset per app' $false
    $promptFlow.Controls.AddRange(@($cmbPrompt, $chkRandom))
    Add-Row 'Prompt' $promptFlow

    $txtPrompt = New-Object System.Windows.Forms.TextBox
    $txtPrompt.Multiline = $true; $txtPrompt.ScrollBars = 'Vertical'; $txtPrompt.Dock = 'Fill'; $txtPrompt.MinimumSize = New-Object System.Drawing.Size(0, 50)
    Add-Row '' $txtPrompt 'Fill'

    $repeatFlow = New-Flow
    $numRounds = New-Number 0 1000000 1
    $numDuration = New-Number 0 100000 0
    $repeatFlow.Controls.AddRange(@($numRounds, (New-Caption 'rounds (0 = until Stop)     or run for'), $numDuration, (New-Caption 'minutes (0 = off)')))
    Add-Row 'Repeat' $repeatFlow

    $paceFlow = New-Flow
    $numDelay = New-Number 0 3600000 500 100
    $numParallel = New-Number 1 64 4
    $numTimeout = New-Number 1 600 20
    $chkShuffle = New-Check 'Shuffle order' $false
    $paceFlow.Controls.AddRange(@((New-Caption 'Delay'), $numDelay, (New-Caption 'ms   Parallel'), $numParallel, (New-Caption 'Timeout'), $numTimeout, (New-Caption 's'), $chkShuffle))
    Add-Row 'Pace' $paceFlow

    $txtProxy = New-Object System.Windows.Forms.TextBox; $txtProxy.Dock = 'Fill'
    Add-Row 'Proxy' $txtProxy
    $proxyHint = New-Object System.Windows.Forms.ToolTip
    $proxyHint.SetToolTip($txtProxy, 'Empty = Windows proxy settings. Example: http://proxy.example.com:8080')

    $buttons = New-Flow
    $btnStart = New-Object System.Windows.Forms.Button; $btnStart.Text = 'Start'; $btnStart.Width = 90; $btnStart.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $btnStop = New-Object System.Windows.Forms.Button; $btnStop.Text = 'Stop'; $btnStop.Width = 80; $btnStop.Enabled = $false
    $btnClear = New-Object System.Windows.Forms.Button; $btnClear.Text = 'Clear results'; $btnClear.AutoSize = $true
    $btnExport = New-Object System.Windows.Forms.Button; $btnExport.Text = 'Export CSV...'; $btnExport.AutoSize = $true
    $btnEdit = New-Object System.Windows.Forms.Button; $btnEdit.Text = 'Edit catalogue'; $btnEdit.AutoSize = $true
    $btnReload = New-Object System.Windows.Forms.Button; $btnReload.Text = 'Reload catalogue'; $btnReload.AutoSize = $true
    $buttons.Controls.AddRange(@($btnStart, $btnStop, $btnClear, $btnExport, $btnEdit, $btnReload))
    Add-Row '' $buttons

    # --- Results --------------------------------------------------------------
    $list = New-Object System.Windows.Forms.ListView
    $list.Dock = 'Fill'; $list.View = 'Details'; $list.FullRowSelect = $true; $list.GridLines = $true; $list.HideSelection = $false
    foreach ($col in @(@('Time', 130), @('Result', 75), @('App', 140), @('Mode', 60), @('Status', 55), @('ms', 55), @('URL', 330), @('Detail', 600))) {
        [void]$list.Columns.Add($col[0], $col[1])
    }
    $split.Panel2.Controls.Add($list)

    $statusBar = New-Object System.Windows.Forms.StatusStrip
    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text = 'Ready'
    [void]$statusBar.Items.Add($statusLabel)
    $form.Controls.Add($statusBar)
    $split.BringToFront()  # fill the space above the status bar

    $rowColors = @{
        'Allowed' = [System.Drawing.Color]::FromArgb(225, 245, 225); 'Blocked' = [System.Drawing.Color]::FromArgb(250, 215, 215)
        'Blocked?' = [System.Drawing.Color]::FromArgb(245, 225, 245); 'TLS error' = [System.Drawing.Color]::FromArgb(255, 243, 205)
        'Timeout' = [System.Drawing.Color]::FromArgb(255, 243, 205); 'Error' = [System.Drawing.Color]::FromArgb(255, 243, 205)
        'Opened' = [System.Drawing.Color]::FromArgb(220, 238, 250)
    }

    # --- Behaviour ------------------------------------------------------------
    $loadCatalog = {
        try { $ui.Catalog = Read-Catalog $Catalog }
        catch { [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Catalogue', 'OK', 'Error'); return }
        $checkedIds = @($ui.Apps | Where-Object { $appList.CheckedItems.Contains($_.Label) } | ForEach-Object { $_.App.id })
        $firstLoad = $ui.Apps.Count -eq 0
        $appList.Items.Clear()
        $ui.Apps = @()
        foreach ($app in @($ui.Catalog.apps)) {
            $kinds = @(Get-AppModes $app | Where-Object { $_ -ne 'Browser' }) -join '+'
            $label = '{0}   [{1}, {2}]' -f $app.name, (Get-Prop $app 'category' 'Other'), $kinds
            $ui.Apps += [pscustomobject]@{ App = $app; Label = $label }
            [void]$appList.Items.Add($label, ($firstLoad -or $checkedIds -contains $app.id))
        }
        $cmbCategory.Items.Clear()
        [void]$cmbCategory.Items.Add('Select category...')
        foreach ($c in (@($ui.Catalog.apps) | ForEach-Object { Get-Prop $_ 'category' 'Other' } | Sort-Object -Unique)) { [void]$cmbCategory.Items.Add($c) }
        $cmbCategory.SelectedIndex = 0
        $cmbPrompt.Items.Clear()
        foreach ($p in @($ui.Catalog.prompts)) { [void]$cmbPrompt.Items.Add($p.name) }
        [void]$cmbPrompt.Items.Add('(custom)')
        $cmbPrompt.SelectedIndex = 0
        $statusLabel.Text = "Catalogue: $($ui.Apps.Count) apps, $(@($ui.Catalog.prompts).Count) prompts - $Catalog"
    }

    $cmbPrompt.Add_SelectedIndexChanged({
        $i = $cmbPrompt.SelectedIndex
        $presets = @($ui.Catalog.prompts)
        if ($i -ge 0 -and $i -lt $presets.Count) { $txtPrompt.Text = $presets[$i].text }
    })
    $txtPrompt.Add_TextChanged({
        $i = $cmbPrompt.SelectedIndex
        $presets = @($ui.Catalog.prompts)
        if ($i -ge 0 -and $i -lt $presets.Count -and $txtPrompt.Text -ne $presets[$i].text) { $cmbPrompt.SelectedIndex = $cmbPrompt.Items.Count - 1 }
    })

    $btnAll.Add_Click({ for ($i = 0; $i -lt $appList.Items.Count; $i++) { $appList.SetItemChecked($i, $true) } })
    $btnNone.Add_Click({ for ($i = 0; $i -lt $appList.Items.Count; $i++) { $appList.SetItemChecked($i, $false) } })
    $cmbCategory.Add_SelectedIndexChanged({
        if ($cmbCategory.SelectedIndex -le 0) { return }
        $cat = [string]$cmbCategory.SelectedItem
        for ($i = 0; $i -lt $ui.Apps.Count; $i++) {
            if ((Get-Prop $ui.Apps[$i].App 'category' 'Other') -eq $cat) { $appList.SetItemChecked($i, $true) }
        }
        $cmbCategory.SelectedIndex = 0
    })

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 100

    $setRunning = {
        param([bool]$Running)
        $btnStart.Enabled = -not $Running; $btnStop.Enabled = $Running; $btnReload.Enabled = -not $Running
        $appList.Enabled = -not $Running
    }

    $btnStart.Add_Click({
        $modes = @()
        if ($chkWeb.Checked) { $modes += 'Web' }
        if ($chkApi.Checked) { $modes += 'Api' }
        if ($chkBrowser.Checked) { $modes += 'Browser' }
        $apps = @(for ($i = 0; $i -lt $ui.Apps.Count; $i++) { if ($appList.GetItemChecked($i)) { $ui.Apps[$i].App } })
        if ($modes.Count -eq 0) { [void][System.Windows.Forms.MessageBox]::Show('Choose at least one traffic type.', 'AI Traffic Generator'); return }
        if ($apps.Count -eq 0) { [void][System.Windows.Forms.MessageBox]::Show('Tick at least one application.', 'AI Traffic Generator'); return }
        $prompts = @($ui.Catalog.prompts | ForEach-Object { $_.text })
        if (-not $txtPrompt.Text.Trim() -and -not $chkRandom.Checked) { [void][System.Windows.Forms.MessageBox]::Show('Enter a prompt.', 'AI Traffic Generator'); return }
        if ($modes -contains 'Browser' -and ($numRounds.Value -eq 0 -or $numRounds.Value * $apps.Count -gt 20)) {
            $answer = [System.Windows.Forms.MessageBox]::Show("'Open in browser' will open many browser tabs. Continue?", 'AI Traffic Generator', 'YesNo', 'Warning')
            if ($answer -ne 'Yes') { return }
        }
        $settings = @{
            Apps = $apps; Modes = $modes; Prompts = $prompts; PromptText = $txtPrompt.Text.Trim()
            RandomPrompt = $chkRandom.Checked; Shuffle = $chkShuffle.Checked; Rounds = [int]$numRounds.Value
            DurationMinutes = [int]$numDuration.Value; DelayMs = [int]$numDelay.Value
            Concurrency = [int]$numParallel.Value; TimeoutSec = [int]$numTimeout.Value; Proxy = $txtProxy.Text.Trim()
            UserAgent = [string](Get-Prop $ui.Catalog 'userAgent' 'Mozilla/5.0'); Markers = @(Get-Prop $ui.Catalog 'blockMarkers' @())
        }
        try { $ui.State = New-RunState $settings }
        catch { [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'AI Traffic Generator', 'OK', 'Error'); return }
        & $setRunning $true
        $timer.Start()
    })

    $btnStop.Add_Click({ if ($ui.State) { Stop-Run $ui.State; $statusLabel.Text = 'Stopping...' } })

    $timer.Add_Tick({
        $state = $ui.State
        if (-not $state) { $timer.Stop(); return }
        $timer.Stop()  # no re-entry while this tick runs
        try {
            $new = Invoke-EngineStep $state
            if ($new.Count) {
                $list.BeginUpdate()
                foreach ($r in $new) {
                    $ui.AllResults.Add($r)
                    $item = New-Object System.Windows.Forms.ListViewItem($r.Time)
                    foreach ($v in @($r.Result, $r.App, $r.Mode, [string]$r.Status, [string]$r.Ms, $r.Url, $r.Detail)) { [void]$item.SubItems.Add([string]$v) }
                    $color = $rowColors[$r.Result]; if ($color) { $item.BackColor = $color }
                    $item.Tag = $r
                    [void]$list.Items.Add($item)
                }
                while ($list.Items.Count -gt 5000) { $list.Items.RemoveAt(0) }
                $list.EndUpdate()
                $list.Items[$list.Items.Count - 1].EnsureVisible()
            }
            $where = if ($state.EndTime) { 'until ' + $state.EndTime.ToString('HH:mm') } elseif ($state.Settings.Rounds -le 0) { 'until Stop' } else { "of $($state.Settings.Rounds)" }
            $statusLabel.Text = "Round $($state.Round) $where | in flight: $($state.InFlight.Count) | " + (Get-Summary $ui.AllResults)
            if ($state.Done) {
                Close-Run $state
                $ui.State = $null
                & $setRunning $false
                $statusLabel.Text = 'Finished | ' + (Get-Summary $ui.AllResults)
                return
            }
        } catch {
            Stop-Run $state
            Close-Run $state
            $ui.State = $null
            & $setRunning $false
            [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'AI Traffic Generator', 'OK', 'Error')
            return
        }
        $timer.Start()
    })

    $btnClear.Add_Click({ $list.Items.Clear(); $ui.AllResults.Clear(); $statusLabel.Text = 'Results cleared' })

    $btnExport.Add_Click({
        if ($ui.AllResults.Count -eq 0) { [void][System.Windows.Forms.MessageBox]::Show('No results yet.', 'AI Traffic Generator'); return }
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Filter = 'CSV files (*.csv)|*.csv'
        $dialog.FileName = 'ai-traffic-' + (Get-Date).ToString('yyyyMMdd-HHmmss') + '.csv'
        if ($dialog.ShowDialog($form) -eq 'OK') {
            Export-Results $ui.AllResults $dialog.FileName
            $statusLabel.Text = "Saved $($ui.AllResults.Count) results to $($dialog.FileName)"
        }
    })

    $btnEdit.Add_Click({ Start-Process notepad.exe -ArgumentList "`"$Catalog`"" })
    $btnReload.Add_Click({ & $loadCatalog })

    $list.Add_DoubleClick({
        if ($list.SelectedItems.Count -eq 0) { return }
        $r = $list.SelectedItems[0].Tag
        $text = ($r.PSObject.Properties | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Value }) -join "`r`n"
        [System.Windows.Forms.Clipboard]::SetText($text)
        [void][System.Windows.Forms.MessageBox]::Show($text + "`r`n`r`n(copied to clipboard)", 'Request details')
    })

    # Splitter positions can only be set once the form has its size.
    $form.Add_Shown({
        $split.SplitterDistance = [Math]::Min(380, $split.Height - 150)
        $top.SplitterDistance = [Math]::Min(430, $top.Width - 400)
    })

    $form.Add_FormClosing({
        $timer.Stop()
        if ($ui.State) { Stop-Run $ui.State; Close-Run $ui.State; $ui.State = $null }
    })

    & $loadCatalog
    if (-not $ui.Catalog) { return }
    [void]$form.ShowDialog()
    $form.Dispose()
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if ($List) {
    $cat = Read-Catalog $Catalog
    $cat.apps | ForEach-Object {
        [pscustomobject]@{ Id = $_.id; Name = $_.name; Category = (Get-Prop $_ 'category' ''); Modes = (Get-AppModes $_) -join ',' }
    } | Format-Table -AutoSize | Out-String -Width 200
    return
}

if ($NoGui) {
    Invoke-Console (Read-Catalog $Catalog)
} else {
    Show-Window
}
