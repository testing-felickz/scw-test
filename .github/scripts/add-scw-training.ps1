[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$InputPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [string]$LanguageKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$apiEndpoint = 'https://integration-api.securecodewarrior.com/api/v1/trial'
$partnerId = 'github'
$integrationId = 'github'
$trainingMarker = '<!-- scw-contextual-training:github -->'
$cwePattern = '(?i)\bCWE(?:[-_/:\\\s]|%2D)*0*(?<id>[1-9][0-9]{0,5})\b'

function Get-PropertyValue {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Set-PropertyValue {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Value
    )

    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function Get-CweIds {
    param(
        [object]$Rule,
        [string]$ResultContext
    )

    $cweIds = [System.Collections.Generic.HashSet[string]]::new()
    $searchText = ($Rule | ConvertTo-Json -Depth 30 -Compress) + "`n" + $ResultContext

    foreach ($match in [regex]::Matches($searchText, $cwePattern)) {
        $null = $cweIds.Add(([int]$match.Groups['id'].Value).ToString())
    }

    foreach ($relationship in @(Get-PropertyValue $Rule 'relationships')) {
        $target = Get-PropertyValue $relationship 'target'
        $targetId = [string](Get-PropertyValue $target 'id')
        $toolComponent = Get-PropertyValue $target 'toolComponent'
        $toolComponentName = [string](Get-PropertyValue $toolComponent 'name')

        if ($toolComponentName -match '(?i)\bCWE\b' -and $targetId -match '^\s*0*(?<id>[1-9][0-9]{0,5})\s*$') {
            $null = $cweIds.Add(([int]$Matches['id']).ToString())
        }
    }

    return @($cweIds | Sort-Object { [int]$_ })
}

function Get-TrainingData {
    param([string]$CweId)

    $query = [ordered]@{
        Id            = $partnerId
        MappingList   = 'CWE'
        MappingKey    = $CweId
        IntegrationId = $integrationId
    }
    if (-not [string]::IsNullOrWhiteSpace($LanguageKey)) {
        $query.LanguageKey = $LanguageKey
    }

    $queryString = ($query.GetEnumerator() | ForEach-Object {
        '{0}={1}' -f [uri]::EscapeDataString($_.Key), [uri]::EscapeDataString([string]$_.Value)
    }) -join '&'

    try {
        return Invoke-RestMethod -Method Get -Uri "$apiEndpoint`?$queryString"
    }
    catch {
        $statusCode = if ($null -ne $_.Exception.Response) {
            [int]$_.Exception.Response.StatusCode
        }
        else {
            $null
        }

        if ($statusCode -eq 404) {
            Write-Warning "Secure Code Warrior has no training mapping for CWE-$CweId."
            return $null
        }

        throw
    }
}

$resolvedInputPath = (Resolve-Path -LiteralPath $InputPath).Path
$sarif = Get-Content -Raw -LiteralPath $resolvedInputPath | ConvertFrom-Json -Depth 100
if ((Get-PropertyValue $sarif 'version') -ne '2.1.0') {
    throw "Unsupported SARIF version in '$resolvedInputPath'. Expected 2.1.0."
}

$trainingCache = @{}
$enrichedRuleCount = 0

foreach ($run in @(Get-PropertyValue $sarif 'runs')) {
    $triggeredRuleIds = [System.Collections.Generic.HashSet[string]]::new()
    $resultContextByRule = @{}

    foreach ($result in @(Get-PropertyValue $run 'results')) {
        $ruleId = [string](Get-PropertyValue $result 'ruleId')
        if ([string]::IsNullOrWhiteSpace($ruleId)) {
            $ruleId = [string](Get-PropertyValue (Get-PropertyValue $result 'rule') 'id')
        }
        if ([string]::IsNullOrWhiteSpace($ruleId)) {
            continue
        }

        $null = $triggeredRuleIds.Add($ruleId)
        $resultJson = $result | ConvertTo-Json -Depth 30 -Compress
        $resultContextByRule[$ruleId] = @($resultContextByRule[$ruleId], $resultJson) -join "`n"
    }

    $tool = Get-PropertyValue $run 'tool'
    $components = [System.Collections.Generic.List[object]]::new()
    $driver = Get-PropertyValue $tool 'driver'
    if ($null -ne $driver) {
        $components.Add($driver)
    }
    foreach ($extension in @(Get-PropertyValue $tool 'extensions')) {
        $components.Add($extension)
    }

    foreach ($component in $components) {
        foreach ($rule in @(Get-PropertyValue $component 'rules')) {
            $ruleId = [string](Get-PropertyValue $rule 'id')
            if ([string]::IsNullOrWhiteSpace($ruleId) -or -not $triggeredRuleIds.Contains($ruleId)) {
                continue
            }

            $help = Get-PropertyValue $rule 'help'
            $existingMarkdown = [string](Get-PropertyValue $help 'markdown')
            if ($existingMarkdown.Contains($trainingMarker)) {
                continue
            }

            $cweIds = @(Get-CweIds -Rule $rule -ResultContext ([string]$resultContextByRule[$ruleId]))
            if ($cweIds.Count -eq 0) {
                Write-Warning "No CWE indicator found for triggered rule '$ruleId'."
                continue
            }

            $textEntries = [System.Collections.Generic.List[string]]::new()
            $markdownEntries = [System.Collections.Generic.List[string]]::new()

            foreach ($cweId in $cweIds) {
                $cacheKey = "$LanguageKey|$cweId"
                if (-not $trainingCache.ContainsKey($cacheKey)) {
                    $trainingCache[$cacheKey] = Get-TrainingData -CweId $cweId
                }
                $training = $trainingCache[$cacheKey]
                if ($null -eq $training) {
                    continue
                }

                $name = [string](Get-PropertyValue $training 'name')
                $description = [string](Get-PropertyValue $training 'description')
                $trainingUrl = [string](Get-PropertyValue $training 'url')
                if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($trainingUrl)) {
                    throw "Secure Code Warrior returned incomplete training data for CWE-$cweId."
                }

                $trainingUrl = $trainingUrl.Replace(' ', '%20')
                $videoUrl = [string](@(Get-PropertyValue $training 'videos') | Select-Object -First 1)
                if (-not [string]::IsNullOrWhiteSpace($videoUrl)) {
                    $videoUrl = $videoUrl.Replace(' ', '%20')
                }

                $textEntry = "[CWE-$cweId] $name"
                $markdownEntry = "#### [CWE-$cweId] $name"
                if (-not [string]::IsNullOrWhiteSpace($videoUrl)) {
                    $textEntry += " [Watch the explainer video]($videoUrl)"
                    $markdownEntry += " *[Watch the explainer video]($videoUrl)*"
                }

                if (-not [string]::IsNullOrWhiteSpace($description)) {
                    $textEntry += "`n`n$description"
                    $markdownEntry += "`n`n$description"
                }
                $textEntry += " [Try this challenge in Secure Code Warrior]($trainingUrl)"
                $markdownEntry += " [Try this challenge in Secure Code Warrior]($trainingUrl)"

                $textEntries.Add($textEntry)
                $markdownEntries.Add($markdownEntry)
            }

            if ($markdownEntries.Count -eq 0) {
                continue
            }

            $fullDescription = Get-PropertyValue $rule 'fullDescription'
            if ($null -eq $help) {
                $help = [pscustomobject]@{}
                Set-PropertyValue $rule 'help' $help
            }

            $existingText = [string](Get-PropertyValue $help 'text')
            if ([string]::IsNullOrWhiteSpace($existingText)) {
                $existingText = [string](Get-PropertyValue $fullDescription 'text')
            }
            if ([string]::IsNullOrWhiteSpace($existingMarkdown)) {
                $existingMarkdown = [string](Get-PropertyValue $fullDescription 'markdown')
            }
            if ([string]::IsNullOrWhiteSpace($existingMarkdown)) {
                $existingMarkdown = $existingText
            }

            $newText = @(
                $existingText
                'Build your secure coding skills and defend your code:'
                ($textEntries -join "`n`n")
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

            $newMarkdown = @(
                $existingMarkdown
                '## Build your secure coding skills and defend your code'
                ($markdownEntries -join "`n`n")
                $trainingMarker
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

            Set-PropertyValue $help 'text' ($newText -join "`n`n")
            Set-PropertyValue $help 'markdown' ($newMarkdown -join "`n`n")
            $enrichedRuleCount++
        }
    }
}

$resolvedOutputPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutputPath
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    $null = New-Item -ItemType Directory -Path $outputDirectory -Force
}

$sarif | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $resolvedOutputPath -Encoding utf8NoBOM
Write-Output "Enriched $enrichedRuleCount triggered SARIF rule(s) with Secure Code Warrior training."
