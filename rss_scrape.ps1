$date_find = Get-Date -Format "MMMM yyyy"
$kbList = @()
$cveList = @()
$collectionWithItems_KB = New-Object System.Collections.ArrayList
$collectionWithItems_CVE = New-Object System.Collections.ArrayList
$kb_regex = 'KB(\d{7,8})|[uU]pdate (\d{7,8})'
$cve_regex = 'CVE-\d{4}-\d*'

[xml]$tenable_feed = Invoke-WebRequest "https://www.tenable.com/plugins/feeds?sort=newest"
$parsedInput = $tenable_feed.rss.channel.item | Select-Object guid, link, pubDate, @{N="Title"; E={$_.ChildNodes.item(0).InnerText}},@{N="Description"; E={($_.ChildNodes.item(4).InnerText) -replace '<[^>]+>',''}} #| Export-Csv "plugin_feed.csv" -NoTypeInformation -Delimiter:"," -Encoding:UTF8
$parsedInput | ForEach-Object {
    if (($_.Title -match $date_find) -or ($_.Title -match ".*Windows.*Security Update") -or ($_.Title -match ".*Microsoft.*")) {
        $kb = $_.Description | Select-String -Pattern $kb_regex -AllMatches | % { $_.Matches.Groups } | % { $_.Value } | Select -index (1,2)
        $cve = $_.Description | Select-String -Pattern $cve_regex -AllMatches | % { $_.Matches.Groups } | % { $_.Value } 
        $kbList += $kb
        $cveList += $cve

    }
}

$kbList | Select-Object -Unique | Where-Object { $_ -ne "" } | ForEach-Object {
    $temp = New-Object psobject
    $kb_name = "KB" + $_
    $temp | Add-Member -MemberType NoteProperty -Name "kb" -Value $kb_name
    $collectionWithItems_KB.Add($temp) | Out-Null
}

$cveList | Select-Object -Unique | ForEach-Object {
    $temp = New-Object psobject
    $cve_name = "$_".ToUpper()
    $temp | Add-Member -MemberType NoteProperty -Name "cve" -Value $cve_name
    $collectionWithItems_CVE.Add($temp) | Out-Null
}

$collectionWithItems_KB | Sort-Object -Descending | Export-Csv -NoTypeInformation -Path kb-dump-$date.csv
$collectionWithItems_CVE | Sort-Object -Descending | Export-Csv -NoTypeInformation -Path cve-dump-$date.csv