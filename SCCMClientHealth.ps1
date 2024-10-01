try {
    if (-not (Get-Module dbatools -ListAvailable)) {
        Install-Module dbatools
    }
}
catch {
    Write-Warning "Warning: Could not install dbatools module"
}


$dbhost = "atklsccm.kostweingroup.intern" # site SQL host FQDN
$cmhost = "atklsccm.kostweingroup.intern" # CM primary site host FQDN
$site = "KOW" # CM site code
$cmdb = "CM_KOW" # CM site database

. .\SCCMSQLQueries.ps1

$ServerServiceUsers = Invoke-DbaQuery -SqlInstance $dbhost -Database $cmdb -Query $ServiceUsers
$ServerServiceUsers | ConvertTo-Csv -NoTypeInformation -Delimiter ';' | Out-File -FilePath "\\atklsccm.kostweingroup.intern\sources`$\Logs\CMSRVServiceAccounts.csv" #-Append

$ClientFailedUnknown = Invoke-DbaQuery -SqlInstance $dbhost -Database $cmdb -Query $FailedUnknownClientHealth
#$ClientHealth = Invoke-DbaQuery -SqlInstance $dbhost -Database $cmdb -Query $v_CH_ClientHealth
#$ClientSummary = Invoke-DbaQuery -SqlInstance $dbhost -Database $cmdb -Query $v_CH_ClientSummary

$ClientSummary = $ClientFailedUnknown

$Active = $ClientSummary | Where-Object { $_.ClientStateDescription -match 'Active' }
$ActiveFail = $Active | Where-Object { $_.ClientStateDescription -match 'Fail' }
$ActivePass = $Active | Where-Object { $_.ClientStateDescription -match 'Pass' }
$ActiveUnknown = $Active | Where-Object { $_.ClientStateDescription -match 'Unknown' }

$Inactive = $ClientSummary | Where-Object { $_.ClientStateDescription -match 'Inactive' }
$InactiveFail = $Inactive | Where-Object { $_.ClientStateDescription -match 'Fail' }
$InactivePass = $Inactive | Where-Object { $_.ClientStateDescription -match 'Pass' }
$InactiveUnknown = $Inactive | Where-Object { $_.ClientStateDescription -match 'Unknown' }

$Fail = $ClientSummary | Where-Object { $_.ClientStateDescription -match 'Fail' }
$Pass = $ClientSummary | Where-Object { $_.ClientStateDescription -match 'Pass' }
$Unknown = $ClientSummary | Where-Object { $_.ClientStateDescription -match 'Unknown' }

$Clients = [PSCustomObject]@{
    Summary = $ClientSummary
    Fail    = $Fail
    Pass    = $Pass
    Unknown = $Unknown
    Active  = [PSCustomObject]@{
        Active = $Active
        Fail   = $ActiveFail
        Pass   = $ActivePass
        Unknown = $ActiveUnknown
    }
    Inactive = [PSCustomObject]@{
        Inactive = $Inactive
        Fail     = $InactiveFail
        Pass     = $InactivePass
        Unknown  = $InactiveUnknown
    }
}

Start-Sleep -Seconds 1
