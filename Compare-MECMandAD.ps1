
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

#Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true -PassThru | Register-DbatoolsConfig -Scope SystemDefault

$Query = @"
select * from v_CombinedDeviceResources where (name not like '%unknown%') and (name not like '%provisioning device%') order by name
"@

$CMDevices = Invoke-DbaQuery -SqlInstance $dbhost -Database $cmdb -Query $Query | 
    Select-Object Name, MachineID, SerialNumber, MACAddress, DeviceOS, DeviceOSBuild, CoManaged, ClientVersion, ClientActiveStatus, ClientRemediationSuccess, IsActive, LastSuccessSyncTimeUTC, LastStatusMessage, IsVirtualMachine, ADSiteName, LastMPServerName, LastPolicyRequest, LastDDR, LastHardwareScan, LastSoftwareScan, LastActiveTime, LastClientCheckTime, ClientCheckPass

$ADComps = Get-ADComputer -Filter * -Properties lastlogontimestamp, whenCreated, operatingsystem, description | Where-Object { $_.DistinguishedName -notmatch 'loeschen' } | Select-Object Name, OperatingSystem, Description, @{n = 'LastLogon'; e = { [DateTime]::FromFileTime($_.LastLogonTimeStamp) } }, whenCreated

$ADWorkstations = $ADComps | Where-Object { $_.OperatingSystem -match 'Workstation|Windows 1' }
#$CMWorkstations = $CMDevices | Where-Object { ([string]::IsNullOrEmpty($_.IsVirtualMachine) -or $_.IsVirtualMachine -eq $False) -and ([string]::IsNullOrEmpty($_.DeviceOS) -or $_.DeviceOS -match 'Workstation') }
$CMWorkstations = $CMDevices | Where-Object { $_.DeviceOS -match 'Workstation' }
#$CMUndefinedDevices = $CMDevices | Where-Object { ([string]::IsNullOrEmpty($_.IsVirtualMachine) -or $_.IsVirtualMachine -eq $False) -and [string]::IsNullOrEmpty($_.DeviceOS) }
#$CMUndefinedWorkstations = $CMUndefinedDevices | Where-Object { $_.Name -in $ADWorkstations.Name }

$OldOrMissingHWInventory = $CMDevices | Where-Object { [string]::IsNullOrEmpty($_.LastHardwareScan) }
$HWInventoryNotSince30d = $CMDevices | Where-Object { (-not[string]::IsNullOrEmpty($_.LastHardwareScan)) -and ((New-TimeSpan -Start $_.LastHardwareScan -End (Get-Date)).Days -gt 30) }
$LastActive90d = $CMDevices | Where-Object { [string]::IsNullOrEmpty($_.LastActiveTime) -or ((New-TimeSpan -Start $_.LastActiveTime -End (Get-Date)).Days -gt 90) }

$WSADLastActive90d = $ADWorkstations | Where-Object { (New-TimeSpan -Start $_.LastLogon -End (Get-Date)).Days -gt 90 }

$MissingInMECM = $ADComps | Where-Object { $_.Name -notin $CMDevices.Name } | Select-Object Name
$MissingInAD = $CMDevices | Where-Object { $_.Name -notin $ADComps.Name } | Select-Object Name


$WSMissingInMECM = $ADWorkstations | Where-Object { $_.Name -notin $CMWorkstations.Name } | Select-Object Name
$WSMissingInAD = $CMWorkstations | Where-Object { $_.Name -notin $ADWorkstations.Name } | Select-Object Name

$AllDevices = foreach ($Device in $CMDevices) {
    
    $ADDevice = $ADComps | Where-Object { $_.Name -eq $Device.Name }

    [PSCustomObject]@{
        Name                     = $Device.Name
        MachineID                = $Device.MachineID
        SerialNumber             = $Device.SerialNumber
        MACAddress               = $Device.MACAddress
        DeviceOS                 = $Device.DeviceOS
        DeviceOSBuild            = $Device.DeviceOSBuild
        IsActive                 = $Device.IsActive
        ClientVersion            = $Device.ClientVersion
        ClientActiveStatus       = $Device.ClientActiveStatus
        ClientRemediationSuccess = $Device.ClientRemediationSuccess
        IsVirtualMachine         = $Device.IsVirtualMachine
        ADSiteName               = $Device.ADSiteName
        LastSuccessSyncTimeUTC   = $Device.LastSuccessSyncTimeUTC
        LastStatusMessage        = $Device.LastStatusMessage
        LastMPServerName         = $Device.LastMPServerName
        LastPolicyRequest        = $Device.LastPolicyRequest
        LastDDR                  = $Device.LastDDR
        LastHardwareScan         = $Device.LastHardwareScan
        LastSoftwareScan         = $Device.LastSoftwareScan
        LastActiveTime           = $Device.LastActiveTime
        LastClientCheckTime      = $Device.LastClientCheckTime
        ClientCheckPass          = $Device.ClientCheckPass
        OperatingSystem          = $ADDevice.OperatingSystem
        LastLogon                = $ADDevice.LastLogon
        whenCreated              = $ADDevice.whenCreated
    }
}

$AllWorkstations = $AllDevices | Where-Object { $_.OperatingSystem -match 'Windows 1' }

$AllWorkstationsNoClient = $AllWorkstations | Where-Object { [string]::IsNullOrEmpty($_.ClientCheckPass) }
$AllWorkstationsClient = $AllWorkstations | Where-Object { (-not[string]::IsNullOrEmpty($_.ClientCheckPass)) }
$AllWorkstationsHealthy = $AllWorkstations | Where-Object { $_.ClientCheckPass -eq 1 }
$AllWorkstationsUnHealthy = $AllWorkstations | Where-Object { $_.ClientCheckPass -eq 2 }
$AllWorkstationsUnknownHealth = $AllWorkstations | Where-Object { $_.ClientCheckPass -eq 3 }

$AllWorkstationsNoClientOnline = foreach ($Device in $AllWorkstationsNoClient) {

    $LastLogonDays = (New-Timespan -Start $Device.LastLogon -End ([DateTime]::now)).Days -lt 7

    if ($LastLogonDays) {
        
        if (Test-Connection -Ping -IPv4 -Count 1 -Quiet -TargetName $Device.Name) {
            $Device | Add-Member -MemberType NoteProperty -Name 'Online' -Value $TestPing
            $Device
        }
        
    }
    
}

$WSActiveClients = $AllWorkstationsClient | Where-Object { $_.ClientActiveStatus -eq 1 }
$WSInactiveClients = $AllWorkstationsClient | Where-Object { $_.Name -notin $WSActiveClients.Name }

$WSInactiveClientsOnline = foreach ($Device in $WSInactiveClients) {

    $LastLogonDays = (New-Timespan -Start $Device.LastLogon -End ([DateTime]::now)).Days -lt 7

    if ($LastLogonDays) {
        
        if (Test-Connection -Ping -IPv4 -Count 1 -Quiet -TargetName $Device.Name) {
            $Device | Add-Member -MemberType NoteProperty -Name 'Online' -Value $TestPing
            $Device
        }
        
    }
    
}

$WSMissingClientCheck = $AllWorkstationsClient | Where-Object { [string]::IsNullOrEmpty($_.LastClientCheckTime) }
$WSLastClientCheck30d = $AllWorkstations | Where-Object { (-not[string]::IsNullOrEmpty($_.LastClientCheckTime)) -and ((New-TimeSpan -Start $_.LastClientCheckTime -End (Get-Date)).Days -gt 30) }

$WSOldOrMissingHWInventory = $AllWorkstations | Where-Object { [string]::IsNullOrEmpty($_.LastHardwareScan) }
$WSHWInventoryNotSince30d = $AllWorkstations | Where-Object { (-not[string]::IsNullOrEmpty($_.LastHardwareScan)) -and ((New-TimeSpan -Start $_.LastHardwareScan -End (Get-Date)).Days -gt 30) }

$WSOldOrMissingSWInventory = $AllWorkstations | Where-Object { [string]::IsNullOrEmpty($_.LastSoftwareScan) }
$WSSWInventoryNotSince30d = $AllWorkstations | Where-Object { (-not[string]::IsNullOrEmpty($_.LastSoftwareScan)) -and ((New-TimeSpan -Start $_.LastSoftwareScan -End (Get-Date)).Days -gt 30) }

$WSADLastActive90d = $AllWorkstations | Where-Object { (New-TimeSpan -Start $_.LastLogon -End (Get-Date)).Days -gt 90 }
$WSCMLastActive90d = $AllWorkstations | Where-Object { [string]::IsNullOrEmpty($_.LastActiveTime) -or ((New-TimeSpan -Start $_.LastActiveTime -End (Get-Date)).Days -gt 90) }
$WSLastActive90d = $AllWorkstations | Where-Object { [string]::IsNullOrEmpty($_.LastActiveTime) -or ((New-TimeSpan -Start $_.LastActiveTime -End (Get-Date)).Days -gt 90) }

$CMLast90AndADLast90 = $WSCMLastActive90d | Where-Object { $_.Name -in $WSADLastActive90d.Name }
$CMLast90NotADLast90 = $WSCMLastActive90d | Where-Object { $_.Name -notin $WSADLastActive90d.Name }

$Workstations = [PSCustomObject]@{
    AllWorkstations              = $AllWorkstations | Sort-Object -Property Name
    AllWorkstationsNoClient      = $AllWorkstationsNoClient
    AllWorkstationsClient        = $AllWorkstationsClient
    AllWorkstationsHealthy       = $AllWorkstationsHealthy
    AllWorkstationsUnHealthy     = $AllWorkstationsUnHealthy
    AllWorkstationsUnknownHealth = $AllWorkstationsUnknownHealth
    ActiveClients                = $WSActiveClients
    InactiveClients              = $WSInactiveClients | Sort-Object -Property LastLogon -Descending
    MissingClientCheck           = $WSMissingClientCheck
    LastClientCheck30d           = $WSLastClientCheck30d | Sort-Object -Property LastClientCheckTime
    OldOrMissingHWInventory      = $WSOldOrMissingHWInventory | Sort-Object -Property LastHardwareScan
    HWInventoryNotSince30d       = $WSHWInventoryNotSince30d | Sort-Object -Property LastHardwareScan
    OldOrMissingSWInventory      = $WSOldOrMissingSWInventory | Sort-Object -Property LastSoftwareScan
    SWInventoryNotSince30d       = $WSSWInventoryNotSince30d | Sort-Object -Property LastSoftwareScan
    LastActive90d                = $WSLastActive90d | Sort-Object -Property LastLogon
    LastActive90dCMandAD         = $CMLast90AndADLast90 | Sort-Object -Property LastLogon
    LastActive90dCMnotAD         = $CMLast90NotADLast90 | Sort-Object -Property LastLogon
    MissingInMECM                = $WSMissingInMECM | Sort-Object -Property Name
    MissingInAD                  = $WSMissingInAD | Sort-Object -Property Name
    NoClientOnline               = $AllWorkstationsNoClientOnline
    InactiveClientOnline         = $WSInactiveClientsOnline
}

$Workstations = [PSCustomObject]@{
    AllWorkstations              = $AllWorkstations | Sort-Object -Property Name
    NoClient = [PSCustomObject]@{
        All = $AllWorkstationsNoClient
        Online = $AllWorkstationsNoClientOnline
    }
    Client   = [PSCustomObject]@{
        All = $AllWorkstationsClient
        Health = [PSCustomObject]@{
            Healthy = $AllWorkstationsHealthy
            Unhealthy = $AllWorkstationsUnHealthy
            Unknown = $AllWorkstationsUnknownHealth
        }
        Status = [PSCustomObject]@{
            Active = $WSActiveClients
            Inactive = $WSInactiveClients
            InactiveOnline = $WSInactiveClientsOnline
        }
        Checks = [PSCustomObject]@{
            Client = [PSCustomObject]@{
                Missing = $WSMissingClientCheck
                30d     = $WSLastClientCheck30d | Where-Object { $_.Name -notin $WSInactiveClients.Name -and $_.Name -notin $WSLastActive90d.Name }
            }
            Hardware = [PSCustomObject]@{
                Missing = $WSOldOrMissingHWInventory | Where-Object { $_.Name -notin $AllWorkstationsNoClient.Name -and $_.Name -notin $WSLastActive90d.Name }
                30d     = $WSHWInventoryNotSince30d | Where-Object { $_.Name -notin $WSInactiveClients.Name -and $_.Name -notin $WSLastActive90d.Name }
            }
            Software = [PSCustomObject]@{
                Missing = $WSOldOrMissingSWInventory | Where-Object { $_.Name -notin $AllWorkstationsNoClient.Name -and $_.Name -notin $WSLastActive90d.Name }
                30d     = $WSSWInventoryNotSince30d | Where-Object { $_.Name -notin $WSInactiveClients.Name -and $_.Name -notin $WSLastActive90d.Name }
            }
        }
    }

}

$Now = Get-Date -Format 'yyyyMMdd'
$Workstations | ConvertTo-Json -Depth 50 | Out-File "WorkstationsReport_$($Now).json"

$AllWorkstationsNoClient | Sort-Object -Property LastLogon | ConvertTo-Csv -Delimiter ';' | Out-File -FilePath "WorkstationsNoClient_$($Now).csv"
$AllWorkstationsUnHealthy | Sort-Object -Property LastLogon | ConvertTo-Csv -Delimiter ';' | Out-File -FilePath "WorkstationsUnhealthyClient_$($Now).csv"
$AllWorkstationsUnknownHealth | Sort-Object -Property LastLogon | ConvertTo-Csv -Delimiter ';' | Out-File -FilePath "WorkstationsUnknownHealth_$($Now).csv"
$WSClientCheckNotSince30d | Sort-Object -Property LastLogon | ConvertTo-Csv -Delimiter ';' | Out-File -FilePath "WorkstationsLastClientCheck30d_$($Now).csv"
$WSSWInventoryNotSince30d | Sort-Object -Property LastLogon | ConvertTo-Csv -Delimiter ';' | Out-File -FilePath "WorkstationsOldSWInventory_$($Now).csv"
$WSHWInventoryNotSince30d | Sort-Object -Property LastLogon | ConvertTo-Csv -Delimiter ';' | Out-File -FilePath "WorkstationsOldHWInventory_$($Now).csv"
$WSLastActive90d | Sort-Object -Property LastLogon | ConvertTo-Csv -Delimiter ';' | Out-File -FilePath "WorkstationsLastActive90d_$($Now).csv"
$WSMissingInAD | Sort-Object -Property LastLogon | ConvertTo-Csv -Delimiter ';' | Out-File -FilePath "WorkstationsNotinAD_$($Now).csv"


try {
    if (-not (Get-Module ConfigurationManager)) {
        Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" -Verbose:$false
    }
    $SiteCode = ( Get-PSDrive -ErrorAction SilentlyContinue | Where-Object { $_.Provider -like "*CMSite*" }).Name
}
catch {
    Write-Warning "Warning: Could not import the 'ConfigurationManager.psd1' module"
}

foreach ($Device in $CMLast90AndADLast90) {
    Write-Host "[$($Device.Name)] Processing" -ForegroundColor Cyan

    $ADDevice = Get-ADComputer -Identity $Device.Name
    if ($ADDevice) {
        
        if ($ADDevice.Enabled -eq $true) {
            Write-Host "[$($Device.Name)]  Disable Device in AD" -ForegroundColor Yellow
            Disable-ADAccount -Identity $ADDevice
        }
        
        if ($ADDevice.DistinguishedName -notmatch 'loeschen') {
            Write-Host "[$($Device.Name)]  Move Device to OU" -ForegroundColor Yellow
            Move-ADObject -Identity $ADDevice -TargetPath "OU=Allgemein zu Loeschen,DC=kostweingroup,DC=intern"
        }

    }
    
    Push-Location
    Set-Location "$($SiteCode):\"

    $CMDevice = Get-CMDevice -Name $Device.Name
    if ($CMDevice) {
        Write-Host "[$($Device.Name)]  Remove Device in CM" -ForegroundColor Yellow
        Remove-CMDevice -InputObject $CMDevice -Force
    }

    Pop-Location

}

$Report = [PSCustomObject]@{
    CMDevices               = $CMDevices
    ADDevices               = $ADComps
    OldOrMissingHWInventory = $OldOrMissingHWInventory
    HWInventoryNotSince30d  = $HWInventoryNotSince30d
    LastActive90d           = $LastActive90d
    MissingInMECM           = $MissingInMECM
    MissingInAD             = $MissingInAD
    CMWorkstations          = $CMWorkstations
}

$Report | ConvertTo-Json -Depth 50 | Out-File 'DevicesReport.json'

$ComputerName = 'PC985', 'PC674', 'LP819', 'LP1054', 'PC728'
$Namespace = "ROOT\ccm"
$ClassName = 'SMS_Client'
$MethodName = "TriggerSchedule"
$MethodParameters = @{ sScheduleID = '{00000000-0000-0000-0000-000000000001}' }

foreach ($Computer in $ComputerName) {
    try {
        Invoke-CimMethod -ComputerName $Computer -Namespace $Namespace -ClassName $ClassName -MethodName $MethodName -Arguments $MethodParameters
    }
    catch {
        Write-Host "[$Computer] $($_.Exception.Message)" -ForegroundColor Red
    }
}



$ComputerName = 'LP450', 'PC718', 'LP648', 'PC1346', 'PC1222', 'LP318', 'LP940', 'LP944', 'PC791'

foreach ($Computer in $ComputerName) {

    if (Test-Connection -ComputerName $Computer -Quiet -Count 1 -ErrorAction SilentlyContinue) {

        $SessionArgs = @{
            ComputerName       = $Computer
            SessionOption      = New-CimSessionOption -Protocol DCOM
            SkipTestConnection = $True
        }
        $MethodArgs = @{
            Namespace  = "ROOT\ccm"
            ClassName  = 'SMS_Client'
            MethodName = 'TriggerSchedule'
            CimSession = New-CimSession @SessionArgs
            Arguments  = @{
                sScheduleID = '{00000000-0000-0000-0000-000000000001}'
            }
            ErrorAction = 'SilentlyContinue'
        }

        try {
            Invoke-CimMethod @MethodArgs | Out-Null
            Write-Host "[$Computer] HWInventory invoked" -ForegroundColor Green
        } catch {
            Write-Host "[$Computer] $($_.Exception.Message)" -ForegroundColor Red
        }

    } else {
        Write-Host "[$Computer] offline" -ForegroundColor Yellow
    }
    
}

