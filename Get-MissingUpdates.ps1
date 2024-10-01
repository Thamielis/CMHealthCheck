
$ComputerName = 'PC630'

$MissingSoftwareUpdates = Get-CimInstance -ComputerName $ComputerName -Query "SELECT * FROM CCM_SoftwareUpdate" -Namespace "ROOT\ccm\ClientSDK"
#get-wmiobject -query "SELECT * FROM CCM_UpdateStatus" -namespace "root\ccm\SoftwareUpdates\UpdatesStore"
$MissingStoreUpdates = Get-CimInstance -ComputerName $ComputerName -Query "SELECT * FROM CCM_UpdateStatus" -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" | Where-Object { $_.status -eq "Missing" }


# WMIRebuild
# Created by Dennis Ihrén

$Path = Get-Location

[String]$PathFile = [String]$Path + "\Input.txt"
[String]$LoggPath = [String]$Path + "\" + "Result.csv"

$Computers = Get-Content $PathFile

$ScriptBlock = {
    NET STOP "Windows Firewall/Internet Connection Sharing (ICS)"
    Start-Sleep -s 5
    NET STOP "SMS AGENT HOST"
    Start-Sleep -s 5
    NET STOP Winmgmt /Y

    Rename-Item c:\windows\system32\wbem\repository repository_oldByScript

    Start-Service winmgmt
    Start-Sleep -s 5
    Start-Service "Windows Firewall/Internet Connection Sharing (ICS)"
    Start-Sleep -s 5
    Start-Service "SMS AGENT HOST"
}

ForEach ($Computer in $Computers) {

    Write-host $Computer
    $Computer | Out-File $LoggPath -Append

    Invoke-Command -ScriptBlock $ScriptBlock -Computername $Computer -SessionOption (New-PSSessionOption -NoMachineProfile) | Out-File $LoggPath -Append
}
