
Import-Module .\CMHealthCheck.psm1

$ReportPath = "C:\Data\2024-05-07\atklsccm.kostweingroup.intern"
$ModulePath = $PSScriptRoot
$Healthcheckfilename = Join-Path -Path $ModulePath -ChildPath "assets\cmhealthcheck.xml"
$MessagesFilename = Join-Path -Path $ModulePath -ChildPath "assets\messages.xml"

$ConfigTable = New-Object System.Data.DataTable 'ConfigTable'
$ConfigTable = Get-CmXMLFile -Path $ReportPath -FileName "config.xml"
$ReportTable = New-Object System.Data.DataTable 'ReportTable'
$ReportTable = Get-CmXMLFile -Path $ReportPath -FileName "report.xml"



$ClientReportingErrorsinthelast7daysdetailFile = 'ClientReportingErrorsinthelast7daysdetail.xml'
$ClientReportingErrorsinthelast7dayssummaryFile = 'ClientReportingErrorsinthelast7dayssummary.xml'

$DiscoveredmachineswithoutSCCMClientinstalleddetailFile = 'DiscoveredmachineswithoutSCCMClientinstalleddetail.xml'
$DiscoveredmachineswithoutSCCMClientinstalledsummaryFile = 'DiscoveredmachineswithoutSCCMClientinstalledsummary.xml'

$SoftwareUpdateDeploymentErrorsdetailFile = 'SoftwareUpdateDeploymentErrorsdetail.xml'
$SoftwareUpdateDeploymentErrorsMessagedetailFile = 'SoftwareUpdateDeploymentErrorsMessagedetail.xml'
$SoftwareUpdateDeploymentErrorsMessagesummaryFile = 'SoftwareUpdateDeploymentErrorsMessagesummary.xml'
$SoftwareUpdateDeploymentErrorsSolutionFile = 'SoftwareUpdateDeploymentErrorsSolution.xml'
$SoftwareUpdateDeploymentErrorssummaryFile = 'SoftwareUpdateDeploymentErrorssummary.xml'

$SUDErrorsDetail = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $SoftwareUpdateDeploymentErrorsdetailFile)
$SUdErrorsMessageDetail = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $SoftwareUpdateDeploymentErrorsMessagedetailFile)
$SUDErrorsMessageSummary = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $SoftwareUpdateDeploymentErrorsMessagesummaryFile)
$SUDErrorsSolution = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $SoftwareUpdateDeploymentErrorsSolutionFile)
$SUDErrorsSummary = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $SoftwareUpdateDeploymentErrorssummaryFile)


$ClientErrorsDetail = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $ClientReportingErrorsinthelast7daysdetailFile)
$ClientErrorsSummary = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $ClientReportingErrorsinthelast7dayssummaryFile)

$NoClientDetail = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $DiscoveredmachineswithoutSCCMClientinstalleddetailFile)
$NoClientSummary = Import-Clixml -Path (Join-Path -Path $ReportPath -ChildPath $DiscoveredmachineswithoutSCCMClientinstalledsummaryFile)

$ClientErrors = [PSCustomObject]@{
    'Advanced Client'                      = $ClientErrorsDetail | Where-Object { $_.Component -eq 'Advanced Client' }
    'Advanced Client Inventory Agent'      = $ClientErrorsDetail | Where-Object { $_.Component -eq 'Advanced Client Inventory Agent' }
    'File Collection Agent'                = $ClientErrorsDetail | Where-Object { $_.Component -eq 'File Collection Agent' }
    'Hardware Inventory Agent'             = $ClientErrorsDetail | Where-Object { $_.Component -eq 'Hardware Inventory Agent' }
    'Software Distribution'                = $ClientErrorsDetail | Where-Object { $_.Component -eq 'Software Distribution' }
    'Software Distribution Content Access' = $ClientErrorsDetail | Where-Object { $_.Component -eq 'Software Distribution Content Access' }
    'Software Inventory Agent'             = $ClientErrorsDetail | Where-Object { $_.Component -eq 'Software Inventory Agent' }
    'Software Metering'                    = $ClientErrorsDetail | Where-Object { $_.Component -eq 'Software Metering' }
}

$MissingWSClient = [PSCustomObject]@{
    "Windows 10" = $NoClientDetail | Where-Object { $_.Operating_System_Name_and0 -match 'Workstation 1' }
    "Windows XP" = $NoClientDetail | Where-Object { $_.Operating_System_Name_and0 -match 'Workstation 5' }
}

Start-Sleep -Seconds 1
