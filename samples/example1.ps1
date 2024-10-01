#requires -RunAsAdministrator
[CmdletBinding()]
param()

if (-not(Get-Module cmHealthCheck -ListAvailable)) {

	try {
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		Install-Module -Name CMHealthCheck
	}
	catch {
		Write-Output "error: $($_.Exception.Message -join ';')"
	}
}

try {
	if (-not (Get-Module ConfigurationManager)) {
		Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" -Verbose:$false
	}
}
catch {
	#Write-Log -Message "Warning: Could not import the ConfigurationManager.psd1 Module"
	Write-Warning "Warning: Could not import the 'ConfigurationManager.psd1' module"
	#Write-Log -Message ("'{0}'" -f $_.Exception.Message) -LogId $LogId -Severity 3
}

Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true -PassThru | Register-DbatoolsConfig -Scope SystemDefault

$params = @{
	SmsProvider         = "atklsccm.kostweingroup.intern"
	CustomerName        = "Kostwein Maschinenbau GmbH"
	Author              = "Mario Mellunig"
	CopyrightName       = "Kostwein Maschinenbau GmbH"
	DataFolder          = "$PSScriptRoot\Data"
	PublishFolder       = "$PSScriptRoot\Report"
	MessagesFilename    = Join-Path $(Split-Path (Get-Module "CMHealthCheck").Path) -ChildPath "assets\messages.xml"
	HealthcheckFilename = Join-Path $(Split-Path (Get-Module "cmhealthcheck").Path) -ChildPath "assets\cmhealthcheck.xml"
	NoHotFix            = $True
	Detailed            = $True
	Overwrite           = $True
}

Invoke-CMHealthCheck @params
