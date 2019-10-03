function Get-MessageSolution {
    [CmdletBinding()]
    param (
		[parameter()][string]$MessageID = ""
    )
	try {
		if (![string]::IsNullOrEmpty($MessageID)) {
			Write-Log "looking up solution for error message id: $MessageID" -Log $logfile
			$msg = $MessagesXML.dtsHealthCheck.MessageSolution | Where-Object {$_.MessageId -eq $MessageID}
			if ([string]::IsNullOrEmpty($msg)) {
				Write-Log "searching windows update error solutions table" -Log $logfile
				$errcodes = Join-Path $(Split-Path (Get-Module "cmhealthcheck").Path) -ChildPath "assets\windows_update_errorcodes.csv"
				if (Test-Path $errcodes) {
					Write-Log "importing: $errcodes" -Log $logfile
					$errdata = Import-Csv -Path $errcodes
					if (![string]::IsNullOrEmpty($errdata)) {
						Write-Log "imported $($errdata.Count) rows from file" -Log $logfile
						$errdet = $($errdata | Where-Object {$_.ErrorCode -eq $MessageID} | Select-Object -ExpandProperty Description).Trim()
						if ([string]::IsNullOrEmpty($errdet)) {
							Write-Log "standard details not found. searching decimal error information" -Log $logfile
							$errdet = $($errdata | Where-Object {$_.DecErrorCode -eq $MessageID} | Select-Object -ExpandProperty Description).Trim()
							if (![string]::IsNullOrEmpty($errdet)) {
								Write-Output $errdet
							}
							else {
								Write-Output "There is no known possible solution for Message ID $MessageID"
							}
						}
						else {
							Write-Output $errdet
						}
					}
					else {
						Write-Log "failed to import $errcodes"
						Write-Output ""
					}
				}
				else {
					Write-Warning "missing file: $errcodes"
					Write-Output "There is no known possible solution for Message ID $MessageID"
				}
			}
			else {
				Write-Output $msg.Description
			}
		}
		else {
			Write-Log "MessageID was blank or null" -Log $logfile
			Write-Output ""
		}
	}
	catch {
		Write-Log $_.Exception.Message -Log $logfile -Severity 3
	}
}