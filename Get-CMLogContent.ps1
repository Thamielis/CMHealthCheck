<#
This script creates three functions, the main one I use is Get-CMLogContent, which relies on the other function.
Function: Format-Color from:  https://www.bgreco.net/powershell/format-color/
Function: ConvertFrom-Logs created by Jeff Scripter
Function: Get-CMLogContent created by Gary Blok (@gwblok)

#>

Function Format-Color([hashtable] $Colors = @{}, [switch] $SimpleMatch) {

    $lines = ($input | Out-String) -replace "`r", "" -split "`n"

    foreach ($line in $lines) {
        $color = ''

        foreach ($pattern in $Colors.Keys) {
            if (!$SimpleMatch -and $line -match $pattern) { $color = $Colors[$pattern] }
            elseif ($SimpleMatch -and $line -like $pattern) { $color = $Colors[$pattern] }
        }

        if ($color) {
            Write-Host -ForegroundColor $color $line -BackgroundColor Black
        }
        else {
            Write-Host $line
        }
    }
}

Function ConvertFrom-Logs {
    [OutputType([PSObject[]])]
    Param (
        [Parameter(ValueFromPipeline)]
        [String] $string,
        [Int]$Tail,
        [String] $LogPath,
        [string] $Date,
        [string] $LogComponent,
        [Int] $Bottom = $Null,
        [DateTime] $After
    )
    
    Begin {
    
        If ($LogPath) {
            If (Test-Path -Path $LogPath) {
                if ($Tail) { $string = Get-Content -Path $LogPath -Tail $Tail }
                else { $string = Get-Content -Raw -Path $LogPath }
                
                $LogFileName = Get-Item -Path $LogPath | Select-Object -ExpandProperty name
            }
            Else {
                Return $False
            }
        }
    
        $SccmRegexShort = '\[LOG\[(?:.|\s)+?\]LOG\]'
        $SccmRegexLong = '(?im)((?<=\[LOG\[)((?:.|\s)+?)(\]LOG\]))(.{2,4}?)<(\s*[a-z0-9:\-\.\+]+="[_a-z0-9:\-\.\+]*")+>'

        $ErrorcodeRegex = '(?i)0x[0-9a-fA-F]{8}|(?<=\s)-\d{10}(?=\s)|(?<=code\s*)\d{1,}|(?<=error\s*)\d{1,}'
        $FilePathRegex = '(([a-zA-Z]\:)|(\\))(\\{1}|((\\{1})[^\\]([^/:*?<>"|]*))+)([/:*?<>"|]*(\.[a-zA-Z]+))'
    
        $StringLength = $string.Length    
        $Return = New-Object -TypeName System.Collections.ArrayList
    
    }
    Process {
        $TestLength = 500

        If ($StringLength -lt $TestLength) {
            $TestLength = $StringLength
        }
    
        #Which type is the log
        If ($StringLength -gt 5) {

            # SCCM Log Parshing
            If ([regex]::match($string.Substring(0, $TestLength), $SccmRegexShort).value, 'Compiled') { 
                $SccmRegex = [regex]::matches($string, $SccmRegexLong)
        
                #foreach Line
                If (-not $Bottom -or $SccmRegex.count -lt $Bottom) {
                    $Bottom = $SccmRegex.count
                }

                For ($Counter = 1 ; $Counter -Lt $Bottom + 1; $Counter++) { 
                    $r = $SccmRegex[ $SccmRegex.count - $Counter]
                    $Errorcode = ''
                    $FilePath = ''
                    #get Message
                    $Hash = @{}
                    $Hash.Add('Message', $r.groups[2].value)

                    If ($LogFileName) {
                        $Hash.Add('LogFileName', $LogFileName)
                    }

                    If ($LogPath) {
                        $Hash.Add('LogPath', $LogPath)
                    }

                    #get additional information 
                    $parts = $r.groups |
                        Where-Object -FilterScript {
                            $_.captures.count -gt 1
                        } |
                            Select-Object -ExpandProperty captures

                    Foreach ($p in $parts) {
                        If ($p.value -match '\w=') {
                            $name = $p.value.split('=')[0].trim()
                            $value = $p.value.split('=')[1].replace('"', '').Replace('>', '').Replace('<', '')
                            $Hash.Add($name, $value)
                        }
                    }
                    
                    #convert to Datetime .net object
                    If ($Null -ne $Hash.Item('time') -and $Null -ne $Hash.Item('Date')) {
                        $Hash.Add('TempTime', $Hash.Item('time'))
                        $Time = $($Hash.Item('time').split('+')[0]).split('-')[0]
                        $Hash.Item('time') = [datetime] "$($Hash.Item('date')) $Time"
                        #$Hash.Item('time') = [datetime] "$($Hash.Item('date')) $($Hash.Item('time').split('+')[0])"

                        If ($Hash.Item('time').gettype() -eq [datetime]) {
                            $Hash.Remove('Date')
                        }
                        Else {
                            $Hash.Item('time') = $Hash.Item('TempTime')
                        }

                        $Hash.Remove('TempTime')
                    }
                    
                    #get severity information
                    Switch ($Hash.Item('Type')) {
                        0 {
                            $Hash.Add('TypeName', 'Status')
                        }
                        1 {
                            $Hash.Add('TypeName', 'Info')
                        }
                        2 {
                            $Hash.Add('TypeName', 'Error')
                        }
                        3 {
                            $Hash.Add('TypeName', 'Warning')
                        }
                        4 {
                            $Hash.Add('TypeName', 'Verbose')
                        }
                        5 {
                            $Hash.Add('TypeName', 'Debug')
                        }
                    }
                    
                    #build object
                    If ($After -GT $Hash.Item('time') -and ([bool] $Hash.Item('time'))) {
                        $Counter = $SccmRegex.count
                    }

                    Try {
                        [string] $Errorcode = [RegEx]::match($Hash['Message'], $ErrorcodeRegex 
                        ).value

                        $ErrorMSG = [ComponentModel.Win32Exception]::New([int]($Errorcode)).Message
                    }
                    Catch {
                        $Errorcode = ''
                        $Error.removeat(0)
                    }

                    [string] $FilePath = [RegEx]::match($Hash['Message'], $FilePathRegex).value 

                    If ($Errorcode -ne '') {
                        $Hash.Add('ErrorCode', $Errorcode)
                        $Hash.Add('ErrorMessage', $ErrorMSG)
                    }

                    If ($FilePath -ne '') {
                        $Hash.Add('FilePath', $FilePath)
                    }

                    $TempObj = New-Object -TypeName PSobject -Property $Hash
                    $Return.add($TempObj)
                }

                [array]::Reverse($Return)
            }
            Else {
                Write-Warning -Message 'Not Sccm log format'
            }
        }
    }   
    End {
        Return $Return
    }
}

function Get-CMLogContent {
    [OutputType([System.IO.FileInfo])]
    [CmdletBinding()]
    param (
        [Parameter( Mandatory = $false )]
        [int]    $Tail,
        [String] $Highlight1 = 'Gray',
        [String] $Highlight2 = 'White',
        [String] $LogFileFolder = 'C:\windows\ccm\logs'
    )

    DynamicParam {          
        $ParamAttrib = New-Object System.Management.Automation.ParameterAttribute
        $ParamAttrib.Mandatory = $true
        $ParamAttrib.ParameterSetName = '__AllParameterSets'

        $AttribColl = New-Object  System.Collections.ObjectModel.Collection[System.Attribute]
        $AttribColl.Add($ParamAttrib)
        $configurationFileNames = Get-ChildItem -Path $($PSBoundParameters.LogFileFolder) -Recurse | Select-Object -ExpandProperty  Name
        $AttribColl.Add((New-Object  System.Management.Automation.ValidateSetAttribute($configurationFileNames)))
        $RuntimeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('FileName', [string], $AttribColl)
        $RuntimeParamDic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $RuntimeParamDic.Add('FileName', $RuntimeParam)

        return  $RuntimeParamDic
    }

    process {
        $configFileFolder = $LogFileFolder

        $File = Get-ChildItem  -Path $configFileFolder -Recurse -Filter "$($PSBoundParameters.FileName)"

        if ($tail) {
            $CMLOG = ConvertFrom-Logs -LogPath $File.FullName -Tail $tail
            $CMLOG | Where-Object { $null -ne $_.Message } | Select-Object -Last $tail | Select-Object -Property time, message | Format-Color @{$Highlight1 = 'Yellow'; $Highlight2 = 'cyan' }
        }
        else {
            $CMLOG = ConvertFrom-Logs -LogPath $File.FullName
            $CMLOG | Where-Object { $null -ne $_.Message } | Select-Object -Property time, message | Format-Color @{$Highlight1 = 'Yellow'; $Highlight2 = 'cyan' }
        }
    }
}

## Examples 
<#

Get-CMLogContent -Tail 50 -FileName WUAHandler.log -Highlight1 'Missing'

Get-CMLogContent -Tail 100 -FileName SMSTS.log -Highlight1 'The Action' -Highlight2 'exit code 0'

#>
$ComputerName = 'LP1183'

#$Path = "\\atklsccm\d$\Program Files\Microsoft Configuration Manager\Logs"
$Path = "\\$($ComputerName)\c$\Windows\ccmsetup\Logs"
#$Path = "\\$($ComputerName)\c$\Windows\CCM\Logs"

$LogFile = "ccmsetup.log"
#$LogFile = "StateMessage.log"
#$LogFile = "UpdatesStore.log"
#$LogFile = "PatchDownloader.log"

$Highlight1 = '[Errorfailed()0-9xA-F\s]+'
$Highlight2 = '((E|e)rror|(F|f)ailed) [0-9x|(A-F|a-f)]+'

#$Logs = Get-ChildItem -Path $Path
$Logs = Get-ChildItem -Path "$Path\$LogFile"

$LogsResult = foreach ($File in $Logs) {
    ConvertFrom-Logs -LogPath $File.FullName
}
$LogsErrors = $LogsResult | Where-Object { $_.Type -eq '3' -and $_.time -gt $(Get-Date).AddDays(-7) }
$UniqueLogErrors = $LogsErrors | Sort-Object -Property Message -Unique
$UniqueLogErrors | Select-Object -Property time, Message, ErrorMessage, LogFileName | Out-HtmlView



$LogResult = ConvertFrom-Logs -LogPath (Join-Path -Path $Path -ChildPath $LogFile)
$LogErrors = $LogResult | Where-Object { $_.Type -eq '3' }
Get-CMLogContent -FileName $LogFile -LogFileFolder $Path -Highlight2 $Highlight2


$DeviceName = "PC911"
$DeploymentDate = "202307101200"
$BaseLogPath = "\\atklsccm\sources$\Logs"
$SMSTSLogs = "$BaseLogPath\$DeviceName\$DeploymentDate\_SMSTaskSequence\Logs"

$configFileFolder = $SMSTSLogs
#$File = Get-ChildItem  -Path $configFileFolder -Recurse -Filter "$($PSBoundParameters.FileName)"

Get-CMLogContent -Tail 200 -FileName smsts.log -Highlight1 'The Action' -Highlight2 'exit code 0' -LogFileFolder $SMSTSLogs
#Get-CMLogContent -Tail 100 -FileName SMSTS.log -Highlight1 'The Action' -Highlight2 'exit code 0'
