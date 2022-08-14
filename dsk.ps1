<#
#DSK.PS1 SCRIPT INFORMATION HEADER###################################################################################################################################################
Discord Secret Knock
Created by Josh 'OzDeaDMeaT' McDougall
Version: v1.0g
Date: 14-08-2022
#COPYRIGHT STATEMENT#################################################################################################################################################################
Copyright (c) 2022 Josh 'OzDeaDMeaT' McDougall, All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
4. Utilization of this software for commercial use is prohibited unless authorized by the software copywrite holder in writing (electronic mail).

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>
#SCRIPT PARAMETERS###################################################################################################################################################################
param(
    [switch]$Init,                                                                      #Initializes DSK
    [switch]$Reload,                                                                    #Will reload dsk.ps1 variables
    [switch]$Reboot,                                                                    #Will Reboot the device
    [switch]$RDP,                                                                       #Executes RDP Firewall Rule
    [switch]$VNC,                                                                       #Executes VNC Firewall Rule
    [switch]$FTP,                                                                       #Executes FTP Firewall Rule
    [switch]$Shut,                                                                      #Executes removal of Firewall Rule
    [switch]$ClearFW,                                                                   #Clears All temp firewall connections (typically prior to a restart)
    [string]$IP,                                                                        #Variable to be passed to the firwall function
    [string]$DISCORDUSER,                                                               #Discord username running command
    [string]$DiscordID                                                                  #Discord ID of user running command
)
$DSK_PS      = "v1.0g"                                                                  #Version of the DSK PowerShell script
#DONT EDIT INFORMATION ABOVE THIS LINE###############################################################################################################################################

#USER DEVICE CONFIGURATION STARTS AT LINE 1114, just after the big CONFIG 
#USER DEVICE CONFIGURATION STARTS AT LINE 1114, just after the big CONFIG 
#USER DEVICE CONFIGURATION STARTS AT LINE 1114, just after the big CONFIG 

#FUNCTIONS###########################################################################################################################################################################
Function replaceLine {
param(
    [switch]$Version,
    [Parameter(Mandatory=$true)][string]$File,
    [Parameter(Mandatory=$true)][string]$Match,
    [Parameter(Mandatory=$true)][string]$Replace
)
    if($Version) {
        return "v1.0d"
    }
    if(Test-Path $file) {
        $Text = Get-Content $File
        $outputString = $null
        ForEach ($Line in $Text) {
            if($Line -match $Match) {
                $Line = $Replace
            }
            $outputString = $outputString + $Line
        }
        return $outputString
    } else {
        write-host "ERROR: $File file Not Found!" -ForegroundColor "RED"
    }
}
Function Out-Report {
    <# 
    .DESCRIPTION 
    Automated method of outputting information in a formatted way to the CLI 
    .EXAMPLE
    Out-Report -Label "List of Variables"
    Out-Report -Label "`$CommandPrefix ==" -Data $CommandPrefix
    Out-Report -Label "`$HELP          ==" -Data $HELP -Bool
    Out-Report -Label "`$HELP          ==" -Data $HELP -Compare $OtherHelp -CompareBool
    #>
    param(
    [switch]$Version,
    [Parameter(Mandatory=$true)][string]$Label,
    $Data,
    $Compare,			    #Used for Compare. If Different, will report mismatch unless Override switch is called also, then it will Override to $Data varible and report Override
    [string]$LabelColour = "white",
    [string]$DataColour = "yellow",
    [string]$CheckOK = "green",
    [string]$CheckDisabled = "yellow",
    [string]$CheckFail = "red",
    [switch]$Override,     #only used for Compare, ignored otherwise
    [switch]$CheckPath,     
    [switch]$CompareBool,
    [switch]$Bool			#Do not use CheckPath, Compare or Bool at the same time
    )
    if($Version) {
        return "v1.0a"
    }
    write-host "$Label " -foregroundcolor $LabelColour -nonewline
        if($CheckPath) {
            if($Data -eq "") {$Data = "NOT CONFIGURED"}
            $check = test-path $Data -ErrorAction SilentlyContinue
            if ($check) {
                write-host "OK" -ForegroundColor $CheckOK -nonewline
                write-host " - $Data" -ForegroundColor $DataColour
            } else {
                write-host "Not Found" -ForegroundColor $CheckFail -nonewline
                write-host " - $Data" -ForegroundColor $DataColour
            }
        }

        ElseIf ($Bool){
            if($Data -eq $true) {
                write-host "Enabled" -ForegroundColor $CheckOK
            } else {
                write-host "Disabled" -ForegroundColor $CheckDisabled
                }
            }

        ElseIf ($CompareBool){
            if($Data -eq $Compare) {
                if($Data -eq $true) {write-host "Enabled" -ForegroundColor $CheckOK} else {write-host "Disabled" -ForegroundColor $CheckDisabled}
            } else {
                if(($Compare -eq $false) -and ($Data -eq $true)) {write-host "Disabled (Overridden due to config error)" -ForegroundColor $CheckDisabled} else {write-host "Disabled" -ForegroundColor $CheckDisabled}
                }
            } 
        else {
            if($Data -eq "") {
                $Data = "NOT CONFIGURED"
                write-host $Data -foregroundcolor $CheckFail
            } else {
                write-host $Data -foregroundcolor $CheckOK
                }
            }
}
Function Write-Log {
    <# 
    .Version 2
    Added foregroundcolor passthru as well as nonewline passthru
    .DESCRIPTION 
    Write-Log is a simple function that dumps an output to a log file.
    .EXAMPLE
    The line below will create a log file called test.log in the current folder and populate it with 'This data is going into the log'
    write-log -LogData "This data is going into the log" -LogFile "test.log" 
    #>
     Param (
    [switch]$Version,
     $LogData = "",
    $LogFile = $DSK_LogFile,
    $foregroundcolor = ($Host.UI.RawUI).ForegroundColor,
    [switch]$nonewline,
    [switch]$Silent
    )
    if($Version) {
        return "v1.0a"
    }
    if ($LogData -ne "") {
        $Time = get-date -Format "yyyy-MMM-dd--HH:mm:ss"
        $TimeStampLog = $Time + "  -  " + $LogData
        if (-Not (test-path $LogFile)) {
            $shh = new-item $LogFile -type File -Force -ErrorAction SilentlyContinue
            if($shh.count -gt 0) {
                $created = $Time + " - LOGFILE CREATED"
                Add-Content $LogFile $created
                Add-Content $LogFile $TimeStampLog
                if(-not ($silent)) {
                    write-host "LOGFILE CREATED" -foregroundcolor $foregroundcolor
                    if($nonewline) {write-host $LogData -foregroundcolor $foregroundcolor -nonewline} else {write-host $LogData -foregroundcolor $foregroundcolor}
                    }
                }
            else
                {
                if(-not ($silent)) {
                    write-host "Logfile does not exist and was not able to be created, please check path provided and try again"
                    }
                }
            }
        else
            {
            Add-Content $LogFile $TimeStampLog
            if(-not ($silent)) {
                if($nonewline) {write-host $LogData -foregroundcolor $foregroundcolor -nonewline} else {write-host $LogData -foregroundcolor $foregroundcolor}
                }
            }
        } 
    }
Function Prompt-User {
<# 
.DESCRIPTION 
Prompt-User allows for a simple user prompt based on Parameters passed to it.
#Note: The Default Option is always true. So if you use the switch -NoAsDefault it will make the return of 'no' as True. Its annoying and confusing but it is the way this Automation Host thing works. :(
.EXAMPLE
Prompt-User -Question "Is DDC2 Awesome?!?" -NoHelp "You shouldn't lie, lying is bad" -YesHelp "Damn Right it is"
Prompt-User -Question "Did you poop yourself?" -NoHelp "No, it was just an epic fart!" -YesHelp "Yes, it's what all the kids are doing these days, it's hip and happening!" -NoAsDefault
#>
param(
[switch]$Version,
[Parameter(Mandatory=$true)][string]$Question,
[Parameter(Mandatory=$true)][string]$NoHelp,
[Parameter(Mandatory=$true)][string]$YesHelp,
[switch]$NoAsDefault
)
if($Version) {
    return "v1.0a"
}
    $DefaultOption = if($NoAsDefault) {1} else {0}
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription ("&Yes", $YesHelp)
    $no = New-Object System.Management.Automation.Host.ChoiceDescription ("&No", $NoHelp)
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $rtn = $Host.ui.PromptForChoice("", $Question, $options, $DefaultOption) 
return $rtn
}
Function Get-DSK {
<# 
.DESCRIPTION 
Gets system information on the configuration of FTP for Discord Secret Knock (DSK)
    
.EXAMPLE
Get-FTP
#>
param(
[switch]$Version
)
    if($Version) {
        return "v1.0d"
    }
    $DSK_return = $null
    $DSK_return = New-Object -TypeName psobject
    $DSK_return | Add-Member -MemberType NoteProperty -Name DeviceID -Value $DeviceID
    $DSK_return | Add-Member -MemberType NoteProperty -Name OnlyDevice -Value $OnlyDevice
    $DSK_return | Add-Member -MemberType NoteProperty -Name CmdPrefix -Value $CmdPrefix
    $DSK_return | Add-Member -MemberType NoteProperty -Name TimeOut -Value $TimeOut
    $DSK_return | Add-Member -MemberType NoteProperty -Name DynamicIP -Value $DynamicIP
    $DSK_return | Add-Member -MemberType NoteProperty -Name EnableHELP -Value $EnableHELP
    $DSK_return | Add-Member -MemberType NoteProperty -Name EnableVNC -Value $EnableVNC
    $DSK_return | Add-Member -MemberType NoteProperty -Name EnableRDP -Value $EnableRDP
    $DSK_return | Add-Member -MemberType NoteProperty -Name EnableFTP -Value $EnableFTP
    $DSK_return | Add-Member -MemberType NoteProperty -Name EnableWhitelist -Value $EnableWhitelist
    $DSK_return | Add-Member -MemberType NoteProperty -Name Whitelist -Value $Whitelist
    $DSK_return | Add-Member -MemberType NoteProperty -Name Blacklist -Value $Blacklist
    return $DSK_return
}
Function Get-FTP{
    <# 
    .DESCRIPTION 
    Gets system information on the configuration of FTP for Discord Secret Knock (DSK)
     
    .EXAMPLE
    Get-FTP
    #>
    param(
    [switch]$Version
    )
    if($Version) {
        return "v1.0b"
    }
    if(Test-Path $FTP_Path) {
        if($FTP_Port -eq $nil) {$GetFTPPort = "Not Configured"} else {$GetFTPPort = $FTP_Port}
        $GetFTPPath = $FTP_Path
        $GetFTPEnab = $true
        }
    else {
        $GetFTPPath = "FTP Path not configured or not found"
        $GetFTPPort = "FTP Path not configured or not found"
        $GetFTPEnab = $false
        }
    $FTP_return = $null
    $FTP_return = New-Object -TypeName psobject
    $FTP_return | Add-Member -MemberType NoteProperty -Name Enabled -Value $GetFTPEnab
    $FTP_return | Add-Member -MemberType NoteProperty -Name Port -Value $GetFTPPort
    $FTP_return | Add-Member -MemberType NoteProperty -Name Path -Value $GetFTPPath
    $FTP_return | Add-Member -MemberType NoteProperty -Name PASV_Port_Min -Value $FTP_PASV_PORT_MIN
    $FTP_return | Add-Member -MemberType NoteProperty -Name PASV_Port_Max -Value $FTP_PASV_PORT_MAX
    $FTP_return | Add-Member -MemberType NoteProperty -Name PASV -Value $FTP_PASV
    return $FTP_return
} 
Function Get-VNC{
<# 
.DESCRIPTION 
Gets system information on the configuration of VNC for Discord Secret Knock (DSK)
 
.EXAMPLE
Get-VNC
#>
param(
[switch]$Version
)
if($Version) {
    return "v1.0a"
}
if(Test-Path $VNC_Path) {
    if($VNC_Port -eq $nil) {$GetVNCPort = "Not Configured"} else {$GetVNCPort = $VNC_Port}
    $GetVNCPath = $VNC_Path
    $GetVNCEnab = $true
    }
else {
    $GetVNCPath = "VNC Path not configured or not found"
    $GetVNCPort = "VNC Path not configured or not found"
    $GetVNCEnab = $false
    }
$VNC_return = $null
$VNC_return = New-Object -TypeName psobject
$VNC_return | Add-Member -MemberType NoteProperty -Name Enabled -Value $GetVNCEnab
$VNC_return | Add-Member -MemberType NoteProperty -Name Port -Value $GetVNCPort
$VNC_return | Add-Member -MemberType NoteProperty -Name Path -Value $GetVNCPath
return $VNC_return
}
Function Get-RDP {
<# 
.DESCRIPTION 
Gets system information on the configuration of RDP for Discord Secret Knock (DSK)
 
.EXAMPLE
Get-RDP
#>
param(
[switch]$Version
)
if($Version) {
    return "v1.0a"
}
$GetRDPEnab = Get-ItemPropertyValue -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
if($GetRDPEnab -eq 0) {$GetRDPEnab = $true} else {$GetRDPEnab = $false}
$GetRDPPort = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name 'PortNumber' -ErrorAction SilentlyContinue
$RDP_return = $null
$RDP_return = New-Object -TypeName psobject
$RDP_return | Add-Member -MemberType NoteProperty -Name Enabled -Value $GetRDPEnab
$RDP_return | Add-Member -MemberType NoteProperty -Name Port -Value $GetRDPPort
return $RDP_return
}
Function Get-Version {
param(
    [switch]$Version
)
    if($Version) {
        RETURN "v1.0d"
    }
    $Node = if(Test-Command node) {node --version} else {"NODE.JS NOT FOUND"}
    $NPM = if(Test-Command npm) {npm --version} else {"NPM NOT FOUND"}
    $rtnDSKFunctions = $null
    $rtnDSKFunctions = New-Object -TypeName psobject
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name replaceLine -Value (replaceLine -Version -File "-" -Match "-" -Replace "-")
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Out`-Report -Value (Out-Report -Version -Label "-")
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Write`-Log -Value (Write-Log -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Prompt`-User -Value (Prompt-User -Version -Question "-" -NoHelp "-" -YesHelp "-")
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Get`-DSK -Value (Get-DSK -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Get`-FTP -Value (Get-FTP -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Get`-RDP -Value (Get-RDP -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Get`-VNC -Value (Get-VNC -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Get`-Version -Value (Get-Version -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Test`-Command -Value (Test-Command -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Check`-DSK -Value (Check-DSK -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Prepare`-Config -Value (Prepare-Config -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Get`-FirewallRule -Value (Get-FirewallRule -Version -Name "-")
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Simple`-Split -Value (Simple-Split -Version -Str "-" -Seperator "-")
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Setup`-Firewall`-FTPPort -Value (Setup-Firewall-FTPPort -Version -IP "-")
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Setup`-Firewall`-RDPPort -Value (Setup-Firewall-RDPPort -Version -IP "-")
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Setup`-Firewall`-VNCPort -Value (Setup-Firewall-VNCPort -Version -IP "-")
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Set`-Firewall -Value (Set-Firewall -Version)
    $rtnDSKFunctions | Add-Member -MemberType NoteProperty -Name Reboot`-Server -Value (Reboot-Server -Version)

    $rtnVersion = $null
    $rtnVersion = New-Object -TypeName psobject
    $rtnVersion | Add-Member -MemberType NoteProperty -Name DSK_PS -Value $DSK_PS
    $rtnVersion | Add-Member -MemberType NoteProperty -Name Windows -Value ($PSVersionTable.OS)
    $rtnVersion | Add-Member -MemberType NoteProperty -Name PowerShell -Value ($PSVersionTable.GitCommitId)
    $rtnVersion | Add-Member -MemberType NoteProperty -Name npm -Value $NPM
    $rtnVersion | Add-Member -MemberType NoteProperty -Name node -Value $Node
    $rtnVersion | Add-Member -MemberType NoteProperty -Name DSK -Value $rtnDSKFunctions
    RETURN $rtnVersion
}
Function Test-Command {
<# 
.DESCRIPTION 
Tests a command to see if it exists
.EXAMPLE
Test-Command npm
Test-Command notepad
#>
param(
    [switch]$Version,
    $command
)
if($Version) {
    RETURN "v1.0c"
}
$oldPreference = $ErrorActionPreference
$ErrorActionPreference = "STOP"
try {if(Get-Command $command){RETURN $true}}
Catch {RETURN $false}
Finally {$ErrorActionPreference=$oldPreference}
}
Function Check-DSK {
<# 
.DESCRIPTION
Check-DSK Function checks if all the paths are configured correctly as well as outputting all configuration items to the CLI
 .EXAMPLE
Check-DSK
#>
param(
[switch]$Version
)
if($Version) {
    return "v1.0b"
}
write-host "Reloading DSK.ps1 file into memory..." -ForegroundColor "white"
. .\DSK.ps1
write-host " "
##############################################################################################
$CheckAccess = $null                                                                         #
$CheckAccess = New-Object -TypeName psobject                                                 #
$CheckAccess | Add-Member -MemberType NoteProperty -Name ftp -Value $EnableFTP               #
$CheckAccess | Add-Member -MemberType NoteProperty -Name rdp -Value $EnableRDP               #
$CheckAccess | Add-Member -MemberType NoteProperty -Name vnc -Value $EnableVNC               #
##############################################################################################
$CheckConfig = $null                                                                         #
$CheckConfig = New-Object -TypeName psobject                                                 #
$CheckConfig | Add-Member -MemberType NoteProperty -Name dsk -Value (Get-DSK)                #
$CheckConfig | Add-Member -MemberType NoteProperty -Name ftp -Value (Get-FTP)                #
$CheckConfig | Add-Member -MemberType NoteProperty -Name rdp -Value (Get-RDP)                #
$CheckConfig | Add-Member -MemberType NoteProperty -Name vnc -Value (Get-VNC)                #
##############################################################################################
$CheckPerms = $null                                                                          #
$CheckPerms = New-Object -TypeName psobject                                                  #
$CheckPerms | Add-Member -MemberType NoteProperty -Name vnc -Value $VNCPerm                  #
$CheckPerms | Add-Member -MemberType NoteProperty -Name rdp -Value $RDPPerm                  #
$CheckPerms | Add-Member -MemberType NoteProperty -Name ftp -Value $FTPPerm                  #
$CheckPerms | Add-Member -MemberType NoteProperty -Name test -Value $TESTPerm                #
$CheckPerms | Add-Member -MemberType NoteProperty -Name help -Value $HELPPerm                #
$CheckPerms | Add-Member -MemberType NoteProperty -Name version -Value $VERSPerm             #
$CheckPerms | Add-Member -MemberType NoteProperty -Name info -Value $INFOPerm                #
$CheckPerms | Add-Member -MemberType NoteProperty -Name reload -Value $RELOADPerm            #
$CheckPerms | Add-Member -MemberType NoteProperty -Name reboot -Value $REBOOTPerm            #
$CheckPerms | Add-Member -MemberType NoteProperty -Name shut -Value $SHUTPerm                #
##############################################################################################
$CheckChannel = $null                                                                        #
$CheckChannel = New-Object -TypeName psobject                                                #
$CheckChannel | Add-Member -MemberType NoteProperty -Name LogChannel -Value $LOGCHANNEL      #
$CheckChannel | Add-Member -MemberType NoteProperty -Name ReqChannel -Value $REQCHANNEL      #
##############################################################################################
$CheckDSK = $null                                                                            #
$CheckDSK = New-Object -TypeName psobject                                                    #
$CheckDSK | Add-Member -MemberType NoteProperty -Name DeviceID -Value $DeviceID              #
$CheckDSK | Add-Member -MemberType NoteProperty -Name OnlyDevice -Value $OnlyDevice          #
$CheckDSK | Add-Member -MemberType NoteProperty -Name CmdPrefix -Value $CmdPrefix            #
$CheckDSK | Add-Member -MemberType NoteProperty -Name TimeOut -Value $TimeOut                #
$CheckDSK | Add-Member -MemberType NoteProperty -Name Version -Value (Get-Version)           #
$CheckDSK | Add-Member -MemberType NoteProperty -Name DynamicIP -Value $DynamicIP            #
$CheckDSK | Add-Member -MemberType NoteProperty -Name EnableHelp -Value $EnableHELP          #
##############################################################################################
$CheckDSK | Add-Member -MemberType NoteProperty -Name Config -Value $CheckConfig             #
$CheckDSK | Add-Member -MemberType NoteProperty -Name Channel -Value $CheckChannel           #
$CheckDSK | Add-Member -MemberType NoteProperty -Name Access -Value $CheckAccess             #
$CheckDSK | Add-Member -MemberType NoteProperty -Name Permissions -Value $CheckPerms         #
$CheckDSK | Add-Member -MemberType NoteProperty -Name EnableWhitelist -Value $EnableWhitelist#
$CheckDSK | Add-Member -MemberType NoteProperty -Name Whitelist -Value $Whitelist            #
$CheckDSK | Add-Member -MemberType NoteProperty -Name EnableBlacklist -Value $EnableBlacklist#
$CheckDSK | Add-Member -MemberType NoteProperty -Name Blacklist -Value $Blacklist            #
##############################################################################################
##This section dumps the variables above into a readable report at the CLI
write-host "Checking DSK Variables..." -ForegroundColor "white"
Out-Report -Label "  DeviceID            ==" -Data ($CheckDSK.DeviceID)
Out-Report -Label "  OnlyDevice          ==" -Data ($CheckDSK.OnlyDevice) -Bool
Out-Report -Label "  CmdPrefix           ==" -Data ($CheckDSK.CmdPrefix)
Out-Report -Label "  TimeOut             ==" -Data ($CheckDSK.TimeOut)
Out-Report -Label "  DynamicIP           ==" -Data ($CheckDSK.DynamicIP) -Bool
Out-Report -Label "  EnableHELP          ==" -Data ($CheckDSK.EnableHELP) -Bool
write-host "Country Black and White lists" -ForegroundColor "white"
Out-Report -Label "  EnableWhitelist     ==" -Data ($CheckDSK.EnableWhitelist) -Bool
Out-Report -Label "  Whitelist           ==" -Data ($CheckDSK.Whitelist)
Out-Report -Label "  Blacklist           ==" -Data ($CheckDSK.Blacklist)
write-host " "
write-host "FTP Configuration" -ForegroundColor "white"
Out-Report -Label "  EnableFTP           ==" -Data $EnableFTP -Compare ($CheckDSK.Config.ftp.Enabled) -CompareBool
Out-Report -Label "  FTP_Path            ==" -Data ($CheckDSK.Config.ftp.Path) -CheckPath
Out-Report -Label "  Port                ==" -Data ($CheckDSK.Config.ftp.Port)
Out-Report -Label "  Passive FTP (PASV)  ==" -Data ($CheckDSK.Config.ftp.PASV) -Bool
Out-Report -Label "  PASV_Port_Min       ==" -Data ($CheckDSK.Config.ftp.PASV_Port_Min)
Out-Report -Label "  PASV_Port_Max       ==" -Data ($CheckDSK.Config.ftp.PASV_Port_Max)
write-host " "
write-host "RDP Configuration" -ForegroundColor "white"
Out-Report -Label "  EnableRDP           ==" -Data $EnableRDP -Compare ($CheckDSK.Config.rdp.Enabled) -CompareBool
Out-Report -Label "  Port                ==" -Data ($CheckDSK.Config.rdp.Port)
write-host " "
write-host "VNC Configuration" -ForegroundColor "white"
Out-Report -Label "  EnableVNC           ==" -Data $EnableVNC -Compare ($CheckDSK.Config.vnc.Enabled) -CompareBool
Out-Report -Label "  VNC_Path            ==" -Data ($CheckDSK.Config.vnc.Path) -CheckPath
Out-Report -Label "  Port                ==" -Data ($CheckDSK.Config.vnc.Port)
write-host " "
write-host "DSK Discord Group Command Permissions" -ForegroundColor "white"
Out-Report -Label "  FTP (FTPPerm)       ==" -Data $FTPPerm
Out-Report -Label "  RDP (RDPPerm)       ==" -Data $RDPPerm
Out-Report -Label "  VNC (VNCPerm)       ==" -Data $VNCPerm
Out-Report -Label "  TEST (TESTPerm)     ==" -Data $TESTPerm
Out-Report -Label "  HELP (HELPPerm)     ==" -Data $HELPPerm
Out-Report -Label "  INFO (INFOPerm)     ==" -Data $INFOPerm
Out-Report -Label "  VERSION (VERSPerm)  ==" -Data $VERSPerm
Out-Report -Label "  SHUT (SHUTPerm)     ==" -Data $SHUTPerm
Out-Report -Label "  RELOAD (RELOADPerm) ==" -Data $RELOADPerm
Out-Report -Label "  REBOOT (REBOOTPerm) ==" -Data $REBOOTPerm
write-host " "
}
Function Prepare-Config {
<# 
.DESCRIPTION 
Prepares the configuration information in dsk.ps1 into a standardized structure for Node-Red to interprit.
Returns a PowerShell Object of all the configuration information
 .EXAMPLE
Prepare-Config
#>
param(
[switch]$Version
)
if($Version) {
    return "v1.0e"
}
    $Access = $null
    $Access = New-Object -TypeName psobject
    $Access | Add-Member -MemberType NoteProperty -Name ftp -Value $EnableFTP
    $Access | Add-Member -MemberType NoteProperty -Name rdp -Value $EnableRDP
    $Access | Add-Member -MemberType NoteProperty -Name vnc -Value $EnableVNC

    $Config = $null
    $Config = New-Object -TypeName psobject
    $Config | Add-Member -MemberType NoteProperty -Name dsk -Value (Get-DSK)
    $Config | Add-Member -MemberType NoteProperty -Name ftp -Value (Get-FTP)
    $Config | Add-Member -MemberType NoteProperty -Name rdp -Value (Get-RDP)
    $Config | Add-Member -MemberType NoteProperty -Name vnc -Value (Get-VNC)
    
    $Perms = $null
    $Perms = New-Object -TypeName psobject
    $Perms | Add-Member -MemberType NoteProperty -Name vnc -Value $VNCPerm
    $Perms | Add-Member -MemberType NoteProperty -Name rdp -Value $RDPPerm
    $Perms | Add-Member -MemberType NoteProperty -Name ftp -Value $FTPPerm
    $Perms | Add-Member -MemberType NoteProperty -Name test -Value $TESTPerm
    $Perms | Add-Member -MemberType NoteProperty -Name help -Value $HELPPerm
    $Perms | Add-Member -MemberType NoteProperty -Name version -Value $VERSPerm
    $Perms | Add-Member -MemberType NoteProperty -Name info -Value $INFOPerm
    $Perms | Add-Member -MemberType NoteProperty -Name reload -Value $RELOADPerm
    $Perms | Add-Member -MemberType NoteProperty -Name reboot -Value $REBOOTPerm
    $Perms | Add-Member -MemberType NoteProperty -Name shut -Value $SHUTPerm
        
    $Channel = $null
    $Channel = New-Object -TypeName psobject
    $Channel | Add-Member -MemberType NoteProperty -Name LogChannel -Value $LOGCHANNEL
    $Channel | Add-Member -MemberType NoteProperty -Name ReqChannel -Value $REQCHANNEL

    $DSK = $null
    $DSK = New-Object -TypeName psobject
    $DSK | Add-Member -MemberType NoteProperty -Name DeviceID -Value $DeviceID
    $DSK | Add-Member -MemberType NoteProperty -Name OnlyDevice -Value $OnlyDevice
    $DSK | Add-Member -MemberType NoteProperty -Name CmdPrefix -Value $CmdPrefix
    $DSK | Add-Member -MemberType NoteProperty -Name TimeOut -Value $TimeOut
    $DSK | Add-Member -MemberType NoteProperty -Name Version -Value (Get-Version)
    $DSK | Add-Member -MemberType NoteProperty -Name DynamicIP -Value $DynamicIP
    $DSK | Add-Member -MemberType NoteProperty -Name EnableHelp -Value $EnableHELP

    $DSK | Add-Member -MemberType NoteProperty -Name Config -Value $Config
    $DSK | Add-Member -MemberType NoteProperty -Name Channel -Value $Channel
    $DSK | Add-Member -MemberType NoteProperty -Name Access -Value $Access
        
    $DSK | Add-Member -MemberType NoteProperty -Name Permissions -Value $Perms
    $DSK | Add-Member -MemberType NoteProperty -Name EnableWhitelist -Value $EnableWhitelist
    $DSK | Add-Member -MemberType NoteProperty -Name Whitelist -Value $Whitelist
    $DSK | Add-Member -MemberType NoteProperty -Name EnableBlacklist -Value $EnableBlacklist
    $DSK | Add-Member -MemberType NoteProperty -Name Blacklist -Value $Blacklist
return $DSK
}
Function Get-FirewallRule {
<# 
.DESCRIPTION 
Returns information about a firewall rule
.EXAMPLE
Get-FirewallRule -Name "Test Firewall Rule Alpha 1"
#>
Param (
[switch]$Version,
[Parameter(Mandatory=$true)][string]$Name
)
if($Version) {
    return "v1.0a"
}
    $rtn = $null
    $rtn = New-Object -TypeName psobject
    $FWRule = get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if($FWRule -eq $null) {
        $rtn | Add-Member -MemberType NoteProperty -Name Exists -Value $false
    } else {
        $ApplFilter = $FWRule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        $PortFilter = $FWRule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $AddrFilter = $FWRule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $rtn | Add-Member -MemberType NoteProperty -Name Exists -Value $true
        $rtn | Add-Member -MemberType NoteProperty -Name Name -Value ($FWRule.Name)
        $rtn | Add-Member -MemberType NoteProperty -Name Description -Value ($FWRule.Description)
        $rtn | Add-Member -MemberType NoteProperty -Name Protocol -Value $PortFilter.Protocol
        $rtn | Add-Member -MemberType NoteProperty -Name LocalPort -Value $PortFilter.LocalPort
        $rtn | Add-Member -MemberType NoteProperty -Name RemotePort -Value $PortFilter.RemotePort
        $rtn | Add-Member -MemberType NoteProperty -Name IcmpType -Value $PortFilter.IcmpType
        $rtn | Add-Member -MemberType NoteProperty -Name DynamicTarget -Value $PortFilter.DynamicTarget
        $rtn | Add-Member -MemberType NoteProperty -Name DynamicTransport -Value $PortFilter.DynamicTransport
        $rtn | Add-Member -MemberType NoteProperty -Name Program -Value $ApplFilter.Program
        $rtn | Add-Member -MemberType NoteProperty -Name AppPath -Value $ApplFilter.AppPath
        $rtn | Add-Member -MemberType NoteProperty -Name Package -Value $ApplFilter.Package
        $rtn | Add-Member -MemberType NoteProperty -Name LocalAddress -Value $AddrFilter.LocalAddress
        $rtn | Add-Member -MemberType NoteProperty -Name LocalIP -Value $AddrFilter.LocalIP
        $rtn | Add-Member -MemberType NoteProperty -Name RemoteAddress -Value $AddrFilter.RemoteAddress
        $rtn | Add-Member -MemberType NoteProperty -Name RemoteIP -Value $AddrFilter.RemoteIP
    }
$rtn | Add-Member -MemberType NoteProperty -Name SearchName -Value $Name
return $rtn
}
Function Simple-Split {
<# 
.DESCRIPTION 
Simple Split Function
.EXAMPLE
$newSubString = Simple-Split - Elephatns
Prompt-User -Question "Did you poop yourself?" -NoHelp "No, it was just an epic fart!" -YesHelp "Yes, it's what all the kids are doing these days, it's hip and happening!" -NoAsDefault
#>
Param (
[switch]$Version,
[Parameter(Mandatory=$true)][string]$Str,
[Parameter(Mandatory=$true)][string]$Seperator,
[switch]$Trim,
[string]$Index = 0
)
if($Version) {
    return "v1.0a"
}
    $rtn = $str.Split($Seperator)
    $rtn = if($Trim) {
        $rtn[$Index].Trim()
    } else {
        $rtn[$Index]
    }
return $rtn
}
Function Setup-Firewall-FTPPort {
<# 
.DESCRIPTION 
Automatic setup of Firewall Rulkes for Discord Secret Knock FTP
#Note: The Default Option is always true. So if you use the switch -NoAsDefault it will make the return of 'no' as True. Its annoying and confusing but it is the way this Automation Host thing works. :(
.EXAMPLE
1. Setup-Firewall-FTPPort
2. Setup-Firewall-FTPPort -Port 21
2. Setup-Firewall-FTPPort -Passive -PASV_PORT_MIN 2100 -PASV_PORT_MAX 2121
#>
Param (
[switch]$Version,
[Parameter(Mandatory=$true)][string]$IP,
[switch]$Passive,
[string]$PASV_PORT_MIN,
[string]$PASV_PORT_MAX,
[string]$Port = $FTP_Port,
[string]$Path = $FTP_Path
)
if($Version) {
	return "v1.0a"
}
$RULEGROUP = 'File and Printer Sharing'
write-log -LogData "Setup-Firewall-FTPPort Starting" 
Out-Report -Label "  Checking FTP Path ==" -Data $Path -CheckPath
	if(Test-Path $Path) {
		$Dtime = (get-date).DateTime
		$RULE_DESCRIPTION = "DSK Generated FTP Firewall Rule - Created:$Dtime"
		$RULE_NAME_PREFIX = "FTP Server (DSK Generated) - "
		$Octet = '(?:0?0?[0-9]|0?[1-9][0-9]|1[0-9]{2}|2[0-5][0-5]|2[0-4][0-9])'
		[regex] $IPv4Regex = "^(?:$Octet\.){3}$Octet$"
		$CheckIP = $IP -match $IPv4Regex
		if($CheckIP) {
			Out-Report -Label "  Valid IP Addresss ==" -Data $IP
			########################################
			$RuleName = "$RULE_NAME_PREFIX$Port TCP"
			$RuleNameCheck = Get-FirewallRule -Name $RuleName
			write-log -LogData "  Rule Name = $RuleName"
			if($RuleNameCheck.Exists) {
				write-log -LogData "  FTP TCP Firewall Rule with the same name found"
				$prompt = Prompt-User -Question "  Did you wish to replace all current DSK FTP firewall rules?" -NoHelp "No, I will modify the firewall rules manually." -YesHelp "Yes, please modify this firewall rules for me,  NOTE: If the new information for the firewall rules is incorrect, you could lose connectivity to this machine." -NoAsDefault
				if (-not ($prompt)) {
					$UPDATED_RULE_DESCRIPTION = ($RuleNameCheck.Description).Split(' --')[0] + " -- Last Updated on $Dtime"
					if($Passive) {
						$shhh = Set-NetFirewallRule -NewDisplayName $RuleName `
													-Description $UPDATED_RULE_DESCRIPTION `
													-Program $Path `
													-Direction Inbound `
													-LocalPort $Port, $PASV_PORT_MIN-$PASV_PORT_MAX `
													-RemoteAddress $IP `
													-Action Allow `
													-Enabled true `
													-Group $RULEGROUP `
													-ErrorAction SilentlyContinue
						write-log -LogData "  FTP PASSIVE TCP Firewall Rule updated!"
						$RuleName = "$RULE_NAME_PREFIX$Port UDP"
						$RuleameCheck = Get-FirewallRule -Name $RuleName
						$UPDATED_RULE_DESCRIPTION = ($RuleNameCheck.Description).Split(' --')[0] + " -- Last Updated on $Dtime"
						$shhh = Set-NetFirewallRule -NewDisplayName $RuleName `
													-Description $UPDATED_RULE_DESCRIPTION `
													-Program $Path `
													-Direction Inbound `
													-LocalPort $Port, $PASV_PORT_MIN-$PASV_PORT_MAX `
													-RemoteAddress $IP `
													-Action Allow `
													-Enabled true `
													-Group $RULEGROUP `
													-ErrorAction SilentlyContinue
						write-log -LogData "  FTP PASSIVE UDP Firewall Rule updated!"
						write-log -LogData " DONT FORGET TO DISABLE THE DEFAULT FIREWALL RULES FOR FTP (If there are any)"
						write-log -LogData "Setup-Firewall-FTPPort reports 'JOB DONE'"                        
					} else {
						$shhh = Set-NetFirewallRule -NewDisplayName $RuleName `
													-Description $UPDATED_RULE_DESCRIPTION `
													-Program $Path `
													-Direction Inbound `
													-LocalPort $Port `
													-RemoteAddress $IP `
													-Action Allow `
													-Enabled true `
													-Group $RULEGROUP `
													-ErrorAction SilentlyContinue
						write-log -LogData "  FTP ACTIVE TCP Firewall Rule updated!"
						$RuleName = "$RULE_NAME_PREFIX$Port UDP"
						$RuleameCheck = Get-FirewallRule -Name $RuleName
						$UPDATED_RULE_DESCRIPTION = ($RuleNameCheck.Description).Split(' --')[0] + " -- Last Updated on $Dtime"
						$shhh = Set-NetFirewallRule -NewDisplayName $RuleName 
													-Description $UPDATED_RULE_DESCRIPTION `
													-Program $Path `
													-Direction Inbound `
													-LocalPort $Port `
													-RemoteAddress $IP `
													-Action Allow `
													-Enabled true `
													-Group $RULEGROUP `
													-ErrorAction SilentlyContinue
						write-log -LogData "  FTP ACTIVE UDP Firewall Rule updated!"
						write-log -LogData " DONT FORGET TO DISABLE THE DEFAULT FIREWALL RULES FOR FTP (If there are any)"
						write-log -LogData "Setup-Firewall-FTPPort reports 'JOB DONE'"
					}
				}
			} else {
				if($Passive) {
					write-log -LogData "  Creating New Passive FTP TCP Firewall Rule - $RULE_NAME_PREFIX$Port TCP"
					$shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port TCP" `
												-DisplayName "$RULE_NAME_PREFIX$Port TCP" `
												-Description $RULE_DESCRIPTION `
												-Direction Inbound `
												-LocalPort $Port, $PASV_PORT_MIN-$PASV_PORT_MAX `
												-Protocol TCP `
												-RemoteAddress $IP `
												-Action Allow `
												-Program $FTP_Path `
												-Group $RULEGROUP
					write-log -LogData "  Creating New Passive FTP UDP Firewall Rule - $RULE_NAME_PREFIX$Port UDP"
					$shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port UDP" `
												-DisplayName "$RULE_NAME_PREFIX$Port UDP" `
												-Description $RULE_DESCRIPTION `
												-Direction Inbound `
												-LocalPort $Port, $PASV_PORT_MIN-$PASV_PORT_MAX `
												-Protocol UDP `
												-RemoteAddress $IP `
												-Action Allow `
												-Program $FTP_Path `
												-Group $RULEGROUP
					write-log -LogData " DONT FORGET TO DISABLE THE DEFAULT FIREWALL RULES FOR FTP (If there are any)"
					write-log -LogData "Setup-Firewall-FTPPort reports 'JOB DONE'"
				} else {
					write-log -LogData "  Creating New Active FTP TCP Firewall Rule - $RULE_NAME_PREFIX$Port TCP"
					$shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port TCP" `
												-DisplayName "$RULE_NAME_PREFIX$Port TCP" `
												-Description $RULE_DESCRIPTION `
												-Direction Inbound `
												-LocalPort $Port `
												-Protocol TCP `
												-RemoteAddress $IP `
												-Action Allow `
												-Program $FTP_Path `
												-Group $RULEGROUP
					write-log -LogData "  Creating New Active FTP UDP Firewall Rule - $RULE_NAME_PREFIX$Port UDP"
					$shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port UDP" `
												-DisplayName "$RULE_NAME_PREFIX$Port UDP" `
												-Description $RULE_DESCRIPTION `
												-Direction Inbound `
												-LocalPort $Port `
												-Protocol UDP `
												-RemoteAddress $IP`
												-Action Allow`
												-Program $FTP_Path`
												-Group $RULEGROUP
					write-log -LogData " DONT FORGET TO DISABLE THE DEFAULT FIREWALL RULES FOR FTP (If there are any)"
					write-log -LogData "Setup-Firewall-FTPPort reports 'JOB DONE'"
				}
			}
		} else {
			Out-Report -Label "  Invalid IP Addresss ==" -Data $IP -CheckOK "RED"
			write-log -LogData "  ERROR: Invalid IP Addresss == $IP" -Silent
			write-log -LogData "Setup-Firewall-FTPPort aborted..."
		}
	} else {
		write-log -LogData "  Setup-Firewall-FTPPort requires a path to the FTP executable file using the -Path option" -foregroundcolor "RED"
		write-log -LogData "Setup-Firewall-FTPPort aborted..."
	}
}
Function Setup-Firewall-RDPPort {
Param (
[switch]$Version,
[Parameter(Mandatory=$true)][string]$IP
)
if($Version) {
    return "v1.0a"
}
    write-log -LogData "Setup-Firewall-RDPPort Starting"
    $Dtime = (get-date).DateTime
    $RULE_DESCRIPTION = "DSK Generated RDP Firewall Rule - $Dtime"
    $Port = (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").GetValue('PortNumber')
    $RULE_NAME_PREFIX = "RDP Server (DSK Generated) - "
    $Octet = '(?:0?0?[0-9]|0?[1-9][0-9]|1[0-9]{2}|2[0-5][0-5]|2[0-4][0-9])'
    [regex] $IPv4Regex = "^(?:$Octet\.){3}$Octet$"
    $CheckIP = $IP -match $IPv4Regex
    if($CheckIP) {
        Out-Report -Label "  Valid IP Addresss ==" -Data $IP
        ########################################
        $RuleName = "$RULE_NAME_PREFIX$Port TCP"
        $RuleNameCheck = Get-FirewallRule -Name $RuleName
        write-log -LogData "  Rule Name = $RuleName"
        if($RuleNameCheck.Exists) {
            write-log -LogData "  RDP TCP Firewall Rule with the same name found"
            $prompt = Prompt-User -Question "  Did you wish to replace all current DSK RDP firewall rules?" -NoHelp "No, I will modify the firewall rules manually." -YesHelp "Yes, please modify this firewall rules for me,  NOTE: If the new information for the firewall rules is incorrect, you could lose connectivity to this machine." -NoAsDefault
            if (-not ($prompt)) {
                $UPDATED_RULE_DESCRIPTION = ($RuleNameCheck.Description).Split(' --')[0] + " -- Last Updated on $Dtime"
                $shhh = Set-NetFirewallRule -NewDisplayName $RuleName `
                                            -Description $UPDATED_RULE_DESCRIPTION `
                                            -Program "%SystemRoot%\system32\svchost.exe" `
                                            -Direction Inbound `
                                            -LocalPort $Port `
                                            -RemoteAddress $IP `
                                            -Action Allow `
                                            -Enabled true `
                                            -Group 'Remote Desktop' `
                                            -ErrorAction SilentlyContinue
                write-log -LogData "  RDP TCP Firewall Rule updated!"
                $RuleName = "$RULE_NAME_PREFIX$Port UDP"
                $RuleameCheck = Get-FirewallRule -Name $RuleName
                $UPDATED_RULE_DESCRIPTION = ($RuleNameCheck.Description).Split(' --')[0] + " -- Last Updated on $Dtime"
                $shhh = Set-NetFirewallRule -NewDisplayName $RuleName `
                                            -Description $UPDATED_RULE_DESCRIPTION `
                                            -Program "%SystemRoot%\system32\svchost.exe" `
                                            -Direction Inbound `
                                            -LocalPort $Port `
                                            -RemoteAddress $IP `
                                            -Action Allow `
                                            -Enabled true `
                                            -Group 'Remote Desktop' `
                                            -ErrorAction SilentlyContinue
                write-log -LogData "  RDP UDP Firewall Rule updated!"
                $RuleName = "$RULE_NAME_PREFIX$Port Shadow TCP"
                $RuleameCheck = Get-FirewallRule -Name $RuleName
                $UPDATED_RULE_DESCRIPTION = ($RuleNameCheck.Description).Split(' --')[0] + " -- Last Updated on $Dtime"
                $shhh = Set-NetFirewallRule -NewDisplayName $RuleName `
                                            -Description $UPDATED_RULE_DESCRIPTION `
                                            -Program "%SystemRoot%\system32\svchost.exe" `
                                            -Direction Inbound `
                                            -LocalPort $Port `
                                            -RemoteAddress $IP `
                                            -Action Allow `
                                            -Enabled true `
                                            -Group 'Remote Desktop' `
                                            -ErrorAction SilentlyContinue
                write-log -LogData "  RDP Shadow TCP Firewall Rule updated!"
                write-log -LogData " DONT FORGET TO DISABLE THE DEFAULT FIREWALL RULES FOR RDP"
                write-log -LogData "Setup-Firewall-RDPPort reports 'JOB DONE'"
            }
        } else {
            $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port TCP" -DisplayName "$RULE_NAME_PREFIX$Port TCP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $Port -Protocol TCP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\svchost.exe -Group 'Remote Desktop'
            write-log -LogData "  Creating RDP TCP Firewall Rule - $RULE_NAME_PREFIX$Port TCP"
            $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port UDP" -DisplayName "$RULE_NAME_PREFIX$Port UDP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $Port -Protocol UDP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\svchost.exe -Group 'Remote Desktop'
            write-log -LogData "  Creating RDP UDP Firewall Rule - $RULE_NAME_PREFIX$Port UDP"
            $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port Shadow TCP" -DisplayName "$RULE_NAME_PREFIX$Port Shadow TCP" -Description $RULE_DESCRIPTION -Direction Inbound -Protocol TCP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\RdpSa.exe -Group 'Remote Desktop'    
            write-log -LogData "  Creating RDP Shadow TCP Firewall Rule - $RULE_NAME_PREFIX$Port Shadow TCP"
            write-log -LogData " DONT FORGET TO DISABLE THE DEFAULT FIREWALL RULES FOR RDP"
            write-log -LogData "Setup-Firewall-RDPPort reports 'JOB DONE'"
        }
    } else {
        Out-Report -Label "  Invalid IP Addresss ==" -Data $IP -CheckOK "RED"
        write-log -LogData "  ERROR: Invalid IP Addresss == $IP" -Silent
        write-log -LogData "Setup-Firewall-RDPPort aborted..."
    }
}
Function Setup-Firewall-VNCPort {
<# 
.DESCRIPTION 
Automatic setup of Firewall Rulkes for Discord Secret Knock VNC
#Note: The Default Option is always true. So if you use the switch -NoAsDefault it will make the return of 'no' as True. Its annoying and confusing but it is the way this Automation Host thing works. :(
.EXAMPLE
Setup-Firewall-VNCPort -Port 5900
#>
Param (
[switch]$Version,
[Parameter(Mandatory=$true)][string]$IP,
[string]$Port = $VNC_Port,
[string]$Path = $VNC_Path
)
if($Version) {
    return "v1.0a"
}
write-log -LogData "Setup-Firewall-VNCPort Starting" 
Out-Report -Label "  Checking VNC Path ==" -Data $Path -CheckPath
    if(Test-Path $Path) {
        $Dtime = (get-date).DateTime
        $RULE_DESCRIPTION = "DSK Generated VNC Firewall Rule - Created:$Dtime"
        $RULE_NAME_PREFIX = "VNC Server (DSK Generated) - "
        $Octet = '(?:0?0?[0-9]|0?[1-9][0-9]|1[0-9]{2}|2[0-5][0-5]|2[0-4][0-9])'
        [regex] $IPv4Regex = "^(?:$Octet\.){3}$Octet$"
        $CheckIP = $IP -match $IPv4Regex
        if($CheckIP) {
            Out-Report -Label "  Valid IP Addresss ==" -Data $IP
            ########################################
            $RuleName = "$RULE_NAME_PREFIX$Port TCP"
            $RuleNameCheck = Get-FirewallRule -Name $RuleName
            write-log -LogData "  Rule Name = $RuleName"
            if($RuleNameCheck.Exists) {
                write-log -LogData "  VNC TCP Firewall Rule with the same name found"
                $prompt = Prompt-User -Question "  Did you wish to replace all current DSK VNC firewall rules?" -NoHelp "No, I will modify the firewall rules manually." -YesHelp "Yes, please modify this firewall rules for me,  NOTE: If the new information for the firewall rules is incorrect, you could lose connectivity to this machine." -NoAsDefault
                if (-not ($prompt)) {
                    $UPDATED_RULE_DESCRIPTION = ($RuleNameCheck.Description).Split(' --')[0] + " -- Last Updated on $Dtime"
                    $shhh = Set-NetFirewallRule -NewDisplayName $RuleName `
                                                -Description $UPDATED_RULE_DESCRIPTION `
                                                -Program $Path `
                                                -Direction Inbound `
                                                -LocalPort $Port `
                                                -RemoteAddress $IP `
                                                -Action Allow `
                                                -Enabled true `
                                                -Group 'Remote Desktop' `
                                                -ErrorAction SilentlyContinue
                    write-log -LogData "  VNC TCP Firewall Rule updated!"
                    $RuleName = "$RULE_NAME_PREFIX$Port UDP"
                    $RuleameCheck = Get-FirewallRule -Name $RuleName
                    $UPDATED_RULE_DESCRIPTION = ($RuleNameCheck.Description).Split(' --')[0] + " -- Last Updated on $Dtime"
                    $shhh = Set-NetFirewallRule -NewDisplayName $RuleName `
                                                -Description $UPDATED_RULE_DESCRIPTION `
                                                -Program $Path `
                                                -Direction Inbound `
                                                -LocalPort $Port `
                                                -RemoteAddress $IP `
                                                -Action Allow `
                                                -Enabled true `
                                                -Group 'Remote Desktop' `
                                                -ErrorAction SilentlyContinue
                    write-log -LogData "  VNC UDP Firewall Rule updated!"
                    write-log -LogData " DONT FORGET TO DISABLE THE DEFAULT FIREWALL RULES FOR VNC"
                    write-log -LogData "Setup-Firewall-VNCPort reports 'JOB DONE'"
                }
            } else {
                $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port TCP" -DisplayName "$RULE_NAME_PREFIX$Port TCP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $Port -Protocol TCP -RemoteAddress $IP -Action Allow -Program $VNC_Path -Group 'Remote Desktop'
                write-log -LogData "  Creating TCP Firewall Rule - $RULE_NAME_PREFIX$Port TCP"
                $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port UDP" -DisplayName "$RULE_NAME_PREFIX$Port UDP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $Port -Protocol UDP -RemoteAddress $IP -Action Allow -Program $VNC_Path -Group 'Remote Desktop'
                write-log -LogData "  Creating UDP Firewall Rule - $RULE_NAME_PREFIX$Port UDP"
                write-log -LogData " DONT FORGET TO DISABLE THE DEFAULT FIREWALL RULES FOR VNC"
                write-log -LogData "Setup-Firewall-VNCPort reports 'JOB DONE'"
            }
        } else {
            Out-Report -Label "  Invalid IP Addresss ==" -Data $IP -CheckOK "RED"
            write-log -LogData "  ERROR: Invalid IP Addresss == $IP" -Silent
            write-log -LogData "Setup-Firewall-VNCPort aborted..."
        }
    } else {
        write-log -LogData "  Setup-Firewall-VNCPort requires a path to the VNC executable file using the -Path option" -foregroundcolor "RED"
        write-log -LogData "Setup-Firewall-VNCPort aborted..."
    }
}
Function Set-Firewall {
<# 
.DESCRIPTION 
Modifies the devices Firewall
.EXAMPLE
Mode 1: FTP, RDP, VNC (Open)
This mode creates a firewall rule for a specific application to a specific IP Address
Set-Firewall -FTP -IP 192.168.0.55 -USER 'OzDeaDMeaT' -DiscordID '548546875'
Set-Firewall -RDP -IP 192.168.0.55 -USER 'OzDeaDMeaT' -DiscordID '548546875'
Set-Firewall -VNC -IP 192.168.0.55 -USER 'OzDeaDMeaT' -DiscordID '548546875'

Mode 2: Shut (Closed)
This mode will check if there is an active connection for the specific user and if there is not it will remove the rules associated with the user it is checking for.
Set-Firewall -FTP -IP 192.168.0.55 -USER 'OzDeaDMeaT' -DiscordID '548546875' -Shut
Set-Firewall -RDP -IP 192.168.0.55 -USER 'OzDeaDMeaT' -DiscordID '548546875' -Shut
Set-Firewall -VNC -IP 192.168.0.55 -USER 'OzDeaDMeaT' -DiscordID '548546875' -Shut

Mode 3: ClearAll
This mode will remove ALL rules that have been generated. (use this for scheduled task on reboot)
Set-Firewall -ClearAll
System returns a PowerShell Object Variable for all task types.
#>
Param (
[switch]$Version,
[switch]$FTP,
[switch]$RDP,
[switch]$VNC,
[string]$IP = '',
[string]$USER = '',
[string]$DiscordID = '',
[switch]$Shut,
[switch]$ClearAll
)
if($Version) {
    return "v1.0e"
}
$outputVar = $null
$RULETYPE = ""
$RULEGROUP = ""
if($FTP) {
    $RULETYPE = 'FTP'
    $RULEGROUP = 'File and Printer Sharing'
    $Port =$FTP_Port}
if($RDP) {
    $RULETYPE = 'RDP'
    $RULEGROUP = 'Remote Desktop'
    $Port =$RDP_Port}
if($VNC) {
    $RULETYPE = 'VNC'
    $RULEGROUP = 'Remote Desktop'
    $Port =$VNC_Port}
$WILDCARD = "DSK-"
$RULEPREFIX = "$WILDCARD$RULETYPE - "
$Time = get-date -Format "yyyy-MMM-dd--HH:mm:ss"
$RULE_NAME_PREFIX = "$RULEPREFIX$DiscordID -"
$RULE_DISPLAYNAME_PREFIX = "$RULEPREFIX$USER -"
$RULE_DESCRIPTION = "AutoGenerated Firewall Rule for $USER with Discord ID $DiscordID on date $Time"

$OutputVar = New-Object -TypeName psobject 
$OutputVar | Add-Member -MemberType NoteProperty -Name Status -Value "UNKNOWN"
$OutputVar | Add-Member -MemberType NoteProperty -Name RuleType -Value $RULETYPE
$OutputVar | Add-Member -MemberType NoteProperty -Name Name -Value $USER
$OutputVar | Add-Member -MemberType NoteProperty -Name DiscordID -Value $DiscordID
$OutputVar | Add-Member -MemberType NoteProperty -Name IP -Value $IP
$OutputVar | Add-Member -MemberType NoteProperty -Name Port -Value $Port
$OutputVar | Add-Member -MemberType NoteProperty -Name Connected -Value $false
$OutputVar | Add-Member -MemberType NoteProperty -Name ExitLoop -Value $false
#check if the rules currently exist and removes
If($ClearAll) {
    Get-NetFirewallRule -Name "$WILDCARD*" | remove-NetFirewallRule
    $OutputVar.Status = "ClearAll"
    #$OutputVar.Message = "All AutoGenerated Firewall rules have been deleted."
    write-log -LogData "All AutoGenerated Firewall rules have been deleted." -Silent
    write-log -LogData $OutputVar -Silent
    write-log -LogData "Change-Firewall: ENDED" -Silent
    return $OutputVar
    }
if($Shut) {
    if ($FTP) {
        write-log -LogData "FTP Selected" -Silent
        $connected = (get-nettcpconnection | Where-Object{$_.RemoteAddress -eq $IP -and $_.LocalPort -eq $FTP_Port -and $_.State -eq 'Established'} | Measure-Object).Count
        write-log -LogData "FTP Connections = $connected" -Silent
        }
    if ($RDP) {
        write-log -LogData "RDP Selected" -Silent
        $connected = (get-nettcpconnection | Where-Object{$_.RemoteAddress -eq $IP -and $_.LocalPort -eq $RDP_Port -and $_.State -eq 'Established'} | Measure-Object).Count
        write-log -LogData "RDP Connections = $connected" -Silent
        }
    if ($VNC) {
        write-log -LogData "VNC Selected" -Silent
        $connected = (get-nettcpconnection | Where-Object{$_.RemoteAddress -eq $IP -and $_.LocalPort -eq $VNC_Port -and $_.State -eq 'Established'} | Measure-Object).Count
        write-log -LogData "VNC Connections = $connected" -Silent
        }
    if($connected -eq 0) {
        $OutputVar.Status = "Shut"
        $OutputVar.ExitLoop = $true
        $shhh = Get-NetFirewallRule -Name "$RULE_NAME_PREFIX*" | remove-NetFirewallRule
        write-log -LogData "$USER $RULETYPE Firewall rules removed" -Silent
    } else {
        $OutputVar.Connected = $true
        $OutputVar.Status = "Connected"
        write-log -LogData "$USER still connected to $RULETYPE" -Silent
        }
    } else {
    $currentRules = (get-NetFirewallRule -Name "$RULE_NAME_PREFIX *" | Measure-Object).count
    if($currentRules -gt 0) {
        get-NetFirewallRule -Name "$RULE_NAME_PREFIX *" | remove-NetFirewallRule
        write-log -LogData "Old $RULETYPE Firewall Rules Found for , removing..." -Silent
        Start-sleep 1
        }
    if ($FTP) {
        if($FTP_PASV) {
            write-log -LogData "Setting up FTP Passive Mode Firewall Rule for $USER ($DiscordID)" -Silent
            $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX FTP-TCP" -DisplayName "$RULE_DISPLAYNAME_PREFIX TCP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $FTP_Port, $FTP_PASV_PORT_MIN-$FTP_PASV_PORT_MAX -Protocol TCP -RemoteAddress $IP -Action Allow -Program $FTP_Path -Group $RULEGROUP
            $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX FTP-UDP" -DisplayName "$RULE_DISPLAYNAME_PREFIX UDP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $FTP_Port, $FTP_PASV_PORT_MIN-$FTP_PASV_PORT_MAX -Protocol UDP -RemoteAddress $IP -Action Allow -Program $FTP_Path -Group $RULEGROUP
            $OutputVar.Status = "Open"
        } else {
            write-log -LogData "Setting up FTP Active Mode Firewall Rule for $USER ($DiscordID)" -Silent
            $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX FTP-TCP" -DisplayName "$RULE_DISPLAYNAME_PREFIX TCP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $FTP_Port -Protocol TCP -RemoteAddress $IP -Action Allow -Program $FTP_Path -Group $RULEGROUP
            $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX FTP-UDP" -DisplayName "$RULE_DISPLAYNAME_PREFIX UDP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $FTP_Port -Protocol UDP -RemoteAddress $IP -Action Allow -Program $FTP_Path -Group $RULEGROUP
            $OutputVar.Status = "Open"
        }
    }
    if ($RDP) {
        write-log -LogData "Setting up RDP Firewall Rule for $USER ($DiscordID)" -Silent
        $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX RDP-TCP" -DisplayName "$RULE_DISPLAYNAME_PREFIX TCP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $RDP_Port -Protocol TCP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\svchost.exe -Group $RULEGROUP
        $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX RDP-UDP" -DisplayName "$RULE_DISPLAYNAME_PREFIX UDP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $RDP_Port -Protocol UDP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\svchost.exe -Group $RULEGROUP
        $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX Shadow RDP-TCP" -DisplayName "$RULE_DISPLAYNAME_PREFIX Shadow TCP" -Description $RULE_DESCRIPTION -Direction Inbound -Protocol TCP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\RdpSa.exe -Group $RULEGROUP
        $OutputVar.Status = "Open"
        }
    if ($VNC) {
        write-log -LogData "Setting up VNC Firewall Rule for $USER ($DiscordID)" -Silent
        $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX VNC-TCP" -DisplayName "$RULE_DISPLAYNAME_PREFIX TCP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $VNC_Port -Protocol TCP -RemoteAddress $IP -Action Allow -Program $VNC_Path -Group $RULEGROUP
        $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX VNC-UDP" -DisplayName "$RULE_DISPLAYNAME_PREFIX UDP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $VNC_Port -Protocol UDP -RemoteAddress $IP -Action Allow -Program $VNC_Path -Group $RULEGROUP
        $OutputVar.Status = "Open"
    }                
}
return $OutputVar
}
Function Reboot-Server {
Param (
[switch]$Version
)
    if($Version) {
        return "v1.0d"
    } else {
        write-log -LogData "REBOOTING NOW" -Silent
        Restart-Computer -ComputerName $env:COMPUTERNAME -Force
    }
}
#####################################################################################################################################################################################
#####################################################################################################################################################################################
#        CCCCCCCCCCCCC      OOOOOOOOO      NNNNNNNN        NNNNNNNN FFFFFFFFFFFFFFFFFFFFFF IIIIIIIIII        GGGGGGGGGGGGG
#     CCC::::::::::::C    OO:::::::::OO    N:::::::N       N::::::N F::::::::::::::::::::F I::::::::I     GGG::::::::::::G
#   CC:::::::::::::::C  OO:::::::::::::OO  N::::::::N      N::::::N F::::::::::::::::::::F I::::::::I   GG:::::::::::::::G
#  C:::::CCCCCCCC::::C O:::::::OOO:::::::O N:::::::::N     N::::::N FF::::::FFFFFFFFF::::F II::::::II  G:::::GGGGGGGG::::G
# C:::::C       CCCCCC O::::::O   O::::::O N::::::::::N    N::::::N   F:::::F       FFFFFF   I::::I   G:::::G       GGGGGG
#C:::::C               O:::::O     O:::::O N:::::::::::N   N::::::N   F:::::F                I::::I  G:::::G              
#C:::::C               O:::::O     O:::::O N:::::::N::::N  N::::::N   F::::::FFFFFFFFFF      I::::I  G:::::G              
#C:::::C               O:::::O     O:::::O N::::::N N::::N N::::::N   F:::::::::::::::F      I::::I  G:::::G    GGGGGGGGGG
#C:::::C               O:::::O     O:::::O N::::::N  N::::N:::::::N   F:::::::::::::::F      I::::I  G:::::G    G::::::::G
#C:::::C               O:::::O     O:::::O N::::::N   N:::::::::::N   F::::::FFFFFFFFFF      I::::I  G:::::G    GGGGG::::G
#C:::::C               O:::::O     O:::::O N::::::N    N::::::::::N   F:::::F                I::::I  G:::::G        G::::G
# C:::::C       CCCCCC O::::::O   O::::::O N::::::N     N:::::::::N   F:::::F                I::::I   G:::::G       G::::G
#  C:::::CCCCCCCC::::C O:::::::OOO:::::::O N::::::N      N::::::::N FF:::::::FF            II::::::II  G:::::GGGGGGGG::::G
#   CC:::::::::::::::C  OO:::::::::::::OO  N::::::N       N:::::::N F::::::::FF            I::::::::I   GG:::::::::::::::G
#     CCC::::::::::::C    OO:::::::::OO    N::::::N        N::::::N F::::::::FF            I::::::::I     GGG::::::GGG:::G
#        CCCCCCCCCCCCC      OOOOOOOOO      NNNNNNNN         NNNNNNN FFFFFFFFFFF            IIIIIIIIII        GGGGGG  GGGG
#####################################################################################################################################################################################
#IDENTITY & SERVER CONFIG############################################################################################################################# ENTER YOUR DEVICE CONFIG BELOW
$DeviceID    = "DSK_Device"                                                             #The way you refer to this specific device in Discord 
$OnlyDevice  = $false                                                                   #If $true, you do not need to specify the DeviceID when requesting access to this Device (Only set this to true if you only have 1 device using DSK)
$CmdPrefix   = '$'                                                                      #The Command prefix the bot will look for when looking at a message before considering it a command
$TimeOut     = 30                                                                      #Sets the amount of time the firewall will remain open with no incoming connection before removing firewall rules
$DynamicIP   = $false                                                                    #Marks the internet connection as a Dynamic IP Address and will cause Node-Red to keep checking what the IP Address is every time an FTP, RDP or VNC access request is made

$EnableHELP  = $true                                                                    #Enable Help responses for this DSK Device (If using multiple DSK Devices in a single channel it is recommended to nominate only 1 Device to respond to Help requests)

$EnableVNC   = $true			                                                        #Enables the Ability for a user to request VNC access
$EnableRDP   = $false			                                                        #Enables the Ability for a user to request RDP access
$EnableFTP   = $false			                                                        #Enables the Ability for a user to request FTP access
#BLACK AND WHITE LIST CONFIG#########################################################################################################################################################
$EnableWhitelist = $true                                                                #Enables the Country Whitelist, DSK will only accept connections from these countries, ##IF SET TO FALSE, THE Blacklist WILL BE USED.##
$Whitelist   = @("AU","NZ","US","CA","GB")                                              #Country Code Whitelist (All other countries will be blocked) can be found here https://www.iban.com/country-codes 
$Blacklist   = @("RU","UA","CN","IR","IQ")                                              #Country Code Blacklist (All other countries will be allowed) can be found here https://www.iban.com/country-codes 

#VNC CONFIG########################################################################################################################################### ENTER YOUR DEVICE CONFIG BELOW
$VNC_Path	 = "C:\Program Files\RealVNC\VNC Server\vncserver.exe"						#Path to VNC Server EXE
$VNC_Port    = 5900                                                                    #VNC Port if your are not using RealVNC

#REMOTE DESKTOP PROTOCOL CONFIG####################################################################################################################### ENTER YOUR DEVICE CONFIG BELOW
$RDP_Port = (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").GetValue('PortNumber')

#FILE TRANSFER PROTOCOL CONFIG#######################################################################################################################################################
$FTP_Path    = "C:\Program Files\FileZilla Server\filezilla-server.exe"                 #Path to FTP Server EXE
$FTP_PASV    = $true                                                                    #Enables FTP Passive Mode (i.e. Your FTP incoming connections are going through a NAT router)
$FTP_Port          = "Filezilla Config File not found"                                  #FileZilla Config FTP Port
$FTP_PASV_PORT_MIN = "Filezilla Config File not found"                                  #FileZilla Config FTP Lower Passive Mode Port
$FTP_PASV_PORT_MAX = "Filezilla Config File not found"                                  #FileZilla Config FTP Upper Passive Mode Port

#DSK ACCESS & DISCORD CONFIG#########################################################################################################################################################
#DISCORD CHANNELS####################################################################################################################################################################
$REQCHANNEL  = "000000000000000000"                                                     #Request Channel ID
$LOGCHANNEL  = "000000000000000000"                                                     #Log Channel ID

#ADMIN & POWER USER DISCORD GROUP ID's###############################################################################################################################################
$AdminGroup  = "000000000000000000"                                                     #Discord Group ID that you want to have all commands available
$PwrUsrGroup = "000000000000000000"                                                     #Discord Group ID that you want to have all access commands available

#The following ID's are if you wish to be more granular with the access you are granting to DSK Device (per command permissions) Only set these if you arent planning on using the Admin or PwrUsr Groups
#COMMAND PERMISSIONS#################################################################################################################################################################
$FTPGroup    = "000000000000000000"                                                     #Discord Group ID you wish to grant FTP access (not required if using AdminGroup or PwrUsrGroup)
$RDPGroup    = "000000000000000000"                                                     #Discord Group ID you wish to grant RDP access (not required if using AdminGroup or PwrUsrGroup)
$VNCGroup    = "000000000000000000"                                                     #Discord Group ID you wish to grant VNC access (not required if using AdminGroup or PwrUsrGroup)

$TESTGroup   = "000000000000000000"                                                     #Discord Group ID for TEST command (not required if using AdminGroup or PwrUsrGroup)
$HELPGroup   = "000000000000000000"                                                     #Discord Group ID for HELP command (not required if using AdminGroup or PwrUsrGroup)
$INFOGroup   = "000000000000000000"                                                     #Discord Group ID for INFO command (not required if using AdminGroup or PwrUsrGroup)
$VERSGroup   = "000000000000000000"                                                     #Discord Group ID for VERSION command (not required if using AdminGroup or PwrUsrGroup)

$SHUTGroup   = "000000000000000000"                                                     #Discord Group ID for SHUT command (not required if using AdminGroup or PwrUsrGroup)
$RELOADGroup = "000000000000000000"                                                     #Discord Group ID for RELOAD command (not required if using AdminGroup or PwrUsrGroup)
$REBOOTGroup = "000000000000000000"                                                     #Discord Group ID for REBOOT command (not required if using AdminGroup or PwrUsrGroup)

#DONT EDIT BELOW THIS LINE UNLESS YOU KNOW WHAT YOU ARE DOING########################################################################################################################
$FTPPerm 	 = @($AdminGroup,$PwrUsrGroup,$FTPGroup)                                    #FTP Permission Array
$RDPPerm 	 = @($AdminGroup,$PwrUsrGroup,$RDPGroup) 	                                #RDP Permission Array
$VNCPerm 	 = @($AdminGroup,$PwrUsrGroup,$VNCGroup)                                    #VNC Permission Array

$TESTPerm 	 = @($AdminGroup,$PwrUsrGroup,$TESTGroup)                                   #TEST Permission Array
$HELPPerm 	 = @($AdminGroup,$PwrUsrGroup,$HELPGroup)                                   #HELP Permission Array
$INFOPerm    = @($AdminGroup,$PwrUsrGroup,$INFOGroup)                                   #INFO Permission Array
$VERSPerm    = @($AdminGroup,$PwrUsrGroup,$VERSGroup)                                   #VERSION Permission Array

$SHUTPerm    = @($AdminGroup,$SHUTGroup)                                                #SHUT Permission Array
$RELOADPerm  = @($AdminGroup,$RELOADGroup)                                              #RELOAD Permission Array
$REBOOTPerm  = @($AdminGroup,$REBOOTGroup)                                              #REBOOT Permission Array

#####################################################################################################################################################################################
#####################################################################################################################################################################################
#DONT EDIT BELOW THIS LINE UNLESS YOU KNOW WHAT YOU ARE DOING########################################################################################################################
$DSK_DIR     = Split-Path $MyInvocation.MyCommand.Definition -Parent                    #The directory path that the DSK File was executed from
$DSK_LogFile = "$DSK_DIR\DSK.log" 										            	#Log File Location for this script
#DSK REQUEST PROCESSING##############################################################################################################################################################
$REQUEST_TYPE = ""

if($Init -or $Reload) {
    $DSKreturn = $null
    $DSKreturnJSON = $null
    $REQUEST_TYPE = if($Init) {"DSK Initialization"} else {"DSK Reload"}
    write-log -LogData "REQUEST: $REQUEST_TYPE REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
    $DSKreturn = Prepare-Config
    $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100
}

if($ClearFW) {
    $REQUEST_TYPE = "Clearing All Firewall Rules"
    write-log -LogData "REQUEST: $REQUEST_TYPE REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
    $DSKreturn = $null
    $DSKreturn = Set-Firewall -ClearAll
    $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100
}

if($Reboot) {
    $REQUEST_TYPE = "Clearing All Firewall Rules"
    write-log -LogData "REQUEST: $REQUEST_TYPE REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
    $shh = Set-Firewall -ClearAll
    $REQUEST_TYPE = "Server Reboot"
    write-log -LogData "REQUEST: $REQUEST_TYPE REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
    Reboot-Server
}

if($FTP) {
    $DSKreturn = $null
    $DSKreturnJSON = $null
    if($Shut) {
        $REQUEST_TYPE = "FTP (Shut Requested)"
        write-log -LogData "REQUEST: $REQUEST_TYPE  REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
        $DSKreturn = Set-Firewall -FTP -IP $IP -USER $DISCORDUSER -DiscordID $DiscordID -Shut
        $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100        
    } else {
        $REQUEST_TYPE = "FTP (Open Requested)"
        write-log -LogData "REQUEST: $REQUEST_TYPE  REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
        $DSKreturn = Set-Firewall -FTP -IP $IP -USER $DISCORDUSER -DiscordID $DiscordID
        $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100
        }
}
if($RDP) {
    $DSKreturn = $null
    $DSKreturnJSON = $null
    if($Shut) {
        $REQUEST_TYPE = "RDP (Shut Requested)"
        write-log -LogData "REQUEST: $REQUEST_TYPE  REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
        $DSKreturn = Set-Firewall -RDP -IP $IP -USER $DISCORDUSER -DiscordID $DiscordID -Shut
        $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100
    } else {
        $REQUEST_TYPE = "RDP (Open Requested)"
        write-log -LogData "REQUEST: $REQUEST_TYPE  REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
        $DSKreturn = Set-Firewall -RDP -IP $IP -USER $DISCORDUSER -DiscordID $DiscordID
        $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100
        }
}
if($VNC) {
    $DSKreturn = $null
    $DSKreturnJSON = $null
    if($Shut) {
        $REQUEST_TYPE = "VNC (Shut Requested)"
        write-log -LogData "REQUEST: $REQUEST_TYPE  REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
        $DSKreturn = Set-Firewall -VNC -IP $IP -USER $DISCORDUSER -DiscordID $DiscordID -Shut
        $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100
    } else {
        $REQUEST_TYPE = "VNC (Open Requested)"
        write-log -LogData "REQUEST: $REQUEST_TYPE  REQUESTOR: $DISCORDUSER ($DISCORDID)" -Silent
        $DSKreturn = Set-Firewall -VNC -IP $IP -USER $DISCORDUSER -DiscordID $DiscordID
        $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100
        }
}
#RETURN##############################################################################################################################################################################
if ($DSKreturnJSON -ne $null) {return $DSKreturnJSON}
