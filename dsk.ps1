<#
Discord Secret Knock
Created by Josh 'OzDeaDMeaT' McDougall
Version: v0.0005A (Initial Alpha Release)
Date: 26-02-2022
########################################
#NOTES
- Initial script parameters setup
- Initial Data Structure for Node-Red complete
- Got setup VNC Function working as well as giving the user an option to update existing DSK firewall rules

########################################
Copyright (c) 2021 Josh 'OzDeaDMeaT' McDougall, All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
4. Utilization of this software for commercial use is prohibited unless authorized by the software copywrite holder in writing (electronic mail).

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>
########################################
########################################
param(
    [switch]$Init,      #Initializes DSK
    [switch]$Reload,    #Will reload dsk.ps1 variables
    [switch]$ClearFW,   #Clears All temp firewall connections typically prior to a restart
    [switch]$CloseFW,   #Close a firewall rule (Deletes it) that was opened by DSK
    [switch]$OpenFW,    #Opens a firewall rule that was opened by DSK
    [string]$IP,        #Variable to be passed to the firwall function
    [string]$USER,      #Discord username of user recieving access
    [string]$DiscordID  #Discord ID of user recieving access
)
########################################
########################################
#IDENTITY & SERVER CONFIG
$DeviceID    = "AccessTest"                                                             #The way you refer to this specific device in Discord 
$OnlyDevice  = $false                                                                   #If $true, you do not need to specify the DeviceID when requesting access to this Device (Only set this to true if you only have 1 device using DSK)
$CmdPrefix   = '$'                                                                      #The Command prefix the bot will look for when looking at a message before considering it a command
$TimeOut     = 120                                                                      #Sets the amount of time the firewall will remain open with no incoming connection before removing firewall rules
$DynamicIP   = $true                                                                    #Marks the internet connection as a Dynamic IP Address and will cause Node-Red to keep checking what the IP Address is
$IPCheckTime = 600                                                                      #If DynamicIP is set to $true, this is the interval (seconds) between checks (not recommended to be set less that 600 seconds)


#APPLICATION PATH CONFIG
$VNC_Path	 = "C:\Program Files\RealVNC\VNC Server\vncserver.exe"						#Path to VNC Server EXE
$FTP_Path    = ""                                                                       #Path to FTP Server EXE


#ACCESS CONFIG
$EnableVNC   = $true			                                                        #Enables the Ability for a user to request VNC access
$DiscordVNC  = "946424156638040084"                                                     #Discord Server Group ID# for VNC Access
$EnableRDP   = $false			                                                        #Enables the Ability for a user to request RDP access
$DiscordRDP  = "946424156638040084"                                                     #Discord Server Group ID# for RDP Access
$EnableFTP   = $false			                                                        #Enables the Ability for a user to request FTP access
$DiscordFTP  = "946424156638040084"                                                     #Discord Server Group ID# for FTP Access


#BLACK AND WHITE LIST CONFIG
$EnableWhitelist = $true                                                                #Enables the Country Whitelist, DSK will only accept connections from these countries
$Whitelist   = @("AU","NZ","US","CA","GB")                                              #Country Code Whitelist (All other countries will be blocked) can be found here https://www.iban.com/country-codes 
$EnableBlacklist = $false                                                               #Enables the Country Blacklist, DSK will NOT accept connections from these countries
$Blacklist   = @("RU","UA","CN","IR","IQ")                                              #Country Code Blacklist (All other countries will be allowed) can be found here https://www.iban.com/country-codes 


#DONT EDIT BELOW THIS LINE UNLESS YOU KNOW WHAT YOU ARE DOING########################################################################################################################
$VNCPerm 	 = @($DiscordVNC) 	                                                        #VNC Permission Array
$RDPPerm 	 = @($DiscordRDP) 	                                                        #RDP Permission Array
$FTPPerm 	 = @($DiscordFTP) 	                                                        #FTP Permission Array


#SERIOUSLY DONT EDIT BELOW THIS LINE UNLESS YOU KNOW WHAT YOU ARE DOING##############################################################################################################
$DSK_DIR     = Split-Path $MyInvocation.MyCommand.Definition -Parent                    #The directory path that the DSK File was executed from
$DSK_LogFile = "$DSK_DIR\DSK.log" 										            	#Log File Location for this script


#FUNCTIONS###########################################################################################################################################################################
Function Out-Report {
    <# 
    .DESCRIPTION 
    Automated method of outputting information in a formatted way to the CLI 
    .EXAMPLE
    Out-Report -Label "List of Variables"
    Out-Report -Label "`$CommandPrefix ==" -Data $CommandPrefix
    Out-Report -Label "`$HELP          ==" -Data $HELP -Bool
    #>
    param(
    [Parameter(Mandatory=$true)][string]$Label,
    $Data,
    [string]$LabelColour = "white",
    [string]$DataColour = "yellow",
    [string]$CheckOK = "green",
    [string]$CheckDisabled = "yellow",
    [string]$CheckFail = "red",
    [switch]$CheckPath,
    [switch]$Bool			#Do not use CheckPath and Bool at the same time
    )
    
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
        } ElseIf ($Bool){
            if($data -eq $true) {
                write-host "Enabled" -ForegroundColor $CheckOK
            } else {
                write-host "Disabled" -ForegroundColor $CheckDisabled
            }
        } else {
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
    $LogData = "",
    $LogFile = $DSK_LogFile,
    $foregroundcolor = ($Host.UI.RawUI).ForegroundColor,
    [switch]$nonewline,
    [switch]$Silent
    )
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
[Parameter(Mandatory=$true)][string]$Question,
[Parameter(Mandatory=$true)][string]$NoHelp,
[Parameter(Mandatory=$true)][string]$YesHelp,
[switch]$NoAsDefault
)
    $DefaultOption = if($NoAsDefault) {1} else {0}
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription ("&Yes", $YesHelp)
    $no = New-Object System.Management.Automation.Host.ChoiceDescription ("&No", $NoHelp)
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $rtn = $Host.ui.PromptForChoice("", $Question, $options, $DefaultOption) 
return $rtn
}
Function Check-DSK {
<# 
.DESCRIPTION
Check-DSK Function checks if all the paths are configured correctly as well as outputting all configuration items to the CLI
 .EXAMPLE
Check-DSK
#>
write-host "Reloading DSK.ps1 file into memory..." -ForegroundColor "white"
. .\DSK.ps1
write-host " "
write-host "Checking DSK Variables..." -ForegroundColor "white"
Out-Report -Label "  DeviceID             ==" -Data $DeviceID
Out-Report -Label "  OnlyDevice           ==" -Data $OnlyDevice -Bool
Out-Report -Label "  CmdPrefix            ==" -Data $CmdPrefix
Out-Report -Label "  TimeOut              ==" -Data $TimeOut
Out-Report -Label "  DynamicIP            ==" -Data $DynamicIP
Out-Report -Label "  IPCheckTime          ==" -Data $IPCheckTime
write-host " "
write-host "File Paths" -ForegroundColor "white"
Out-Report -Label "  VNC_Path            ==" -Data $VNC_Path -CheckPath
Out-Report -Label "  FTP_Path            ==" -Data $FTP_Path -CheckPath
write-host " "
write-host "Access Settings" -ForegroundColor "white"
Out-Report -Label "  EnableVNC           ==" -Data $EnableVNC -Bool
Out-Report -Label "  DiscordVNC          ==" -Data $DiscordVNC
Out-Report -Label "  EnableRDP           ==" -Data $EnableRDP -Bool
Out-Report -Label "  DiscordRDP          ==" -Data $DiscordRDP
Out-Report -Label "  EnableFTP           ==" -Data $EnableFTP -Bool
Out-Report -Label "  DiscordFTP          ==" -Data $DiscordFTP
write-host " "
write-host "Country Black and White lists" -ForegroundColor "white"
Out-Report -Label "  EnableWhitelist     ==" -Data $EnableWhitelist -Bool
Out-Report -Label "  Whitelist           ==" -Data $Whitelist
Out-Report -Label "  EnableBlacklist     ==" -Data $EnableBlacklist -Bool
Out-Report -Label "  Blacklist           ==" -Data $Blacklist
}
Function Prepare-Config {
<# 
.DESCRIPTION 
Prepares the configuration information in dsk.ps1 into a standardized structure for Node-Red to interprit.
Returns a PowerShell Object of all the configuration information
 .EXAMPLE
Prepare-Config
#>
    $Perms = $null
    $Perms = New-Object -TypeName psobject
    $Perms | Add-Member -MemberType NoteProperty -Name VNC -Value $DiscordVNC
    $Perms | Add-Member -MemberType NoteProperty -Name RDP -Value $DiscordRDP
    $Perms | Add-Member -MemberType NoteProperty -Name FTP -Value $DiscordFTP

    $DSK = $null
    $DSK = New-Object -TypeName psobject
    $DSK | Add-Member -MemberType NoteProperty -Name DeviceID -Value $DeviceID
    $DSK | Add-Member -MemberType NoteProperty -Name OnlyDevice -Value $OnlyDevice
    $DSK | Add-Member -MemberType NoteProperty -Name CmdPrefix -Value $CmdPrefix
    $DSK | Add-Member -MemberType NoteProperty -Name TimeOut -Value $TimeOut
    $DSK | Add-Member -MemberType NoteProperty -Name DynamicIP -Value $DynamicIP
    $DSK | Add-Member -MemberType NoteProperty -Name IPCheckTime -Value $IPCheckTime
    $DSK | Add-Member -MemberType NoteProperty -Name EnableVNC -Value $EnableVNC
    $DSK | Add-Member -MemberType NoteProperty -Name EnableRDP -Value $EnableRDP
    $DSK | Add-Member -MemberType NoteProperty -Name EnableFTP -Value $EnableFTP
    $DSK | Add-Member -MemberType NoteProperty -Name Permissions -Value $Perms
    $DSK | Add-Member -MemberType NoteProperty -Name EnableWhitelist -Value $EnableWhitelist
    $DSK | Add-Member -MemberType NoteProperty -Name Whitelist -Value $Whitelist
    $DSK | Add-Member -MemberType NoteProperty -Name EnableBlacklist -Value $EnableBlacklist
    $DSK | Add-Member -MemberType NoteProperty -Name Blacklist -Value $Blacklist
return $DSK
}
Function Initialize-DSK {
<# 
.DESCRIPTION 
Initializes Discord Secret Knock (DSK)
 
.EXAMPLE
dsk.ps1 -Init
#>

}
Function Setup-Firewall-RDPPort {
Param (
[Parameter(Mandatory=$true)][string]$IP
)
    write-log -LogData "Setup-Firewall-RDPPort Starting"
    $Dtime = (get-date).DateTime
    $RULE_DESCRIPTION = "DSK Generated RDP Firewall Rule - $Dtime"
    $RDPPort = (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").GetValue('PortNumber')
    $RULE_NAME_PREFIX = "RDP Server (DSK Generated) - "
    $Octet = '(?:0?0?[0-9]|0?[1-9][0-9]|1[0-9]{2}|2[0-5][0-5]|2[0-4][0-9])'
    [regex] $IPv4Regex = "^(?:$Octet\.){3}$Octet$"
    $CheckIP = $IP -match $IPv4Regex
    if($CheckIP) {
        #check if the rules currently exist
        $currentRules = (get-NetFirewallRule -Name "$RULE_NAME_PREFIX *" | Measure-Object).count
        if($currentRules -gt 0) {

            get-NetFirewallRule -Name "$RULE_NAME_PREFIX *" | remove-NetFirewallRule
            write-log -LogData "Old Firewall Rules Found, removing..." -Silent
            Start-sleep 1
            }		
        $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port TCP" -DisplayName "$RULE_NAME_PREFIX$Port Shadow TCP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $RDPPort -Protocol TCP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\svchost.exe -Group 'Remote Desktop'
        $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port UDP" -DisplayName "$RULE_NAME_PREFIX$Port UDP" -Description $RULE_DESCRIPTION -Direction Inbound -LocalPort $RDPPort -Protocol UDP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\svchost.exe -Group 'Remote Desktop'
        $shhh = New-NetFirewallRule -Name "$RULE_NAME_PREFIX$Port Shadow TCP" -DisplayName "$RULE_NAME_PREFIX$Port Shadow TCP" -Description $RULE_DESCRIPTION -Direction Inbound -Protocol TCP -RemoteAddress $IP -Action Allow -Program %SystemRoot%\system32\RdpSa.exe -Group 'Remote Desktop'
        }
    write-log -LogData "Setup-Firewall-RDPPort Finished"
}

####################################################################################################

Function Get-FirewallRule {
<# 
.DESCRIPTION 
Returns information about a firewall rule
.EXAMPLE
Get-FirewallRule -Name "Test Firewall Rule Alpha 1"
#>
Param (
[Parameter(Mandatory=$true)][string]$Name
)
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
[Parameter(Mandatory=$true)][string]$Str,
[Parameter(Mandatory=$true)][string]$Seperator,
[switch]$Trim,
[string]$Index = 0
)
    $rtn = $str.Split($Seperator)
    $rtn = if($Trim) {
        $rtn[$Index].Trim()
    } else {
        $rtn[$Index]
    }
return $rtn
}
Function Setup-Firewall-VNCPort {
<# 
.DESCRIPTION 
Automatic setup of Firewall Rulkes for Discord Secret Knock VNC
#Note: The Default Option is always true. So if you use the switch -NoAsDefault it will make the return of 'no' as True. Its annoying and confusing but it is the way this Automation Host thing works. :(
.EXAMPLE
Prompt-User -Question "Is DDC2 Awesome?!?" -NoHelp "You shouldn't lie, lying is back" -YesHelp "Damn Right it is"
Prompt-User -Question "Did you poop yourself?" -NoHelp "No, it was just an epic fart!" -YesHelp "Yes, it's what all the kids are doing these days, it's hip and happening!" -NoAsDefault
#>
Param (
[Parameter(Mandatory=$true)][string]$IP,
[string]$Port = 5900,
[string]$Path = $VNC_Path
)
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

if($Init -or $Reload) {
    $DSKreturn = Prepare-Config
    $DSKreturnJSON = $DSKreturn | ConvertTo-Json -Depth 100
    #write-log -LogData "##JOB-DONE#####################################JOB-DONE##"
}
#write-log -LogData "##JOB-DONE#####################################JOB-DONE##" -Silent    
if ($DSKreturnJSON -ne "null") {return $DSKreturnJSON}
