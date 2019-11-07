Param (
    [CmdletBinding()]
    [string]$LogName = (($MyInvocation.MyCommand.Path | split-path -Parent) + '\' + ((Get-Date -Format "yyy-MM-dd") + "_Migration.log")),
    
    [Parameter(Mandatory = $false)]
    [switch]$Logging,
    
    [Parameter(Mandatory = $false)]
    [switch]$ScriptCleanup
)

#region Set Logging File if -Logging switch is enabled.
<#
Author: Brian Hanson
#>
#If Logging Switch is set via command line,
If ($Logging) {
    # If $LogName variable is set, and is not full path to file.
    IF (![string]::IsNullOrEmpty($LogName) -and !($LogName -match ':')) { 
        # Default to $Env:TEMP directory + Log file Name
        $ScriptLog = $env:TEMP + "\" + $LogName
        Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
        Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
        Write-Host -Object  ": Logging file set to $ScriptLog"
    }
    # If $LogName variable is set, and contains full path, and the parent folder exists.
    Elseif (![string]::IsNullOrEmpty($LogName) -and ($LogName -match (':')) -and (Test-Path -path ($LogName | Split-Path -Parent))) {
        # Set $ScriptLog to the specified $LogName full path value.
        $ScriptLog = $LogName
        Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
        Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
        Write-Host -Object  ": Logging file set to $ScriptLog"
    }
    # If $LogName variable is set, and contains full path, and the parent folder does not exist exists.
    Elseif (![string]::IsNullOrEmpty($LogName) -and ($LogName -match (':')) -and !(Test-Path -path ($LogName | Split-Path -Parent))) {
        # Set $ScriptLog to the specified $Env:TEMP + $LogName.
        $ScriptLog = ($env:TEMP + "\" + ($LogName | Split-Path -Leaf))
        Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
        Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
        Write-Host -Object  ": Logging file set to $ScriptLog"
    }
    # If $LogName is not specified and $LogName is empty.
    Elseif ([string]::IsNullOrEmpty($LogName)) { 
        # Set $ScriptLog Default Path of $Env:Temp + Date + ScriptLog.txt (Ex: "C:\Temp\2015-06-02_ScriptLog.txt")
        $ScriptLog = $env:TEMP + "\" + (Get-date -Format yyyy-MM-dd) + '_' + 'ScriptLog.txt'
        Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
        Write-Host -Object "INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
        Write-Host -Object  ": Logging file set to $ScriptLog"
    }
}
else {
    Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
    Write-Host -Object "   INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
    Write-Host -Object  ": Logging parameter switch not detected. Proceeding with logging to file as disabled."
}
#endregion Set Logging File if -Logging switch is enabled

#region tempdirectory
$TempDirectory = $MyInvocation.MyCommand.Path | split-path -Parent
#endregion tempdirectory

#region Helper Functions
Function Write-Log{
    <#
    Author: Brian Hanson
    #>
    Param (
        # The string to be written to the log.
        [Parameter( Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        # The path to the log file.
        [Parameter( Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('LogPath')]
        [string]$Path = $ScriptLog,

        [Parameter( Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 3)]
        [ValidateSet("Error", "Warn", "Info", "Success", "Banner", "NoInfo")]
        [string]$Level = "Info"
    )
    If ($Logging)
    {
        switch ($Level)
        {                         
            'Banner'
            {
                # Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") ERROR: $Message"
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "       "   -NoNewline
                Write-Host -Object  "  $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")          $Message" | Add-Content -Path $Path -Encoding UTF8
            }
            'Error'
            {
                # Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") ERROR: $Message"
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "  ERROR"  -BackgroundColor Red -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")   ERROR: $Message" | Add-Content -Path $Path -Encoding UTF8
            }
            'Warn'
            {
                # Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") WARNING: $Message"
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "WARNING"  -BackgroundColor Yellow -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") WARNING: $Message" | Add-Content -Path $Path -Encoding UTF8
            }
            'Info'
            {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "   INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")    INFO: $Message" | Add-Content -Path $Path -Encoding UTF8
            }
            'Success'
            {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "SUCCESS"  -BackgroundColor DarkGreen -ForegroundColor White -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") SUCCESS: $Message" | Add-Content -Path $Path -Encoding UTF8
            }
            'NoInfo'
            {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") SUCCESS: $Message" | Add-Content -Path $Path -Encoding UTF8
            }
        }
    }
    else
    {
        switch ($Level)
        {                                  
            'Banner'
            {
                # Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") ERROR: $Message"
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "       "   -NoNewline
                Write-Host -Object  "  $Message"
            }
            'Error'
            {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "  ERROR"  -BackgroundColor Red -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
            }
            'Warn'
            {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "WARNING"  -BackgroundColor Yellow -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
            }
            'Info'
            {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "   INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
                Write-Host -Object  ": $Message"
            }
            'Success'
            {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object "SUCCESS"  -BackgroundColor DarkGreen -ForegroundColor White -NoNewline
                Write-Host -Object  ": $Message"
            }
            'NoInfo'
            {
                Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
                Write-Host -Object  ": $Message"
                Write-Output -InputObject "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") SUCCESS: $Message" | Add-Content -Path $Path -Encoding UTF8
            }
        }
    }
}
Function Remove-ScriptFiles {          
    Param (
        [Parameter( Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$fileName,
        [Parameter( Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$FilePath            
    )
    BEGIN {}
    PROCESS {            
        Write-Host -Object "ScriptCleanup switch paramenter specified. Script will delete itself."
        Remove-Item -Path "$FilePath\$fileName" -Force        
    }
    END {
        
    }   
}
function Get-GroupBySid () {
    param( 
        [string]$ComputerName = $env:COMPUTERNAME, 
        [string]$GroupNameSid = "S-1-5-32-544"
    ) 
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($GroupNameSid)
    $objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
    $objgroupname = ($objgroup.Value).Split("\")[1]
    return ,$objgroupname
}
Function Get-LocalGroupMembers{
<#
        .Synopsis
            Gets membership information of local groups in remote computer
 
        .Description
            This script by default queries the membership details of local administrators group on remote computers.
            It has a provision to query any local group in remote server, not just administrators group.
 
        .Parameter ComputerName
            Computer Name(s) which you want to query for local group information
 
        .Parameter LocalGroupName
            Name of the local group which you want to query for membership information. It queries 'Administrators' group when
            this parameter is not specified
 
        .Parameter OutputDir
            Name of the folder where you want to place the output file. It creates the output file in c:\temp folder
            this parameter is not used.
 
        .Example
            Get-LocalGroupMembers.ps1 -ComputerName srvmem1, srvmem2
 
            Queries the local administrators group membership and writes the details to c:\temp\localGroupMembers.CSV
 
        .Example
            Get-LocalGroupMembers.ps1 -ComputerName (get-content c:\temp\servers.txt)
 
        .Example
            Get-LocalGroupMembers.ps1 -ComputerName srvmem1, srvmem2
 
        .Notes
            Author : Sitaram Pamarthi
            WebSite: http://techibee.com
 
#>
[CmdletBinding()]
Param(
    [Parameter(    ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true
                )]
    [string]
    $ComputerName = $env:ComputerName,
 
    [Parameter()]
    [string]
    $LocalGroupName = "Administrators"
)
BEGIN {
    #$OutputFile = Join-Path $OutputDir "LocalGroupMembers.csv"
    Write-Verbose "Script will write the output to $OutputFile folder"
}
   
PROCESS{     
        try {
            $group = [ADSI]"WinNT://$ComputerName/$LocalGroupName"
            $members = @($group.Invoke("Members"))
            Write-Verbose "Successfully queries the members of $computer"
            if(!$members) {
                Write-Verbose "No members found in the group"
            }
        }        
        catch {
            Write-Verbose "Failed to query the members of $ComputerName"
        }
        foreach($member in $members) {
            try {
                $MemberName = $member.GetType().Invokemember("Name","GetProperty",$null,$member,$null)
                $MemberType = $member.GetType().Invokemember("Class","GetProperty",$null,$member,$null)
                $MemberPath = $member.GetType().Invokemember("ADSPath","GetProperty",$null,$member,$null)
                $MemberDomain = $null
                if($MemberPath -match "^Winnt\:\/\/(?<domainName>\S+)\/(?<CompName>\S+)\/") {
                    if($MemberType -eq "User") {
                        $MemberType = "LocalUser"
                    } elseif($MemberType -eq "Group"){
                        $MemberType = "LocalGroup"
                    }
                    $MemberDomain = $matches["CompName"]
        
                } elseif($MemberPath -match "^WinNT\:\/\/(?<domainname>\S+)/") {
                    if($MemberType -eq "User") {
                        $MemberType = "DomainUser"
                    } elseif($MemberType -eq "Group"){
                        $MemberType = "DomainGroup"
                    }
                    $MemberDomain = $matches["domainname"]
        
                } else {
                    $MemberType = "Unknown"
                    $MemberDomain = "Unknown"
                }
                $props = @{'LocalGroupName'            = $LocalGroupName;                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
                           'MemberType'                         = $MemberType;
                           'MemberDomain'                     = $MemberDomain;
                           'MemberName'                      = $MemberName}
                $obj = new-object -TypeName PSObject -Property $props
                Write-Output $obj   
            
            } catch {
                Write-Verbose "failed to query details of a member. Details $_"
            }
        
        }
    }
END{}
}
#endregion Helper Functions

#region Script Cleanup
if ($ScriptCleanup) {
    Remove-ScriptFiles -fileName $MyInvocation.MyCommand.Name -FilePath ($MyInvocation.MyCommand.Path | split-path -Parent)    
}
else {
    Write-Host -Object "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") " -NoNewline
    Write-Host -Object "   INFO"  -BackgroundColor White -ForegroundColor Black -NoNewline
    Write-Host -Object  ": '-ScriptCleanup' switch paramenter NOT detected. Script will NOT delete itself."
} 
#endregion Script Cleanup

Write-Log "################# Add-UserToAdministratorsGroup.ps1 #################" -Level Info

try
{
    $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
    $AdminGroup = Get-GroupBySid
    if (($Computer.psbase.children | Where-Object {$_.psBase.schemaClassName -eq "User"} | Select-Object -expand Name) -notcontains "NSTMig-User")
    {        
        $LocalUser = $Computer.Create("User", "NSTMig-User")
        $LocalUser.SetPassword('N34R5H0R3@2018')
        $LocalUser.SetInfo()
        $LocalUser.FullName = "NSTMig-User"
        $LocalUser.SetInfo()
        $LocalUser.Description= "Local Account for the migration process"
        $LocalUser.SetInfo()
        $LocalUser.UserFlags = 65536 # ADS_UF_DONT_EXPIRE_PASSWD
        $LocalUser.SetInfo()
        $group = [ADSI]("WinNT://$Env:COMPUTERNAME/$AdminGroup,group")
        $group.add("WinNT://$Env:COMPUTERNAME/NSTMig-User,user")
        
        
        $colUsers = Get-LocalGroupMembers -LocalGroupName $AdminGroup | select -ExpandProperty MemberName
        
        $UserFound = $colUsers -contains "NSTMig-User"
        
        if ($UserFound){
            Write-Log "Created user NSTMig-User and added to administrators group " -Level Success
            REG ADD "HKLM\Software\NST\Domain Migration" /v "AddNSTMig" /t REG_SZ /d "Completed" /f
            exit 0
        }
        else
        {
            Write-Log "Unable to add/create user NSTMig-User" -Level Error
            exit 1
        }
    }
    else
    {
        Write-Log "User NSTMig-User Already exists" -Level Success
        REG ADD "HKLM\Software\NST\Domain Migration" /v "AddNSTMig" /t REG_SZ /d "Completed" /f
        exit 0
    }
}
catch
{
    Write-Log "$($MyInvocation.MyCommand): $($_.Exception.Message)" -Level Error
    exit 1
}
