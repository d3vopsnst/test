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

#endregion helper functions

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

Write-Log "################# Change-DNSRecords.ps1 #################" -Level Info

try
{
    $OldDNSInfo = Get-WmiObject win32_networkadapterconfiguration -filter “ipenabled = 'true'” | select -ExpandProperty DNSServerSearchOrder
    if(!($OldDNSInfo -eq $null -or $OldDNSInfo -eq ''))
    {
        for ($i = 0; $i -lt $OldDNSInfo.Count; $i++) 
        {
            $t = $i + 1
            Write-Log "Adding DNS entry: $($OldDNSInfo[$i])" -Level Info
            REG ADD "HKLM\Software\NST\Domain Migration" /v "DNSServer_$t" /t REG_SZ /d "$($OldDNSInfo[$i])" /f
        }
    }
    else
    {
         Write-Log "No DNS entry found in the Machine" -Level Info  
    }
    
    # Changing DNS
    $wmi = Get-WmiObject win32_networkadapterconfiguration -filter “ipenabled = 'true'”
    $wmi.SetDNSServerSearchOrder(@("10.0.150.189", "10.0.40.30", "10.0.40.205", "10.1.40.191",  "10.0.40.85")) 
    
    #check if DNS records were changed succesfully
    $check = Get-WmiObject win32_networkadapterconfiguration -filter “ipenabled = 'true'” | select -ExpandProperty DNSServerSearchOrder
    if ($check -contains "10.0.40.205" -and $check -contains "10.1.40.191" -and $check -contains "10.0.150.189" -and $check -contains "10.0.40.30" -and $check -contains "10.0.40.85" )
    {
        Write-Log "Succesfully added DNS records" -Level Success
        REG ADD "HKLM\Software\NST\Domain Migration" /v "ChangeDNSRecords" /t REG_SZ /d "Completed" /f
        exit 0              
    }
    else
    {
        Write-Log "Unable to set DNS records" -Level Info
        exit 1
    }  
}
catch
{
     Write-Log "$($MyInvocation.MyCommand): $($_.Exception.Message)" -Level Error
     exit 1
}
