Param (
    [CmdletBinding()]
    [string]$LogName = (($MyInvocation.MyCommand.Path | split-path -Parent) + '\' + ((Get-Date -Format "yyy-MM-dd") + "_Migration.log")),
    
    [Parameter(Mandatory = $false)]
    [switch]$Logging,
    
    [Parameter(Mandatory = $false)]
    [switch]$ScriptCleanup
)

#region Load Assemblies
[void][Reflection.Assembly]::LoadWithPartialName("System.Core")

#Windows Forms (message boxes, etc)  (Assembly)
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

#WPF Main GUI Form (Assembly)
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')

#Load additional dlls to allow Console control for "Hide-Console" and "Show-Console" functions
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
 
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'

#Load additional code to allow Console control for bringing console window to front "[Tricks]::SetForegroundWindow($ConsoleWindowHandle)"
Add-Type @"
  using System;
  using System.Runtime.InteropServices;
  public class Tricks {
     [DllImport("user32.dll")]
     [return: MarshalAs(UnmanagedType.Bool)]
     public static extern bool SetForegroundWindow(IntPtr hWnd);
  }
"@
#endregion Load Assemblies

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
Function Select-Folder{
    $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    if (([int]$PSVersionTable.PSVersion.Major) -le 2) 
    {
        $ProcessStartInfo.FileName = "$TempDirectory\FolderSelection.exe"
    } else {
        $ProcessStartInfo.FileName = "$TempDirectory\FolderSelect.exe"
    }
    
    $ProcessStartInfo.RedirectStandardError = $true
    $ProcessStartInfo.RedirectStandardOutput = $true
    $ProcessStartInfo.UseShellExecute = $false
    $ProcessStartInfo.CreateNoWindow = $true
    $ProcessStartInfo.Arguments = @()
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessStartInfo
    $Process.Start() | Out-Null
    $Process.WaitForExit()
    [pscustomobject]@{
        StdOut = $Process.StandardOutput.ReadToEnd().Trim()
        StdErr = $Process.StandardError.ReadToEnd().Trim()
        Runtime = ($Process.ExitTime - $Process.StartTime).TotalSeconds
        ExitCode = $Process.ExitCode  
    }
}
Function Hide-Console {
#function utilizing Assembly loaded previously. Controls Powershell console window visibility.
    $consolePtr = [Console.Window]::GetConsoleWindow()
  #0 hide
 [Console.Window]::ShowWindow($consolePtr, 0)
}
Function Show-Console {
#function utilizing Assembly loaded previously. Controls Powershell console window visibility.
   $consolePtr = [Console.Window]::GetConsoleWindow()
  #5 show
 [Console.Window]::ShowWindow($consolePtr, 5)
}
function Get-Hash {
<#
.Synopsis
This Generates hash values of files and strings.
.Description
Function serves to provide a hashing method for both STRINGS and Files. 
Microsoft 'Get-FileHash' currently will not work on string values.

This will default to SHA1, but the available values are MD5, SHA1, SHA256, SHA384, and SHA512

.Example
Get-Hash -String "Hello World!"

String       HashType Hash                                    
------       -------- ----                                    
Hello World! SHA1     2ef7bde608ce5404e97d5f042f95f89f1c232871

.Example
Get-Hash -String "Hello World!" -HashType SHA256

String       HashType Hash                                                            
------       -------- ----                                                            
Hello World! SHA256   7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069

.Example
(Get-Hash -String "Hello World!" -HashType SHA256).Hash
7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069

.Example
Get-Hash -File C:\Temp\test.txt | ft -AutoSize

File             HashType Hash                                    
----             -------- ----                                    
C:\Temp\test.txt SHA1     6D3A5A78CC3890C1C932E7DBAD008F4C10CF5850
   
   
.Parameter String
The String to be hashed.

.Parameter File
The full path of File to be hashed.

.Parameter HashType
Specify the Hash Type
MD5
SHA1 *default*
SHA256
SHA384
SHA512

.Notes
NAME:  Get-Hash
AUTHOR: Brian Hanson
LASTEDIT: 09/24/2015
KEYWORDS: Hash, File, String, MD5, SHA1, SHA256, SHA384, SHA512
.Link
    NA
#>
    [cmdletbinding()]
    param (
        [parameter(mandatory=$false,parametersetname="String")]$String,
        [ValidateScript({If(Test-Path -Path $_ ){$true}else{Throw """$_"" is not a valid file path."}})]
        [parameter(mandatory=$false,parametersetname="File")]$File,
        [parameter(mandatory=$false,parametersetname="String")]
        [validateset("MD5","SHA1","SHA256","SHA384","SHA512")]
        [parameter(mandatory=$false,parametersetname="File")]
        [validateset("MD5","SHA1","SHA256","SHA384","SHA512")]
        [string]$HashType = "SHA1"
    )
    Begin{[Reflection.Assembly]::LoadWithPartialName("System.Core") | Out-Null}
    Process{
            switch (
                    $PsCmdlet.ParameterSetName
                    ){ 
                        "String" {
                                    Write-Verbose -Message "String parameter selected. Value : ""$String"""
                                    $StringBuilder = New-Object System.Text.StringBuilder
                                    switch ($HashType) {
                                                            "MD5"       { $Provider = New-Object System.Security.Cryptography.MD5CryptoServiceProvider }
                                                            "SHA1"      { $Provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider }
                                                            "SHA256"    { $Provider = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider }
                                                            "SHA384"    { $Provider = New-Object System.Security.Cryptography.SHA384CryptoServiceProvider }
                                                            "SHA512"    { $Provider = New-Object System.Security.Cryptography.SHA512CryptoServiceProvider }
                                                        }
                                    $Provider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))| ForEach-Object {[Void]$StringBuilder.Append($_.ToString("x2"))}
                                    $Object = New-Object -TypeName PSObject
                                    $Object | Add-Member -MemberType NoteProperty -Name 'String' -value $String
                                    $Object | Add-Member -MemberType NoteProperty -Name 'HashType' -Value $HashType
                                    $Object | Add-Member -MemberType NoteProperty -Name 'Hash' -Value $StringBuilder.ToString()
                                    Write-Verbose -Message "Completed computing Hash for ""$String"""
                                  } 
                        "File" {
                                Write-Verbose -Message "File parameter selected. Value : ""$File"""
                                $StringBuilder = New-Object System.Text.StringBuilder
                                Write-Verbose -Message "Computing Hash for ""$((Get-item -path $File).BaseName)"". Depending on file size and hash type, this may take some time."
                                $InputStream = New-Object System.IO.FileStream($File,[System.IO.FileMode]::Open)
                                switch ($HashType) {
                                                        "MD5"       { $Provider = New-Object System.Security.Cryptography.MD5CryptoServiceProvider }
                                                        "SHA1"      { $Provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider }
                                                        "SHA256"    { $Provider = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider }
                                                        "SHA384"    { $Provider = New-Object System.Security.Cryptography.SHA384CryptoServiceProvider }
                                                        "SHA512"    { $Provider = New-Object System.Security.Cryptography.SHA512CryptoServiceProvider }
                                                    }
                                $Provider.ComputeHash($InputStream) | Foreach-Object { [void]$StringBuilder.Append($_.ToString("X2")) }
                                $InputStream.Close()
                                $Object = New-Object -TypeName PSObject
                                $Object | Add-Member -MemberType NoteProperty -Name 'File' -value $File
                                $Object | Add-Member -MemberType NoteProperty -Name 'HashType' -Value $HashType
                                $Object | Add-Member -MemberType NoteProperty -Name 'Hash' -Value $StringBuilder.ToString()
                                Write-Verbose -Message "Completed computing Hash for ""$File"""
                                }
                    } #end switch
            }
    End{return $Object}
}
function Set-ConsoleIcon {
##############################################################################
##
## Script: Set-ConsoleIcon.ps1
## By: Aaron Lerch
## Website: www.aaronlerch.com/blog 
##
## Set the icon of the current console window to the specified icon
##
## Usage:  Set-ConsoleIcon [string]
##
## ie:
##
## PS:1 > Set-ConsoleIcon "C:\Icons\special_powershell_icon.ico" 
##
##############################################################################

param(
    [string] $iconFile
)

$WM_SETICON = 0x80
$ICON_SMALL = 0

function Main
{
    [System.Reflection.Assembly ]::LoadWithPartialName("System.Drawing") | out-null

    # Verify the file exists
    if ([System.IO.File]::Exists($iconFile) -eq $TRUE)
    {
        $icon = new-object System.Drawing.Icon($iconFile) 

        if ($icon -ne $null)
        {
            $consoleHandle = GetConsoleWindow
            SendMessage $consoleHandle $WM_SETICON $ICON_SMALL $icon.Handle | out-null
        }
    }
    else 
    {
        Write-Host "Icon file not found"
    }
}


## Invoke a Win32 P/Invoke call.
## From: Lee Holmes
## http://www.leeholmes.com/blog/GetTheOwnerOfAProcessInPowerShellPInvokeAndRefOutParameters.aspx
function Invoke-Win32([string] $dllName, [Type] $returnType, 
   [string] $methodName, [Type[]] $parameterTypes, [Object[]] $parameters) 
{
   ## Begin to build the dynamic assembly
   $domain = [AppDomain]::CurrentDomain
   $name = New-Object Reflection.AssemblyName 'PInvokeAssembly'
   $assembly = $domain.DefineDynamicAssembly($name, 'Run') 
   $module = $assembly.DefineDynamicModule('PInvokeModule')
   $type = $module.DefineType('PInvokeType', "Public,BeforeFieldInit")

   ## Go through all of the parameters passed to us.  As we do this, 
   ## we clone the user's inputs into another array that we will use for
   ## the P/Invoke call.  
   $inputParameters = @()
   $refParameters = @()
  
   for($counter = 1; $counter -le $parameterTypes.Length; $counter++) 
   {
      ## If an item is a PSReference, then the user 
      ## wants an [out] parameter.
      if($parameterTypes[$counter - 1] -eq [Ref])
      {
         ## Remember which parameters are used for [Out] parameters 
         $refParameters += $counter

         ## On the cloned array, we replace the PSReference type with the 
         ## .Net reference type that represents the value of the PSReference, 
         ## and the value with the value held by the PSReference. 
         $parameterTypes[$counter - 1] = 
            $parameters[$counter - 1].Value.GetType().MakeByRefType()
         $inputParameters += $parameters[$counter - 1].Value
      }
      else
      {
         ## Otherwise, just add their actual parameter to the
         ## input array.
         $inputParameters += $parameters[$counter - 1]
      }
   }

   ## Define the actual P/Invoke method, adding the [Out] 
   ## attribute for any parameters that were originally [Ref] 
   ## parameters.
   $method = $type.DefineMethod($methodName, 'Public,HideBySig,Static,PinvokeImpl', 
      $returnType, $parameterTypes) 
   foreach($refParameter in $refParameters)
   {
      $method.DefineParameter($refParameter, "Out", $null)
   }

   ## Apply the P/Invoke constructor
   $ctor = [Runtime.InteropServices.DllImportAttribute ].GetConstructor([string])
   $attr = New-Object Reflection.Emit.CustomAttributeBuilder $ctor, $dllName
   $method.SetCustomAttribute($attr)

   ## Create the temporary type, and invoke the method.
   $realType = $type.CreateType() 
   $realType.InvokeMember($methodName, 'Public,Static,InvokeMethod', $null, $null, 
      $inputParameters)

   ## Finally, go through all of the reference parameters, and update the
   ## values of the PSReference objects that the user passed in. 
   foreach($refParameter in $refParameters)
   {
      $parameters[$refParameter - 1].Value = $inputParameters[$refParameter - 1]
   }
}

function SendMessage([IntPtr] $hWnd, [Int32] $message, [Int32] $wParam, [Int32] $lParam) 
{
    $parameterTypes = [IntPtr], [Int32], [Int32], [Int32]
    $parameters = $hWnd, $message, $wParam, $lParam

    Invoke-Win32 "user32.dll" ([Int32]) "SendMessage" $parameterTypes $parameters 
}

function GetConsoleWindow()
{
    Invoke-Win32 "kernel32" ([IntPtr]) "GetConsoleWindow"
}

. Main
}
Function Get-FileName{
Param($InitialDirectory = $Env:Temp)

#Function to open the "Open File Dialog" to allow graphically browsing for a file.

Begin{
      [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
      }
Process{
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "Archive (*.gho)|*.gho|ALL (*.*)|*.*"
        $OpenFileDialog.ShowDialog() | Out-Null
        }
End{
    If (
        ![String]::IsNullOrEmpty($OpenFileDialog.FileName)
        ){
          Return (Get-Item -Path $OpenFileDialog.FileName)
          }
    }
}
function Unzip{
#Function unzips -ZipFile to -OutPath
    param([string]$zipfile, [string]$outpath)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}
Function Test-Write{
Param($Folder)
$Result = $false
$RNDFile = [System.IO.Path]::GetRandomFileName()
If (
    Test-Path -Path $Folder
    ){
      New-Item -Path $Folder -Name $RNDFile -ItemType File -ErrorAction SilentlyContinue | Out-Null
      If (
          Test-Path -Path "$Folder\$RNDFile"
          ){
            Remove-Item -Path "$Folder\$RNDFile" | Out-Null
            Return $true
            }
      Else {Return $false}
      }
Else {Return $false}
}
Function Check-AllBoxes {
    if ( $AD_User_Box.Text.Length) {
        $OK_Button.IsEnabled = $true
    }
    else {
        $OK_Button.IsEnabled = $false
    }
}
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

Write-Log "################# Get-UserInformation.ps1 #################" -Level Info

#Make sure console window is hidden as to allow only form to be shown.
Hide-Console

#region XAML Code, Form and Object Creation

#region WPF Form Code
# This section uses a "Here-String" to define the XAML code
# This code can be edited in visual studio "WPF Application" project and then copied back into this section.
# If copying from Visual Studio, you may need to replace all the "x:Name" text with just "Name". This will prevent issues with the "Read XAML Code" section/function

[xml]$XAML = @"
<Window 
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Active Directory User" Height="191.777" Width="270.563">
    <Grid>
        <Label Name="Description_Label" Content="Provide the AD user to configure" HorizontalAlignment="Left" Margin="16,8,0,0" VerticalAlignment="Top" Width="231" FontWeight="Bold" Height="29" FontSize="14" Grid.ColumnSpan="2"/>
        <Label Name="AD_User_Label" Content="User" HorizontalAlignment="Left" Margin="17,51,0,0" VerticalAlignment="Top" Width="46" FontWeight="Bold" Height="26"/>
        <TextBox Name="AD_User_Box" HorizontalAlignment="Left" Height="22" Margin="63,53,0,0" VerticalAlignment="Top" Width="176" Grid.ColumnSpan="2"/>
        <Button Name="OK_Button" Content="OK" HorizontalAlignment="Left" Margin="72,118,0,0" VerticalAlignment="Top" Width="74" Height="20" FontWeight="Bold"/>
        <Button Name="Cancel_Button" Content="Cancel" HorizontalAlignment="Left" Margin="163,118,0,0" VerticalAlignment="Top" Width="74" Height="20" FontWeight="Bold"/>
    </Grid>
</Window>
"@

#endregion WPF Form Code

#region Read XAML Code
$global:OK= "CANCEL"
$reader=(New-Object System.Xml.XmlNodeReader $xaml)
try{
     $Form=[Windows.Markup.XamlReader]::Load($reader)
     }
catch{
       Write-Log "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered."
       #exit
       }
#endregion Read XAML Code

# Creates objects for each "Name" in XAML Code. Stores Form Objects In PowerShell 
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)}
#endregion XAML Code, Form and Object Creation

$OK_Button.IsEnabled = $false

# Checking the event TextChanged to validate if all information has been Filled
$AD_User_Box.Add_TextChanged({Check-AllBoxes})

$OK_Button.Add_Click({
                        if($AD_User_Box.text -ne $null -or $AD_User_Box.text -ne ''){
                            $AD_User = $AD_User_Box.text.trim()                           
                            REG ADD "HKLM\Software\NST\Domain Migration" /v "AD_User" /t REG_SZ /d "$AD_User" /f
                            Write-Log -Message "Registry Key Added with user information" -Level Success
                            $global:OK= "OK"
                            $Form.Close()
                            exit 0
                        }
                        else
                        {
                            [System.Windows.Forms.MessageBox]::Show("The user textbox can not be empty", 'Warning', 'OK', 'Error')
                            $global:OK= "OK"
                        }
                      })#end 'OK' Button

# 'Cancel' Button
# Upon click, just closes the form.
$Cancel_Button.Add_Click({
                            Write-Log -Message "Tool was canceled by user." -Level Info
                            #Close and exit
                            $form.Close()
                            Exit 1223
                          })

#endregion Create clickable actions for each form object which is "Clickable" (Buttons, etc)

#region Show the form
$Form.Topmost = $true
$Form.Icon = $IconPath
$Form.WindowStartupLocation = 'CenterScreen'
$Form.ShowDialog() | out-null
$Form.Activate()
#endregion Show the form

#If [X] was clicked on the main form.
If (($Form.IsActive -eq $false) -and ($OK -ne 'OK')){Write-Log -Message "Tool was closed by user." -Level Info; Exit 2}
