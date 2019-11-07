 #requires –Version 2.0
<#
.SYNOPSIS

    AUTHOR:         Brian J. Hanson, CareFusion, Brian.Hanson1@CareFusion.com
    DATE:           2015-07-13
    Last Modified:  2016-10-12

.DESCRIPTION

       Using the 'File attributes' (Collection) section of the PCI 'Config File', If specified ( comma separated values) the following items will be identified.

    1. Identifies the current parent process ID (PCI process Name)

    2. Gets the file version information of the process executible.

    3. If found, the GUID information from file attribute 'Comments' is used to create Uninstall registry key. (Unless Specified by -GUID Parameter)

    3. Adds/Sets 'DisplayVersion' property, with the value of the File Version, to 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\<GUID>'. 

    5. If found, the IconPath information from file attribute 'Comments' is used to create DisplayIcon property.

    6. If found, the HelpLink information from file attribute 'Comments' is used to create HelpLink property.
    
    

.PARAMETER GUID

    Used to identify the registry key under "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" 

.PARAMETER NoUninstall

    Switch parameter used to hide the registration from "Add-Remove Programs".


.EXAMPLE

    Set-PCIVersionReg -GUID '{01234567-89AB-CDEF-0123-456789ABCDEF}'

    
    If: 
    'MED Station PCI.exe' file version = 1.0.0.1
    'MED Station PCI.exe' file attribute 'Comments' contains "C:\CFN.ico" and exists.
    'MED Station PCI.exe' file attribute 'Comments' contains "http://www.carefusion.com"
    'MED Station PCI.exe' file attribute 'FileDescription' exists ("Installer for Med Station Software.")
    'MED Station PCI.exe' file attribute 'CompanyName' exists ("CareFusion")

    It will create the following:

    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'DisplayName'     'MED Station PCI'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'DisplayVersion'  '1.0.0.1'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'DisplayIcon'     'C:\CFN.ico'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'HelpLink'        'http://www.carefusion.com'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'Comments'        'Installer for Med Station Software.'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'Publisher'       'CareFusion'

.EXAMPLE

    Set-PCIVersionReg

    
    If: 
    'MED Station PCI.exe' file version = 1.0.0.1
    'MED Station PCI.exe' file attribute 'Comments' contains valid GUID ("{01234567-89AB-CDEF-0123-456789ABCDEF}")
    'MED Station PCI.exe' file attribute 'Comments' contains "C:\CFN.ico" and exists.
    'MED Station PCI.exe' file attribute 'Comments' contains "http://www.carefusion.com"
    'MED Station PCI.exe' file attribute 'FileDescription' exists ("Installer for Med Station Software.")
    'MED Station PCI.exe' file attribute 'CompanyName' exists ("CareFusion")

    It will create:
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}'
    
    And it will create the following:

    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'DisplayName'     'MED Station PCI'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'DisplayVersion'  '1.0.0.1'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'DisplayIcon'     'C:\CFN.ico'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'HelpLink'        'http://www.carefusion.com'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'Comments'        'Installer for Med Station Software.'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' 'Publisher'       'CareFusion'

.NOTES
    
    If the parent registry key does not exist, it will create the registry key, then the create property and set propery value.
    
    Example:
    
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{01234567-89AB-CDEF-0123-456789ABCDEF}' does not exist

    Creates '{01234567-89AB-CDEF-0123-456789ABCDEF}' under 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    Then creates and sets String properties for that key.

    This Function is enabled with exit codes to allow errors to be passed through to external executibles (PCI/DOTNETINSTALLER/CMD.exe)
    If setting the registry key fails, it will exit with an exit code.

    dotnetinstaller cmd component example:
    1              2                       3                   4               5                                        6            7 8
    ______________ _______________________ ___________________ ________        ________________________________________ ____________ _ __________________                       
    powershell.exe -executionpolicy bypass -windowstyle hidden -command "& { & '#CABPATH\Scripts\Set-PCIVersionReg.ps1' -NoUninstall ; Exit $LASTEXITCODE}"

    1. Use exe directly and not /cmd.exe powershell.exe (required for passing exit codes to dotnetinstaller
    2. Set executionpolicy to bypass, this only sets it temporarily (This Time), allows script execution from unsigned sources.
    3. Hide the powershell console window
    4. Run script as command and not as "-file", allows use of proper exit codes.
    5. Specify file location of script according to "CABPATH", Equates to "#TEMPPATH\GUID"
    6. Optional parameter to hide PCI registration from "Add-Remove Programs"
    7. separater ';' used to separate the commands.
    8. Exit powershell exe with last exit code. This will force powershell.exe to return the same exit code from the powershell script .ps1.
       PowerShell.exe will return with the last exit code from the script and subsequently the DotNetInstaller will see this code.

#>
Param(
[Parameter(
            Mandatory=$false,
            HelpMessage="Enter the GUID used to register the executible under the Uninstall registry. Ex: '{01234567-89AB-CDEF-0123-456789ABCDEF}'"
            )]
[String]$GUID,
[Parameter(
            Mandatory=$false,
            HelpMessage="Hide visibility via ""Add-Remove Programs"" by using the 'NoUninstall' Parameter"
            )]
[Switch]$NoUninstall

)

$ProcessPath = ((Get-Process -Id (gwmi win32_process -Filter "processid='$pid'").parentprocessid).Path)

#region GUID Check
If (
    [String]::IsNullOrEmpty($GUID)
    ){

        If ( #If CSV
            [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match ','
            ){
              #Split values by ',' delimeter. and search each value for regex
              Foreach (
                       $Line in ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -split ',')
                       ){
                 
                         If (
                             #Validate GUID -match regex and Length includes '{' and '}'
                             ($Line -match("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$")) -and
                             ($Line.Length -eq 38)
                             ){
                               Write-Output -InputObject $Line
                               $GUID = $Line
                               $Line.Length
                               }
                         elseif (
                                  #Validate GUID -match and Length excludes '{' and '}'
                                  ($Line -match("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$")) -and
                                  ($Line.Length -eq 36)
                                 ){
                                   #Add '{}' around $GUID value.
                                   Write-Output -InputObject $Line
                                   $GUID = '{'+$Line+'}'
                                   $Line.Length
                                   }
                         else{
                              Write-Output -InputObject """$Line"" does not match GUID REGEX check"
                              }
                         }
              }
        elseif ( #If not CSV and matches GUID Regex
                ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -notmatch ',') -and
                ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments  -match("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$"))
                ){
                  If (
                       [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments.Length -eq 38
                      ){
                        Write-Output -InputObject ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments)
                        $GUID = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments
                        $GUID.Length
                        }
                  elseif (
                          [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments.Length -eq 36
                          ){
                             Write-Output -InputObject ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments)
                             $GUID = '{'+ [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments +'}'
                             $GUID.Length
                            }
                  Write-Output -InputObject ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments)
                  $GUID = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments)
                  }
        else {}
      }
#endregion GUID Check

#region ICON Check
$ICONPaths = @()
If ( #If CSV
    ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match ',') -and
    ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match '.ico')
    ){
      #Split values by ',' delimeter. and search each value for regex
      Foreach (
               $Line in ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -split ',')
               ){
                 If (
                     #Validate Path Exists and file exists and is .ICO extension.
                     (Test-path -path $Line) -and
                     ($Line -match '.ico') -and
                     (Get-Item -Path $Line).Extension -eq '.ico'
                     ){
                       Write-Output -InputObject $Line
                       $object = New-Object -TypeName PSObject
                       $object | Add-Member -Name 'ValidPath' -MemberType Noteproperty -Value $Line
                       $ICONPaths += $object
                       }
                 else{
                      Write-Output -InputObject """$Line"" does not match valid ICON path"
                      }
                 }
     #If more than one IconPath was specified, select first valid path.
     If (
         $ICONPaths.Count -gt 1
         ){
            $ICOPath = $ICONPaths[0].ValidPath
            }
     else{$ICOPath = $ICONPaths[0].ValidPath}
      }
elseif ( #If not CSV and matches .ico
        ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -notmatch ',') -and
        ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match '.ico')
        ){
          If (
               (Test-path -path ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments)) -and
               (Get-Item -Path ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments)).Extension -eq '.ico'
              ){
                Write-Output -InputObject ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments)
                $ICOPath = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments
                }
          else{
               }
          }
else {
      }
#endregion ICON Check

#region HelpLink Check
$HelpLinks = @()
If ( #If CSV
    ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match ',') -and
    ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match 'http')
    ){
      #Split values by ',' delimeter. and search each value for regex
      Foreach (
               $Line in ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -split ',')
               ){
                 If (
                     #Validate Path Exists and file exists and is .ICO extension.
                     $Line -match 'http:' -or
                     $Line -match 'https:'
                     ){
                       Write-Output -InputObject $Line
                       $object = New-Object -TypeName PSObject
                       $object | Add-Member -Name 'Link' -MemberType Noteproperty -Value $Line
                       $HelpLinks += $object
                       }
                 else{
                      Write-Output -InputObject """$Line"" does not match a web Link"
                      }
                 }
     #If more than one IconPath was specified, select first valid path.
     If (
         $HelpLinks.Count -gt 1
         ){
            $HelpLink = $HelpLinks[0].Link
            }
     else{
          $HelpLink = $HelpLinks[0].Link
          }
      }
elseif ( #If not CSV and matches .ico
        ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -notmatch ',') -and
        ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match 'http')
        ){
          If (
               [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match 'http:' -or
               [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments -match 'https:'
              ){
                Write-Output -InputObject ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments)
                $HelpLink = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").Comments
                }
          else{
               $HelpLink = $null
               }
          }
else {
      $HelpLink = $null
      }
#endregion HelpLink Check

#region Main Function (Register Uninstall Strings)
If (
    ![String]::IsNullOrEmpty($GUID)
    ){
        $PCIRegPath      = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$GUID"
        
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -Name $GUID -ItemType Directory
        If(
           Test-Path $PCIRegPath
           ){
              Write-Output -InputObject "Successfully created ""$PCIRegPath"""
             }
        else {Exit 1}

        #region Create Array to store pending registry changes.
        $RegArray = @()
        $object = New-Object -TypeName PSObject
        $object | Add-Member -Name 'Name' -MemberType Noteproperty -Value 'DisplayName'
        $object | Add-Member -Name 'Type' -MemberType Noteproperty -Value 'String'
        $object | Add-Member -Name 'Value' -MemberType Noteproperty -Value ((Get-ItemProperty -Path $ProcessPath).BaseName)
        $RegArray += $object
        $object = New-Object -TypeName PSObject
        $object | Add-Member -Name 'Name' -MemberType Noteproperty -Value 'DisplayVersion'
        $object | Add-Member -Name 'Type' -MemberType Noteproperty -Value 'String'
        $object | Add-Member -Name 'Value' -MemberType Noteproperty -Value ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").FileVersion)
        $RegArray += $object
        If ($HelpLink){
                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -Name 'Name' -MemberType Noteproperty -Value 'HelpLink'
                        $object | Add-Member -Name 'Type' -MemberType Noteproperty -Value 'String'
                        $object | Add-Member -Name 'Value' -MemberType Noteproperty -Value $HelpLink
                        $RegArray += $object
                       }
        If ($ICOPath){
                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -Name 'Name' -MemberType Noteproperty -Value 'DisplayIcon'
                        $object | Add-Member -Name 'Type' -MemberType Noteproperty -Value 'String'
                        #$object | Add-Member -Name 'Value' -MemberType Noteproperty -Value 'C:\Windows\Carefusion.ico'
                        $object | Add-Member -Name 'Value' -MemberType Noteproperty -Value $ICOPath
                        $RegArray += $object
                      }
        If (
            ![String]::IsNullOrEmpty([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").CompanyName)
            ){
                $object = New-Object -TypeName PSObject
                $object | Add-Member -Name 'Name' -MemberType Noteproperty -Value 'Publisher'
                $object | Add-Member -Name 'Type' -MemberType Noteproperty -Value 'String'
                #$object | Add-Member -Name 'Value' -MemberType Noteproperty -Value 'CareFusion'
                $object | Add-Member -Name 'Value' -MemberType Noteproperty -Value ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").CompanyName)
                $RegArray += $object
              }
        If (
            ![String]::IsNullOrEmpty([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").FileDescription)
            ){
                $object = New-Object -TypeName PSObject
                $object | Add-Member -Name 'Name' -MemberType Noteproperty -Value 'Comments'
                $object | Add-Member -Name 'Type' -MemberType Noteproperty -Value 'String'
                #$object | Add-Member -Name 'Value' -MemberType Noteproperty -Value 'Installation Security Settings and Patches.'
                $object | Add-Member -Name 'Value' -MemberType Noteproperty -Value ([System.Diagnostics.FileVersionInfo]::GetVersionInfo("$ProcessPath").FileDescription)
                $RegArray += $object
              }
        If (
            !$NoUninstall
            ){
                $object = New-Object -TypeName PSObject
                $object | Add-Member -Name 'Name' -MemberType Noteproperty -Value 'UninstallString'
                $object | Add-Member -Name 'Type' -MemberType Noteproperty -Value 'String'
                $object | Add-Member -Name 'Value' -MemberType Noteproperty -Value 'No_uninstall'
                $RegArray += $object
              }

        #endregion Create Array to store pending registry changes.
        
        Foreach (
                 $Item in $RegArray
                 ){
                   If (
                       [String]::IsNullOrEmpty((Get-ItemProperty -Path $PCIRegPath -Name ($Item.Name)))
                       ){
                         New-ItemProperty -Path $PCIRegPath -Name $Item.Name -PropertyType $Item.Type -Value $Item.Value -Force
                         }
                   Else{Set-ItemProperty -Path $PCIRegPath -Name $Item.Name -Value $Item.Value -Force}
                   
                   If (
                       (Get-ItemProperty -Path $PCIRegPath | Select -ExpandProperty $Item.Name ) -eq $Item.Value
                       ){
                         Write-Output -InputObject ("Successfully added property name " + '"'+ $Item.Name+'"' + " to ""$PCIRegPath""")
                         }
                   else {
                         Write-Output -InputObject ("Failed to add property name " + '"'+ $Item.Name+'"' + " to ""$PCIRegPath""")
                         Exit 1
                         }
                   }

      }
else{
     Write-Output -InputObject "No valid GUID was specified. Cannot proceed."
     Exit 1
     }
#endregion Main Function (Register Uninstall Strings)