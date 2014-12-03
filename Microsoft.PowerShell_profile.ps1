#Import-Module ActiveDirectory -EA 0
Add-PSSnapin Quest.ActiveRoles.ADManagement -EA 0
Import-Module OneGet -EA 0
if ( $host.Name -eq "ConsoleHost" ) { Import-Module PSReadline -EA 0 }
if ( Test-Path "$env:LOCALAPPDATA\GitHub\shell.ps1" ) { . ( Resolve-Path "$env:LOCALAPPDATA\GitHub\shell.ps1" )
Import-Module posh-git
Start-SshAgent -Quiet
}
$isAdmin = ( New-Object System.Security.principal.windowsprincipal( [System.Security.Principal.WindowsIdentity]::GetCurrent() )).isInRole( [System.Security.Principal.WindowsBuiltInRole]::Administrator )

#region Registry
New-PSDrive -Name HKU  -PSProvider Registry -Root Registry::HKEY_USERS -EA 0 | Out-Null
New-PSDrive -Name HKCR -PSProvider Registry -Root Registry::HKEY_CLASSES_ROOT -EA 0 | Out-Null
New-PSDrive -Name HKCC -PSProvider Registry -Root Registry::HKEY_CURRENT_CONFIG -EA 0 | Out-Null
#endregion

#region Script Browser
#Script Browser Begin
if ( $Host.Name -ne "ConsoleHost" ) {
    if ( Test-Path "C:\Program Files (x86)\Microsoft Corporation\Microsoft Script Browser\ScriptBrowser.dll" ) {
    Add-Type -Path "C:\Program Files (x86)\Microsoft Corporation\Microsoft Script Browser\System.Windows.Interactivity.dll"
    Add-Type -Path "C:\Program Files (x86)\Microsoft Corporation\Microsoft Script Browser\ScriptBrowser.dll"
    Add-Type -Path "C:\Program Files (x86)\Microsoft Corporation\Microsoft Script Browser\BestPractices.dll"
    if ( $psISE.CurrentPowerShellTab.VerticalAddOnTools.Name -notcontains "Script Browser" ) {
        $scriptBrowser = $psISE.CurrentPowerShellTab.VerticalAddOnTools.Add( "Script Browser", [ScriptExplorer.Views.MainView], $true ) }
    if ( $psISE.CurrentPowerShellTab.VerticalAddOnTools.Name -notcontains "Script Analyzer" ) {
        $scriptAnalyzer = $psISE.CurrentPowerShellTab.VerticalAddOnTools.Add( "Script Analyzer", [BestPractices.Views.BestPracticesView], $true ) }
    $psISE.CurrentPowerShellTab.VisibleVerticalAddOnTools.SelectedAddOnTool = $scriptBrowser
}
#Script Browser End
}
#endregion
 
#region Powershell 3 and above specific commands
if ( $PSVersionTable.PSVersion.Major -ge 3 ) {
    if ( $PSDefaultParameterValues.Keys -notcontains "Format-Table:Autosize" ) {
    #insert Default Parameter Values for every command
    $PSDefaultParameterValues.Add( "Format-Table:Autosize",$True )
    }
    if ( $PSDefaultParameterValues.Keys -notcontains "Export-Csv:NoTypeInformation" ) {
    $PSDefaultParameterValues.Add( "Export-Csv:NoTypeInformation",$True )
    }
}
#endregion

#region Alias
Set-Alias -Name "wc" -Value "Write-Color"
Set-Alias -Name "wd" -Value "Write-Debug"
Set-Alias -Name "we" -Value "Write-Error"
Set-Alias -Name "wel" -Value "Write-EventLog"
Set-Alias -Name "wh" -Value "Write-Host"
Set-Alias -Name "wo" -Value "Write-Output"
Set-Alias -Name "wp" -Value "Write-Progress"
Set-Alias -Name "wv" -Value "Write-Verbose"
Set-Alias -Name "ww" -Value "Write-Warning"
Set-Alias -Name "od" -Value "Out-Default"
Set-Alias -Name "of" -Value "Out-File"
Set-Alias -Name "on" -Value "Out-Null"
Set-Alias -Name "op" -Value "Out-Printer"
Set-Alias -Name "os" -Value "Out-String"
Set-Alias -Name "tc" -Value "Test-xConnection"
Set-Alias -Name "cn" -Value "Get-ComputerName"
Set-Alias -Name "hn" -Value "Get-ComputerName"
Set-Alias -Name "up" -Value "Update-Profile"
Set-Alias -Name "igui" -Value "Install-GUI"

Set-Alias -Name "hostname" -Value "Prevent-CMDCommands"
Set-Alias -Name "ping" -Value "Prevent-CMDCommands"
#endregion

#region Custom Functions
function Get-ADAcl { param([string]$name)
Push-Location ad:
(Get-Acl (Get-QADObject $name).DN).access | Select identityreference -Unique | FT -AutoSize
Pop-Location
}

function als { param ( $arg )
gci $arg | ? { $_.PSIsContainer } | % { $sdata += $_.Fullname + ";" }
$sdata.trim( ";" )
}

function Get-ComputerName { Write-Color $env:COMPUTERNAME -ForegroundColor Yellow }

function Get-EnvironmentFolderPath { param( [switch]$AdminTools,[switch]$ApplicationData,[switch]$CDBurning,[switch]$CommonAdminTools,[switch]$CommonApplicationData,[switch]$CommonDesktopDirectory,[switch]$CommonDocuments,[switch]$CommonMusic,[switch]$CommonOemLinks,[switch]$CommonPictures,[switch]$CommonProgramFiles,[switch]$CommonProgramFilesX86,[switch]$CommonPrograms,[switch]$CommonStartMenu,[switch]$CommonStartup,[switch]$CommonTemplates,[switch]$CommonVideos,[switch]$Cookies,[switch]$Desktop,[switch]$DesktopDirectory,[switch]$Favorites,[switch]$Fonts,[switch]$History,[switch]$InternetCache,[switch]$LocalApplicationData,[switch]$LocalizedResources,[switch]$MyComputer,[switch]$MyDocuments,[switch]$MyMusic,[switch]$MyPictures,[switch]$MyVideos,[switch]$NetworkShortcuts,[switch]$Personal,[switch]$PrinterShortcuts,[switch]$ProgramFiles,[switch]$ProgramFilesX86,[switch]$Programs,[switch]$Recent,[switch]$Resources,[switch]$SendTo,[switch]$StartMenu,[switch]$Startup,[switch]$System,[switch]$SystemX86,[switch]$Templates,[switch]$UserProfile,[switch]$Windows )
if ( $AdminTools ) { [environment]::getfolderpath("AdminTools") }
if ( $ApplicationData ) { [environment]::getfolderpath("ApplicationData") }
if ( $CDBurning ) { [environment]::getfolderpath("CDBurning") }
if ( $CommonAdminTools ) { [environment]::getfolderpath("CommonAdminTools") }
if ( $CommonApplicationData ) { [environment]::getfolderpath("CommonApplicationData") }
if ( $CommonDesktopDirectory ) { [environment]::getfolderpath("CommonDesktopDirectory") }
if ( $CommonDocuments ) { [environment]::getfolderpath("CommonDocuments") }
if ( $CommonMusic ) { [environment]::getfolderpath("CommonMusic") }
if ( $CommonOemLinks ) { [environment]::getfolderpath("CommonOemLinks") }
if ( $CommonPictures ) { [environment]::getfolderpath("CommonPictures") }
if ( $CommonProgramFiles ) { [environment]::getfolderpath("CommonProgramFiles") }
if ( $CommonProgramFilesX86 ) { [environment]::getfolderpath("CommonProgramFilesX86") }
if ( $CommonPrograms ) { [environment]::getfolderpath("CommonPrograms") }
if ( $CommonStartMenu ) { [environment]::getfolderpath("CommonStartMenu") }
if ( $CommonStartup ) { [environment]::getfolderpath("CommonStartup") }
if ( $CommonTemplates ) { [environment]::getfolderpath("CommonTemplates") }
if ( $CommonVideos ) { [environment]::getfolderpath("CommonVideos") }
if ( $Cookies ) { [environment]::getfolderpath("Cookies") }
if ( $Desktop ) { [environment]::getfolderpath("Desktop") }
if ( $DesktopDirectory ) { [environment]::getfolderpath("DesktopDirectory") }
if ( $Favorites ) { [environment]::getfolderpath("Favorites") }
if ( $Fonts ) { [environment]::getfolderpath("Fonts") }
if ( $History ) { [environment]::getfolderpath("History") }
if ( $InternetCache ) { [environment]::getfolderpath("InternetCache") }
if ( $LocalApplicationData ) { [environment]::getfolderpath("LocalApplicationData") }
if ( $LocalizedResources ) { [environment]::getfolderpath("LocalizedResources") }
if ( $MyComputer ) { [environment]::getfolderpath("MyComputer") }
if ( $MyDocuments ) { [environment]::getfolderpath("MyDocuments") }
if ( $MyMusic ) { [environment]::getfolderpath("MyMusic") }
if ( $MyPictures ) { [environment]::getfolderpath("MyPictures") }
if ( $MyVideos ) { [environment]::getfolderpath("MyVideos") }
if ( $NetworkShortcuts ) { [environment]::getfolderpath("NetworkShortcuts") }
if ( $Personal ) { [environment]::getfolderpath("Personal") }
if ( $PrinterShortcuts ) { [environment]::getfolderpath("PrinterShortcuts") }
if ( $ProgramFiles ) { [environment]::getfolderpath("ProgramFiles") }
if ( $ProgramFilesX86 ) { [environment]::getfolderpath("ProgramFilesX86") }
if ( $Programs ) { [environment]::getfolderpath("Programs") }
if ( $Recent ) { [environment]::getfolderpath("Recent") }
if ( $Resources ) { [environment]::getfolderpath("Resources") }
if ( $SendTo ) { [environment]::getfolderpath("SendTo") }
if ( $StartMenu ) { [environment]::getfolderpath("StartMenu") }
if ( $Startup ) { [environment]::getfolderpath("Startup") }
if ( $System ) { [environment]::getfolderpath("System") }
if ( $SystemX86 ) { [environment]::getfolderpath("SystemX86") }
if ( $Templates ) { [environment]::getfolderpath("Templates") }
if ( $Windows ) { [environment]::getfolderpath("Windows") }
if ( $SendTo ) { [environment]::getfolderpath("SendTo") }
if ( $StartMenu ) { [environment]::getfolderpath("StartMenu") }
if ( $Startup ) { [environment]::getfolderpath("Startup") }
if ( $System ) { [environment]::getfolderpath("System") }
if ( $SystemX86 ) { [environment]::getfolderpath("SystemX86") }
if ( $Templates ) { [environment]::getfolderpath("Templates") }
if ( $UserProfile ) { [environment]::getfolderpath("UserProfile") }
if ( $Windows ) { [environment]::getfolderpath("Windows") }
}

function Get-IPConfig { param( [Switch]$IP, [Switch]$Mac, [Switch]$All )
Process {
    If ( $MAC ) { IPConfig -all | Select-String "Physical" }
    ElseIf ( $IP ) { IPConfig -all | Select-String "IPv" } 
    ElseIf ( $All ) { IPConfig -all }
    Else { IPConfig }
    }
End { "`r`n" + ( Get-Date ).DateTime }
}

function Get-MemberDefinition { param(
	[Parameter(position=0,Mandatory=$true,ValueFromPipeline=$true)][Alias("Object")]$input,
    [Parameter(position=1)]$Name )

process {
    if ( $Name ) { ( $input | Get-Member $Name ).Definition.Replace("), ", ")`n" )
	} else { ( $input | Get-Member | Out-Default ) }
    }
}

function Get-RegistryChildItem { param( $arg )
$hive = ((( $arg -replace "\[" ) -replace "\]" ) -replace ":" -split "\\" )[0]
$partialpath = ((( $arg -replace "\[" ) -replace "\]" ) -split("\\",2 ))[-1]
switch ( $hive ) {
	"HKEY_CURRENT_USER" { $hive = "HKCU" }
	"HKEY_LOCAL_MACHINE" { $hive = "HKLM" }
	"HKEY_USERS" { $hive = "HKU" }
	"HKEY_CURRENT_CONFIG" { $hive = "HKCC" }
	"HKEY_CLASSES_ROOT" { $hive = "HKCR" }
}
Get-ChildItem -Path ( $hive + ":\" + $partialpath ) -Recurse
}

function Get-RegistryItemProperty { param( $arg )
$hive = ((( $arg -replace "\[" ) -replace "\]" ) -replace ":" -split "\\" )[0]
$itemName = ((( $arg -replace "\[" ) -replace "\]" ) -split "\\" )[-1]
$partialpath = (((( $arg -replace "\[" ) -replace "\]" ) -split( "\\",2 ))[-1] ) -replace $itemName
switch ( $hive ) {
    "HKEY_CURRENT_USER" { $hive = "HKCU" }
    "HKEY_LOCAL_MACHINE" { $hive = "HKLM" }
    "HKEY_USERS" { $hive = "HKU" }
    "HKEY_CURRENT_CONFIG" { $hive = "HKCC" }
    "HKEY_CLASSES_ROOT" { $hive = "HKCR" }
}
Get-ItemProperty -Path ( $hive + ":\" + $partialpath ) -Name $itemName | Select-Object -Property $itemName
}

#For the upcoming WMF 5.0 OneGet feature, hell yee!
if ( $PSVersionTable.PSVersion.Major -ge 5 ) {
	function Find-PackageGUI { Find-Package | Out-Gridview -PassThru | Install-Package -Verbose }
}

function New-SymLink {
<#
    .SYNOPSIS
        Creates a Symbolic link to a file or directory

    .DESCRIPTION
        Creates a Symbolic link to a file or directory as an alternative to mklink.exe

    .PARAMETER Path
        Name of the path that you will reference with a symbolic link.

    .PARAMETER SymName
        Name of the symbolic link to create. Can be a full path/unc or just the name.
        If only a name is given, the symbolic link will be created on the current directory that the
        function is being run on.

    .PARAMETER File
        Create a file symbolic link

    .PARAMETER Directory
        Create a directory symbolic link

    .NOTES
        Name: New-SymLink
        Author: Boe Prox
        Created: 15 Jul 2013


    .EXAMPLE
        New-SymLink -Path "C:\users\admin\downloads" -SymName "C:\users\admin\desktop\downloads" -Directory

        SymLink                          Target                   Type
        -------                          ------                   ----
        C:\Users\admin\Desktop\Downloads C:\Users\admin\Downloads Directory

        Description
        -----------
        Creates a symbolic link to downloads folder that resides on C:\users\admin\desktop.

    .EXAMPLE
        New-SymLink -Path "C:\users\admin\downloads\document.txt" -SymName "SomeDocument" -File

        SymLink                             Target                                Type
        -------                             ------                                ----
        C:\users\admin\desktop\SomeDocument C:\users\admin\downloads\document.txt File

        Description
        -----------
        Creates a symbolic link to document.txt file under the current directory called SomeDocument.
#>
[cmdletbinding(
    DefaultParameterSetName = 'Directory',
    SupportsShouldProcess=$True
)]
Param (
    [parameter(Position=0,ParameterSetName='Directory',ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,Mandatory=$True)]
    [parameter(Position=0,ParameterSetName='File',ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True,Mandatory=$True)]
    [ValidateScript({
        If (Test-Path $_) {$True} Else {
            Throw "`'$_`' doesn't exist!"
        }
    })]
    [string]$Path,
    [parameter(Position=1,ParameterSetName='Directory')]
    [parameter(Position=1,ParameterSetName='File')]
    [string]$SymName,
    [parameter(Position=2,ParameterSetName='File')]
    [switch]$File,
    [parameter(Position=2,ParameterSetName='Directory')]
    [switch]$Directory
)
Begin {
    #Verify user is administrator
    If (-Not [bool]((whoami /groups) -match "S-1-16-12288")) {
        Write-Warning "You must be an Administrator running this under UAC to run this function!"
        Break
    }
    Try {
        $null = [mklink.symlink]
    } Catch {
        Add-Type @"
        using System;
        using System.Runtime.InteropServices;

        namespace mklink
        {
            public class symlink
            {
                [DllImport("kernel32.dll")]
                public static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
            }
        }
"@
    }
}
Process {
    #Assume target Symlink is on current directory if not giving full path or UNC
    If ($SymName -notmatch "^(?:[a-z]:\\)|(?:\\\\\w+\\[a-z]\$)") {
        $SymName = "{0}\{1}" -f $pwd,$SymName
    }
    $Flag = @{
        File = 0
        Directory = 1
    }
    If ($PScmdlet.ShouldProcess($Path,'Create Symbolic Link')) {
        Try {
            $return = [mklink.symlink]::CreateSymbolicLink($SymName,$Path,$Flag[$PScmdlet.ParameterSetName])
            If ($return) {
                $object = New-Object PSObject -Property @{
                    SymLink = $SymName
                    Target = $Path
                    Type = $PScmdlet.ParameterSetName
                }
                $object.pstypenames.insert(0,'System.File.SymbolicLink')
                $object
            } Else {
                Throw "Unable to create symbolic link!"
            }
        } Catch {
            Write-warning ("{0}: {1}" -f $path,$_.Exception.Message)
        }
    }
}
 }

function New-UniverseMode { New-Item -ItemType Directory -Path ( [Environment]::GetFolderPath("Desktop") + "\" + "Universe Mode.{ED7BA470-8E54-465E-825C-99712043E01C}" ) }

function Prevent-CMDCommands {
	$cmdError = "Using old CMD/DOS commands in Powershell is no longer tolerated because Powershell it's not a shell of you grandpa!"
	switch ( $^ ) {
	"cd" { Write-Host "Use Set-Location instead!" }
	"hostname" { Write-Host "Use $env:COMPUTERNAME instead!" }
	"ping" { Write-Host "Use Test-Connection instead!" }
	}
	Write-Error $cmdError
}

function shell: { param( [Parameter(Position=1)]$Name,[Parameter(Position=2)][switch]$ListAvailable)
if ( $ListAvailable -or !$Name ) { ( Get-ItemProperty -LiteralPath (( Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\FolderDescriptions ).PSPath )).Name | Sort-Object }
if ( $Name ) { explorer.exe "shell:$Name" }
}

function Search-File { param(
    [Parameter(Position=0,Mandatory=$true)][string]$SearchString,
    [Parameter(Position=1,Mandatory=$true, ValueFromPipeline = $true)][string]$path = ( Get-Location ).Path
    )
    try {
    [array]$dataDirectory = $null
	Get-ChildItem $path | ? { $_.Attributes -match "Directory" -and $_.Attributes -notmatch "System" -and $_.Attributes -notmatch "Hidden" -and $_.Attributes -notmatch "ReparsePoint" } | % {
    $detect = Get-Item $_.FullName
    if ( $detect ) { $dataDirectory += $_ }}
    [array]$dataDirectory | % {
    $path = $_.FullName
    [System.IO.Directory]::EnumerateFiles($path,$SearchString,[System.IO.SearchOption]::AllDirectories)	
    }
    } catch { $_ }
}

function Test-xConnection { param(
[Parameter(Position=1,ValueFromPipeline=$true)]$ComputerName,
[int]$Count=1,
[switch]$t,
[switch]$Detailed
)
#Write-Host "Using Test-xConnection, improved Test-Connection function."
if ( $t ) { $Count=999999999 }
$destination = ( Get-WmiObject Win32_PingStatus -Filter "Address=`"$ComputerName`" AND ResolveAddressNames=$true" ).ProtocolAddressResolved

if ( $Detailed ) {
Test-Connection -ComputerName $ComputerName -Count $Count | Select-Object @{ Name = "Source";Expression = { $_.PSComputerName } },@{ Name = "Destination";Expression = { $destination } },IPV4Address,IPV6Address,@{ Name = "Bytes";Expression = { $_.BufferSize } },@{ Name = "Time(ms)";Expression = { $_.ResponseTime } }
} else {
Test-Connection -ComputerName $ComputerName -Count $Count | Select-Object @{ Name = "Destination";Expression = { $destination } },IPV4Address,@{ Name = "Bytes";Expression = { $_.BufferSize } },@{ Name = "Time(ms)";Expression = { $_.ResponseTime } }
}
}

function Write-Color { param ( $ForegroundColor )
	# save the current color
    $fc = $host.UI.RawUI.ForegroundColor

    # set the new color
    $host.UI.RawUI.ForegroundColor = $ForegroundColor

    # output
    if ( $args ) { Write-Output $args } else { $input | Write-Output }

    # restore the original color
    $host.UI.RawUI.ForegroundColor = $fc
}
#endregion

#region Update-Profile
function Get-WebFile { param( $url,$fullPath )
$reg = ( Get-Item -Path "hkcu:Software\Microsoft\Windows\CurrentVersion\Internet Settings" ).property | ? { $_ -eq "ProxyServer" }
$is = Get-ItemProperty -path "hkcu:Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name AutoConfigURL -EA 0
if ( $is ) {
    try { Start-BitsTransfer -Source $url -Destination $fullPath -EA 1 }
    catch [System.Management.Automation.ActionPreferenceStopException] {
        try { throw $_ }
        catch {
        $Credentials = Get-Credential
        Start-BitsTransfer -Source $url -Destination $fullPath -ProxyUsage SystemDefault -ProxyAuthentication Basic -ProxyCredential $Credentials | Out-Null
        }
    }
} elseif (( $reg -eq $null ) -and ( $env:USERDNSDOMAIN -ne $null )) {
    $proxy = ( "http=proxy.$($env:USERDNSDOMAIN):8080" -replace "schul","prod" ) -replace "test","prod"
    Set-ItemProperty -path "hkcu:Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Type DWORD -Value 1
    Set-ItemProperty -path "hkcu:Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Type String -Value $proxy | Out-Null
    } else { Start-BitsTransfer -Source $url -Destination $fullPath | Out-Null }
}

function Update-Profile {

$psProfileFileName = "Microsoft.PowerShell_profile.ps1"
$psISEProfileFileName = "Microsoft.PowerShellISE_profile.ps1"

$urlPSProfile = "https://raw.githubusercontent.com/ALIENQuake/WindowsPowerShell/master/$psProfileFileName"

$psPersonalPatch = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\"

$fullPathPSProfile = $psPersonalPatch + $psProfileFileName

Get-WebFile $urlPSProfile $fullPathPSProfile

Copy-Item -Path $fullPathPSProfile -Destination ( $psPersonalPatch + "\" + $psISEProfileFileName ) -Force | Out-Null

Reload-Profile
}

function Reload-Profile {
[array]$dataProfileFiles = $Profile.AllUsersAllHosts,$Profile.AllUsersCurrentHost,$Profile.CurrentUserAllHosts,$Profile.CurrentUserCurrentHost
$dataProfileFiles | % { if ( Test-Path $_ ) { Write-Verbose "Running $_" ; . $_ | Out-Null }}
}
#endregion

#region Info
if ( $host.name -eq "PowerGUIScriptEditorHost" ) {
return
}
if ( $host.name -eq "ConsoleHost" ) {
$color_decoration = [ConsoleColor]::DarkGreen
$color_Host = [ConsoleColor]::Green
$color_Location = [ConsoleColor]::Cyan
}
if ( $host.name -notmatch "Windows PowerShell ISE Host" ) { $host.ui.rawui.WindowSize.Width = "120" }

#add global variable if it doesn't already exist
if ( !($global:LastCheck) ) {
	$global:LastCheck = Get-Date
    $global:cdrive = Get-WMIObject -query "Select Freespace,Size from win32_logicaldisk where deviceid = 'c:'"
}

#only refresh disk information once every 15 minutes
$min = ( New-TimeSpan $Global:lastCheck ).TotalMinutes
if ( $min -ge 15 ) {
    $global:cdrive = Get-WMIObject -query "Select Freespace,Size from win32_logicaldisk where deviceid = 'c:'"
    $global:LastCheck = Get-Date
}

#[int]$freeMem = ( Get-Wmiobject -query "Select FreeAndZeroPageListBytes from Win32_PerfFormattedData_PerfOS_Memory" ).FreeAndZeroPageListBytes/1mb
[int]$freeMem  =  [math]::round( ( Get-WmiObject -Class Win32_OperatingSystem ).FreePhysicalMemory / 1024, 2 )
$cpu = ( Get-WmiObject -Class win32_processor ).loadpercentage | Select-Object -First 1

$pcount = ( Get-Process ).Count
$diskinfo = "{0:N2}" -f (( $global:cdrive.freespace/1gb )/( $global:cdrive.size/1gb )*100 )

#get uptime
$time = Get-WmiObject -class Win32_OperatingSystem
$t = $time.ConvertToDateTime( $time.Lastbootuptime )
[TimeSpan]$uptime = New-TimeSpan $t $( Get-Date )
$up = "$( $uptime.days )d $( $uptime.hours )h $( $uptime.minutes )m $( $uptime.seconds )s"

#$text = "CPU:"+$cpu+"% Procs:"+$pcount+$diskinfo+ " "+( [char]0x25b2 )+$up +" "+( Get-Date -format g )
$text = "CPU:{0}% Memory:{6}MB Process:{1} Free C:{2}% {3}{4} {5}" -f $cpu,$pcount,$diskinfo,( [char]0x25b2 ),$up,( Get-Date -format g ),$FreeMem

$systemInfo = [char]0x250c
$systemInfo += ( [char]0x2500 ).ToString()*$text.length
$systemInfo += [char]0x2510
$systemInfo += "`n"
$systemInfo += ( [char]0x2502 )+$text+( [char]0x2502 )
$systemInfo += "`n"
$systemInfo += [char]0x2514
$systemInfo += ( [char]0x2500 ).ToString()*$text.length
$systemInfo += [char]0x2518

#endregion

#region Powershell Prompt
function Shorten-Path { param( [string]$path )
   $location = $path.Replace( $env:USERPROFILE, "~" ) 
   # remove prefix for UNC paths 
   $location = $location -replace "^[^:]+::"
   # make path shorter like tabs in Vim,
   # handle paths starting with \\ and . correctly
   # return ( $location -replace "\\( \.? )( [^\\] )[^\\]*( ?=\\ )","\$1$2" )
   # return standard location 
   return $location
}

function global:prompt {
	$realLASTEXITCODE = $LASTEXITCODE
	# Make sure that Windows and .Net know where we are at all times
	[Environment]::CurrentDirectory = ( Get-Location -PSProvider FileSystem ).ProviderPath

	# Check Running Jobs
    $jobsCount = (Get-Job -State Running).Count
    
	# Custom color for Windows console
    if ( $Host.Name -eq "ConsoleHost" ) {
        Write-Host $promptString -NoNewline -ForegroundColor Blue
    # Default color for the rest.
    } else {
        Write-Host $promptString -NoNewline
    }
    #Set the PowerShell session time, computername and current location in the title bar.

    #Get start time for the current PowerShell session, $pid is a special variable for the current PowerShell process ID.
    [datetime]$psStart = ( get-Process -id $pid ).StartTime
    
    #Strip off the millisecond part with Substring(). The millisecond part will come after the last period.
    $s = (( Get-Date ) - $psStart).ToString()
    $elapsed = $s.Substring( 0,$s.LastIndexOf( "." )) 
    if ( $env:COMPUTERNAME -ne $env:USERDOMAIN ) {
        $title = "{0}{1}{2}{3}{4}{5}{6}{7}{8}" -f ( Shorten-Path ( Get-Location ).Path )," | ",$env:USERDNSDOMAIN,"\",$env:USERNAME,"@",$env:computername," | ",$elapsed
    } else {
        $title = "{0}{1}{2}{3}{4}{5}{6}" -f ( Shorten-Path ( Get-Location ).Path )," | ",$env:USERNAME,"@",$env:computername," | ",$elapsed
    }
    $host.ui.rawui.WindowTitle = $title

    Write-Host "$( ( Get-History -count 1 ).id+1 ) " -n -f yellow
    if ( $env:COMPUTERNAME -ne $env:USERDOMAIN ) {
        Write-Host $env:USERDNSDOMAIN -n -f $color_Host
        Write-Host "\" -n
    }
    Write-Host $env:USERNAME -n -f $color_Host
    Write-Host "@" -n
    Write-Host ( [net.dns]::GetHostName() ) -n -f $color_Host
    Write-Host " "-n -f $color_decoration
    Write-Host ( Shorten-Path ( Get-Location ).Path ) -n -f $color_Location
    
	Write-VcsStatus
	
	if ( $NestedPromptLevel -gt 0 ) {
    
	$myPrompt = ( " " + "+" * $NestedPromptLevel + ">" )
    $myPrompt
    } else { Write-Host " >" -n }
	$global:LASTEXITCODE = $realLASTEXITCODE
    return " "
}
#endregion

Write-Host "Welcome Bartosz, together we will rule the galaxy with an iron fist and Powershell - it's not a shell of you grandpa!"
Write-Host $systemInfo -ForegroundColor Green
Write-Host ""
