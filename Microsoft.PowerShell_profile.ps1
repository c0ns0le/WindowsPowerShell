if ( $PSVersionTable.PSVersion.Major -ge 5 ) { Import-Module OneGet }
if ( $host.Name -eq "ConsoleHost" ) { Import-Module PSReadline -EA 0 }
if ( Test-Path "$env:LOCALAPPDATA\GitHub\shell.ps1" ) { . Resolve-Path "$env:LOCALAPPDATA\GitHub\shell.ps1" | Out-Null ; Import-Module posh-git ; Start-SshAgent -Quiet }
if ( Test-Path "$env:ProgramFiles\Quest Software\Management Shell for AD\Quest.ActiveRoles.ADManagement.Format.ps1xml" ) { Add-PSSnapin Quest.ActiveRoles.ADManagement -EA 0
    Update-FormatData -PrependPath "$env:ProgramFiles\Quest Software\Management Shell for AD\Quest.ActiveRoles.ADManagement.Format.ps1xml" }

if ( !( $env:Path -split ";" | ? { $_ -like "*git\bin" } )) {
if ( Test-Path D:\Programs\GitPortable\bin\git.exe ) { $env:Path = $env:Path + ";D:\Programs\GitPortable\bin;D:\Programs\GitPortable\cmd" }
}

#region Console
function Set-ConsoleWindowSize { param(
    [int]$x = $host.ui.rawui.windowsize.width,
    [int]$y = $host.ui.rawui.windowsize.heigth)
    $windowSize = New-Object System.Management.Automation.Host.Size($x,$y)
    $bufferSize = New-Object System.Management.Automation.Host.Size($x,($y*75))
    $host.ui.rawui.BufferSize = $bufferSize
    $host.ui.rawui.WindowSize = $windowSize
}

$consoleFontCode = @"
    public delegate bool SetConsoleFont( 
        IntPtr hWnd, 
        uint DWORD 
    ); 
 
    public delegate uint GetNumberOfConsoleFonts(); 
 
    public delegate bool GetConsoleFontInfo( 
        IntPtr hWnd, 
        bool BOOL, 
        uint DWORD, 
        [Out] CONSOLE_FONT_INFO[] ConsoleFontInfo 
    ); 
 
 
    [StructLayout(LayoutKind.Sequential)] 
    public struct CONSOLE_FONT_INFO 
    { 
        public uint nFont; 
        public COORD dwFontSize; 
    } 
 
    [StructLayout(LayoutKind.Sequential)] 
    public struct COORD 
    { 
        public short X; 
        public short Y; 
    } 
 
    [DllImport("kernel32.dll")] 
    public static extern IntPtr GetModuleHandleA( 
        string module 
    ); 
 
    [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)] 
    public static extern IntPtr GetProcAddress( 
        IntPtr hModule, 
        string procName 
        ); 
 
    [DllImport("kernel32.dll", SetLastError = true)] 
    public static extern IntPtr GetStdHandle( 
        int nStdHandle 
        ); 
 
    [DllImport("kernel32.dll", SetLastError = true)] 
    public static extern bool GetCurrentConsoleFont( 
        IntPtr hConsoleOutput, 
        bool bMaximumWindow, 
        out CONSOLE_FONT_INFO lpConsoleCurrentFont 
        ); 
"@
Add-Type -MemberDefinition $consoleFontCode -Name Console -Namespace Win32API | Out-Null
Remove-Variable consoleFontCode
$_hmod = [Win32API.Console]::GetModuleHandleA("kernel32") 

"SetConsoleFont", "GetNumberOfConsoleFonts", "GetConsoleFontInfo" | % { 
        $param = @() 
        $proc = [Win32API.Console]::GetProcAddress($_hmod, $_) 
        $delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($proc, "Win32API.Console+$_") 
 
        $delegate.Invoke.OverloadDefinitions[0] -match "^[^(]+\((.*)\)" > $null 
        $argtypes = $Matches[1] -split ", " | ? { $_ } | % { 
                '[{0}] ${1}' -f ($_ -split " "); 
                $param += "$" + ($_ -split " ")[-1] 
            } 
        $argtypes = $argtypes -join ", " 
        $param = $param -join ", " 
        iex @" 
            function $_($argtypes){ 
                `$$_ = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($proc, 'Win32API.Console+$_') 
                `$$_.Invoke( $param ) 
            } 
"@ 
} 

$STD_OUTPUT_HANDLE = -11 
$_hConsoleScreen = [Win32API.Console]::GetStdHandle($STD_OUTPUT_HANDLE)

$_DefaultFont = New-Object Win32API.Console+CONSOLE_FONT_INFO
[Win32API.Console]::GetCurrentConsoleFont($_hConsoleScreen, $true, [ref]$_DefaultFont) | Out-Null

function Get-ConsoleFontInfo {
    $_FontsNum = GetNumberOfConsoleFonts
    $_ConsoleFonts = New-Object Win32API.Console+CONSOLE_FONT_INFO[] $_FontsNum
    GetConsoleFontInfo $_hConsoleScreen $false $_FontsNum $_ConsoleFonts > $null
    $_ConsoleFonts | Select-Object @{l="nFont";e={$_ConsoleFonts.Count-$_.nFont-1}}, @{l="dwFontSizeX";e={$_.dwFontSize.X}}, @{l="dwFontSizeY";e={$_.dwFontSize.Y}} | Sort-Object nFont
}

function Set-ConsoleFont { param(
	[Parameter(position=0,Mandatory=$true)][Uint32]$size=$_DefaultFont.nFont,
	[IntPtr]$hWnd=$_hConsoleScreen)
    $flag = SetConsoleFont $hWnd $size
    if ( !$flag ) { Get-ConsoleFontInfo ; throw "Illegal font index number. Check correct number using 'Get-ConsoleFontInfo'." }
}

function Reset-ISEColors {
	$Host.PrivateData.RestoreDefaults()
	$Host.PrivateData.RestoreDefaultConsoleTokenColors()
	$Host.PrivateData.RestoreDefaultTokenColors()
	$Host.PrivateData.RestoreDefaultXmlTokenColors()
}

#endregion

#region Registry
New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS -EA 0 | Out-Null
New-PSDrive -Name HKCR -PSProvider Registry -Root Registry::HKEY_CLASSES_ROOT -EA 0 | Out-Null
New-PSDrive -Name HKCC -PSProvider Registry -Root Registry::HKEY_CURRENT_CONFIG -EA 0 | Out-Null
#endregion

#region Right-Click: Run with Powershell
if (( Get-ItemProperty -Path HKCR:\Microsoft.PowerShellScript.1\Shell\0 -Name "Icon" -EA 0 ).Icon -ne "imageres.dll,73") {
New-ItemProperty -Path HKCR:\Microsoft.PowerShellScript.1\Shell\0 -Name "Icon" -Value "imageres.dll,73" -Force
Set-ItemProperty -Path HKCR:\Microsoft.PowerShellScript.1\Shell\0\Command -Name "(Default)" -Value "`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoProfile -NoExit -Command if(( Get-ExecutionPolicy ) -ne `'Bypass`' ) { Set-ExecutionPolicy -Scope Process Bypass -Force } ; & '%1'" -Force
}
#endregion

#region Script Browser Begin
if ( $Host.Name -eq "Windows PowerShell ISE Host" ) {
    if ( Test-Path "C:\Program Files (x86)\Microsoft Corporation\Microsoft Script Browser\ScriptBrowser.dll" ) {
    Add-Type -Path "C:\Program Files (x86)\Microsoft Corporation\Microsoft Script Browser\System.Windows.Interactivity.dll"
    Add-Type -Path "C:\Program Files (x86)\Microsoft Corporation\Microsoft Script Browser\ScriptBrowser.dll"
    Add-Type -Path "C:\Program Files (x86)\Microsoft Corporation\Microsoft Script Browser\BestPractices.dll"
    if ( $psISE.CurrentPowerShellTab.VerticalAddOnTools.Name -notcontains "Script Browser" ) {
        $scriptBrowser = $psISE.CurrentPowerShellTab.VerticalAddOnTools.Add( "Script Browser", [ScriptExplorer.Views.MainView], $false ) }
    if ( $psISE.CurrentPowerShellTab.VerticalAddOnTools.Name -notcontains "Script Analyzer" ) {
        $scriptAnalyzer = $psISE.CurrentPowerShellTab.VerticalAddOnTools.Add( "Script Analyzer", [BestPractices.Views.BestPracticesView], $false ) }
    #$psISE.CurrentPowerShellTab.VisibleVerticalAddOnTools.SelectedAddOnTool = $scriptBrowser
}

}
#endregion Script Browser End
 
#region Powershell 3 and above specific Default Parameter Values
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
Set-Alias -Name "im" -Value "Import-Module"
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

if ( !( Get-Command Resolve-DnsName -EA 0 ) ) { Set-Alias -Name "nslookup" -Value "Prevent-CMDCommands" } else { Set-Alias -Name "nslookup" -Value "Resolve-DnsName"  }

Set-Alias -Name "ping" -Value "Prevent-CMDCommands"
Set-Alias -Name "hostname" -Value "Prevent-CMDCommands"
#endregion

#region Custom Functions
function Add-AliasToCMD-LS { "dir %1" | Out-File -FilePath "$env:SystemRoot\system32\ls.bat" -Encoding default -Force }

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

function Get-PersonalFolderPath { param( [switch]$AdminTools,[switch]$ApplicationData,[switch]$CDBurning,[switch]$CommonAdminTools,[switch]$CommonApplicationData,[switch]$CommonDesktopDirectory,[switch]$CommonDocuments,[switch]$CommonMusic,[switch]$CommonOemLinks,[switch]$CommonPictures,[switch]$CommonProgramFiles,[switch]$CommonProgramFilesX86,[switch]$CommonPrograms,[switch]$CommonStartMenu,[switch]$CommonStartup,[switch]$CommonTemplates,[switch]$CommonVideos,[switch]$Cookies,[switch]$Desktop,[switch]$DesktopDirectory,[switch]$Favorites,[switch]$Fonts,[switch]$History,[switch]$InternetCache,[switch]$LocalApplicationData,[switch]$LocalizedResources,[switch]$MyComputer,[switch]$MyDocuments,[switch]$MyMusic,[switch]$MyPictures,[switch]$MyVideos,[switch]$NetworkShortcuts,[switch]$Personal,[switch]$PrinterShortcuts,[switch]$ProgramFiles,[switch]$ProgramFilesX86,[switch]$Programs,[switch]$Recent,[switch]$Resources,[switch]$SendTo,[switch]$StartMenu,[switch]$Startup,[switch]$System,[switch]$SystemX86,[switch]$Templates,[switch]$UserProfile,[switch]$Windows )
[array]$params = $PsBoundParameters | % { $_.keys }
$currentEAP = $ErrorActionPreference
$ErrorActionPreference = "silentlycontinue"
$params | % { [environment]::GetFolderPath("$_") }
$ErrorActionPreference = $currentEAP
}

function Get-IPConfig { param( [Switch]$ip, [Switch]$MAC, [Switch]$all )
Process {
    If ( $MAC ) { IPConfig.exe -all | Select-String "IPv4","Physical" }
    ElseIf ( $ip ) { IPConfig.exe -all | Select-String "IPv4" } 
    ElseIf ( $all ) { IPConfig.exe -all }
    Else { IPConfig }
    }
End { "`r`n" }
}

function Get-MemberDefinition { param(
	[Parameter(position=0,Mandatory=$true,ValueFromPipeline=$true)][Alias("Object")]$InputObject,
    [Parameter(position=1)]$Name )
process { if ( $Name ) { ( $input | Get-Member $Name ).Definition.Replace("), ", ")`n" ) } else { ( $input | Get-Member | Out-Default ) } }
}

function Get-PersonalFiles { param( [Parameter(position=0,ValueFromPipeline=$true)]$servers )
if ( !$servers ) {
$LDAPFilter = "(&(OperatingSystem=*Server*)(!(CanonicalName=*Infoscreenserver*)))"

if ( ( Get-Command Get-QADComputer -EA 0) -eq $true ) {
    [array]$adComputers = ( Get-QADComputer -LDAPFilter $LDAPFilter -SecurityMask "None" -DontUseDefaultIncludedProperties -IncludedProperties Name,OperatingSystem | ? { $_.OperatingSystem -match "Server" } ).Name
}
if ( !$adComputers ) { Import-Module activedirectory ; [array]$adComputers = (( Get-ADComputer -Filter * -Properties Name,OperatingSystem | ? { $_.OperatingSystem -match "Server" } ).Name) }
[array]$servers = $adComputers
}

$servers | % {
$ComputerName = $_
Write-host $ComputerName

if ( Test-Path "\\$ComputerName\c$\Users\$env:USERNAME" ) {
    Get-ChildItem "\\$ComputerName\c$\Users\$env:USERNAME\Desktop\" -Exclude "WindowsPowershell","Visual Studio*"| Select -ExpandProperty Name
    Get-ChildItem "\\$ComputerName\c$\Users\$env:USERNAME\Documents\" -Exclude "WindowsPowershell","Visual Studio*"| Select -ExpandProperty Name
    Get-ChildItem "\\$ComputerName\c$\Users\$env:USERNAME\Downloads\" -Exclude "WindowsPowershell","Visual Studio*"| Select -ExpandProperty Name
} else { if ( Test-Path "\\$ComputerName\c$\Documents and Settings\$env:USERNAME\" ) {
    Get-ChildItem "\\$ComputerName\c$\Documents and Settings\$env:USERNAME\Desktop\" -Exclude "WindowsPowershell","Visual Studio*"| Select -ExpandProperty Name
    Get-ChildItem "\\$ComputerName\c$\Documents and Settings\$env:USERNAME\My Documents\" -Exclude "WindowsPowershell","Visual Studio*"| Select -ExpandProperty Name
    }
}
}
}

function Get-QCommand {
	if ($args[0] -eq $null)	{ Get-Command -PSSnapin Quest.ActiveRoles*
    } else { Get-Command $args[0] | Where-Object { $_.PSSnapIn -like 'Quest.ActiveRoles*' } }
}

function Get-RegistryChildItem { param( [Parameter(position=0,Mandatory=$true,ValueFromPipeline=$true)]$arg )
$hive = ((( $arg -replace "\[" ) -replace "\]" ) -replace ":" -split "\\" )[0]
$partialpath = ((( $arg -replace "\[" ) -replace "\]" ) -split("\\",2 ))[-1]
switch ( $hive ) {
	"HKEY_CURRENT_USER" { $hive = "HKCU" }
	"HKEY_LOCAL_MACHINE" { $hive = "HKLM" }
	"HKEY_USERS" { $hive = "HKU" }
	"HKEY_CURRENT_CONFIG" { $hive = "HKCC" }
	"HKEY_CLASSES_ROOT" { $hive = "HKCR" }
}
Get-Item ( $hive + ":\" + $partialpath )
Get-ChildItem -Path ( $hive + ":\" + $partialpath ) -Recurse | % { Get-Item (( $hive + ":\" + $partialpath ) + "\\" + (( $_.Name -split "\\" )[-1]))  }
}

function Get-RegistryItemProperty { param( [Parameter(position=0,Mandatory=$true,ValueFromPipeline=$true)]$arg )
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
Get-ItemProperty -Path ( $hive + ":\" + $partialpath ) -Name $itemName | Select-Object -ExpandProperty $itemName
}

if ( $PSVersionTable.PSVersion.Major -ge 5 ) { function Find-PackageGUI { Find-Package | Out-Gridview -PassThru | Install-Package -Verbose } } #For the upcoming WMF 5.0 OneGet feature, hell yee!

function Get-Shortcut {	param( $path = $null )
	$obj = New-Object -ComObject WScript.Shell
	if ($path -eq $null) {
		$pathUser = [Environment]::GetFolderPath('StartMenu')
		$pathCommon = [Environment]::GetFolderPath('CommonStartMenu')

		$path = Get-ChildItem $pathUser, $pathCommon -Filter *.lnk -Recurse
	}
	$path | % { 
		$link = $obj.CreateShortcut($_.FullName)

		$info = @{}
		$info.Hotkey = $link.Hotkey
		$info.TargetPath = $link.TargetPath
		$info.LinkPath = $link.FullName
		$info.Arguments = $link.Arguments
		$info.Target = try { Split-Path $info.TargetPath -Leaf } catch { 'n/a'}
		$info.Link = try { Split-Path $info.LinkPath -Leaf } catch { 'n/a'}
		$info.WindowStyle = $link.WindowStyle
		$info.IconLocation = $link.IconLocation

		New-Object PSObject -Property $info
	}
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

function New-UniverseMode { New-Item -ItemType Directory -Path ([Environment]::GetFolderPath("Desktop") + "\" + "Universe Mode.{ED7BA470-8E54-465E-825C-99712043E01C}") | Out-Null }

function Prevent-CMDCommands {
	$cmdError = "Using old CMD/DOS commands is no longer tolerated because Powershell it's not a shell of you grandpa!"
	switch ( $^ ) {
	"cd" { Write-Host "Use Set-Location instead!" }
	"hostname" { Write-Host 'Use $env:COMPUTERNAME instead!' }
    "nslookup" { Write-Host "Use Resolve-DnsName instead!" }
	"ping" { Write-Host "Use Test-Connection instead!" }
	}
	Write-Error $cmdError
}

function Show-Colors { [enum]::GetValues( [ConsoleColor] ) | % { Write-Host $_ -ForegroundColor $_ } }

function Select-FirstObject { $input | Select-Object -First 1 }
function Select-LastObject { $input | Select-Object -Last 1 }

function Self-Elevating { param( $args )
Set-Location ( Get-Item $MyInvocation.MyCommand.Path ).Directory

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal( $myWindowsID )
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

if ( !$myWindowsPrincipal.IsInRole( $adminRole )) {

[string[]]$argList = @( '-NoProfile', '-NoExit', '-File', """$( $MyInvocation.MyCommand.Path )""" )
$argList += $MyInvocation.BoundParameters.GetEnumerator() | % { "-$( $_.Key )", "$( $_.Value )" }
$argList += $MyInvocation.UnboundArguments

Start-Process PowerShell.exe -Verb Runas -WorkingDirectory $pwd -ArgumentList $argList

exit
}
}

function Set-PinnedApplication {
<#  
.SYNOPSIS  
This function are used to pin and unpin programs from the taskbar and Start-menu in Windows 7 and Windows Server 2008 R2 
.DESCRIPTION  
The function have to parameteres which are mandatory: 
Action: PinToTaskbar, PinToStartMenu, UnPinFromTaskbar, UnPinFromStartMenu 
FilePath: The path to the program to perform the action on 
.EXAMPLE 
Set-PinnedApplication -Action PinToTaskbar -FilePath "C:\WINDOWS\system32\notepad.exe" 
.EXAMPLE 
Set-PinnedApplication -Action UnPinFromTaskbar -FilePath "C:\WINDOWS\system32\notepad.exe" 
.EXAMPLE 
Set-PinnedApplication -Action PinToStartMenu -FilePath "C:\WINDOWS\system32\notepad.exe" 
.EXAMPLE 
Set-PinnedApplication -Action UnPinFromStartMenu -FilePath "C:\WINDOWS\system32\notepad.exe" 
#>
       [CmdletBinding()] 
       param( 
      [Parameter(Mandatory=$true)][ValidateSet("PintoStartMenu","UnpinfromStartMenu","PintoTaskbar","UnpinfromTaskbar")][string]$Action, 
      [Parameter(Mandatory=$true,ValueFromPipeline=$True)][string]$FilePath 
       ) 
       if(-not (test-path $FilePath)) {  
           "FilePath does not exist."
           return  
    } 
    
    function InvokeVerb { 
           param([string]$FilePath,$verb) 
        $verb = $verb.Replace("&","") 
        $path= split-path $FilePath 
        $shell=new-object -com "Shell.Application"  
        $folder=$shell.Namespace($path)    
        $item = $folder.Parsename((split-path $FilePath -leaf)) 
        $itemVerb = $item.Verbs() | ? {$_.Name.Replace("&","") -eq $verb} 
        if($itemVerb -ne $null){
			$itemVerb.DoIt() 
        } else { 
			Write-Verbose "Verb $verb not found."
        } 
            
		} 
    function GetVerb { 
        param([int]$verbId) 
        try { 
            $t = [type]"CosmosKey.Util.MuiHelper" 
        } catch { 
            $def = [Text.StringBuilder]"" 
            [void]$def.AppendLine('[DllImport("user32.dll")]') 
            [void]$def.AppendLine('public static extern int LoadString(IntPtr h,uint id, System.Text.StringBuilder sb,int maxBuffer);') 
            [void]$def.AppendLine('[DllImport("kernel32.dll")]') 
            [void]$def.AppendLine('public static extern IntPtr LoadLibrary(string s);') 
            add-type -MemberDefinition $def.ToString() -name MuiHelper -namespace CosmosKey.Util             
        } 
        if($global:CosmosKey_Utils_MuiHelper_Shell32 -eq $null){         
            $global:CosmosKey_Utils_MuiHelper_Shell32 = [CosmosKey.Util.MuiHelper]::LoadLibrary("shell32.dll") 
        } 
        $maxVerbLength=255 
        $verbBuilder = new-object Text.StringBuilder "",$maxVerbLength 
        [void][CosmosKey.Util.MuiHelper]::LoadString($CosmosKey_Utils_MuiHelper_Shell32,$verbId,$verbBuilder,$maxVerbLength) 
        return $verbBuilder.ToString() 
    } 
 
    $verbs = @{  
        "PintoStartMenu"=5381 
        "UnpinfromStartMenu"=5382 
        "PintoTaskbar"=5386 
        "UnpinfromTaskbar"=5387 
    } 
        
    if($verbs.$Action -eq $null){ 
           Throw "Action $action not supported`nSupported actions are:`n`tPintoStartMenu`n`tUnpinfromStartMenu`n`tPintoTaskbar`n`tUnpinfromTaskbar" 
    } 
    InvokeVerb -FilePath $FilePath -Verb $(GetVerb -VerbId $verbs.$action) 
} 

function Set-Workplace {

$myPinnedApplications = "C:\Windows\system32\dsa.msc", "C:\Windows\system32\compmgmt.msc", "C:\Windows\system32\dhcpmgmt.msc", "C:\Windows\system32\dnsmgmt.msc", "C:\Windows\system32\gpmc.msc"

$myPinnedApplications | % { Set-PinnedApplication -Action PintoTaskbar $_ }

}

function Search-File { param(
    [Parameter(Position=0,Mandatory=$true)][string]$SearchString,
    [Parameter(Position=1,Mandatory=$true, ValueFromPipeline = $true)][string]$path = ( Get-Location ).Path
    )
    # if (Get-acl "C:\Users\ALIEN\AppData\Local\Application Data").Access | ? { $_.AccessControlType -eq "Deny" } then exclude folder
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

function shell: { param( [Parameter(Position=1)]$Name,[switch]$ListAvailable)
if ( $ListAvailable -or !$Name ) { ( Get-ItemProperty -LiteralPath (( Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\FolderDescriptions ).PSPath )).Name | Sort-Object }
if ( $Name ) { explorer.exe "shell:$Name" }
}

function Enter-Scope { $host.EnterNestedPrompt() }

function Test-xConnection { param(
[Parameter(Position=1,ValueFromPipeline=$true)]$ComputerName,
[int]$Count=1,
[switch]$t,
[switch]$Detailed
)
if ( $t ) { $Count=999999999 }
$destination = ( Get-WmiObject Win32_PingStatus -Filter "Address=`"$ComputerName`" AND ResolveAddressNames=$true" ).ProtocolAddressResolved

if ( $Detailed ) {
Test-Connection -ComputerName $ComputerName -Count $Count | Select-Object @{ Name = "Source";Expression = { $_.PSComputerName } },@{ Name = "Destination";Expression = { $destination } },IPV4Address,IPV6Address,@{ Name = "Bytes";Expression = { $_.BufferSize } },@{ Name = "Time(ms)";Expression = { $_.ResponseTime } }
} else {
Test-Connection -ComputerName $ComputerName -Count $Count | Select-Object @{ Name = "Destination";Expression = { $destination } },IPV4Address,@{ Name = "Bytes";Expression = { $_.BufferSize } },@{ Name = "Time(ms)";Expression = { $_.ResponseTime } }
}
}

function Test-FileLock {
    ## Attempts to open a file and trap the resulting error if the file is already open/locked
    param ([string]$filePath )
    $filelocked = $false
    $fileInfo = New-Object System.IO.FileInfo $filePath
    trap {
        Set-Variable -name Filelocked -value $true -scope 1
        continue
    }
    $fileStream = $fileInfo.Open( [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None )
    if ($fileStream) {
        $fileStream.Close()
    }
    $filelocked
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

function Deploy-Profile {
$LDAPFilter = "(&(OperatingSystem=*Server*)(!(Name=$env:COMPUTERNAME)))"
if ( Get-Command Get-QADComputer -EA 0 ) {
    [array]$adComputers = ( Get-QADComputer -LDAPFilter $LDAPFilter -SecurityMask "None" -DontUseDefaultIncludedProperties -IncludedProperties Name,OperatingSystem | ? { $_.OperatingSystem -match "Server 2008" -and $_.Name -ne $env:COMPUTERNAME } ).Name
}
if ( !$adComputers ) { Import-Module activedirectory ; [array]$adComputers = ( Get-ADComputer -Filter * -Properties Name,OperatingSystem | ? { $_.OperatingSystem -match "Server 2008" -and $_.Name -ne $env:COMPUTERNAME } ).Name }
if ( $adComputers.Count -ge 1 ) {

    $adComputers | % {
    $ComputerName = $_
    if ( Test-Connection -ComputerName $ComputerName -Count 1 -Quiet ) {
        if ( Test-Path "\\$ComputerName\c$\Users" ) {
        if ( Test-Path "\\$ComputerName\c$\Users\$env:USERNAME\Documents" ) {
            if ( !( Test-Path "\\$ComputerName\c$\Users\$env:USERNAME\Documents\WindowsPowershell" -EA 0 ) ) {
            New-Item -Path "\\$ComputerName\c$\Users\$env:USERNAME\Documents\WindowsPowershell" -ItemType Directory | Out-Null }
        Write-host $ComputerName
        Copy-Item ( Resolve-Path $profile ) -Destination "\\$ComputerName\c$\Users\$env:USERNAME\Documents\WindowsPowershell" -Force | Out-Null
        } else {
        New-Item -Path "\\$ComputerName\c$\Users\$env:USERNAME" -ItemType Directory | Out-Null
        New-Item -Path "\\$ComputerName\c$\Users\$env:USERNAME\Documents" -ItemType Directory | Out-Null
        New-Item -Path "\\$ComputerName\c$\Users\$env:USERNAME\Documents\WindowsPowershell" -ItemType Directory | Out-Null
        Copy-Item ( Resolve-Path $profile ) -Destination "\\$ComputerName\c$\Users\$env:USERNAME\Documents\WindowsPowershell" -Force | Out-Null
        }
        } else { "2003" }
        }
    }
}
}

function Reload-Profile { $Profile | % { . $_ } }

function Update-Profile {

$psProfileFileName = "Microsoft.PowerShell_profile.ps1"
$psISEProfileFileName = "Microsoft.PowerShellISE_profile.ps1"

$urlPSProfile = "https://raw.githubusercontent.com/ALIENQuake/WindowsPowerShell/master/$psProfileFileName"

$psPersonalPatch = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\"

$fullPathPSProfile = $psPersonalPatch + $psProfileFileName

#Get-WebFile $urlPSProfile $fullPathPSProfile
Invoke-WebRequest $urlPSProfile -OutFile $fullPathPSProfile

Copy-Item -Path $fullPathPSProfile -Destination ( $psPersonalPatch + "\" + $psISEProfileFileName ) -Force | Out-Null

Reload-Profile
}

#endregion

#region Info
if ( $host.name -eq "PowerGUIScriptEditorHost" ) {
return
}

$color_decoration = [ConsoleColor]::DarkGreen
$color_Host = [ConsoleColor]::Green
$color_Location = [ConsoleColor]::Cyan

if ( $host.Name -eq "ConsoleHost" ) {

$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Set-ConsoleWindowSize -x 120 -y 35
Set-ConsoleFont 6 }

if ( $host.name -eq "Windows PowerShell ISE Host" ) {

}
if ( $host.name -notmatch "Windows PowerShell ISE Host" ) { }

#add global variable if it doesn't already exist
if ( !($global:LastCheck) ) {
	$global:LastCheck = Get-Date
    $global:cdrive = Get-WMIObject -Query "Select Freespace,Size from win32_logicaldisk where deviceid = 'c:'"
}

#only refresh disk information once every 15 minutes
$min = ( New-TimeSpan $Global:lastCheck ).TotalMinutes
if ( $min -ge 15 ) {
    $global:cdrive = Get-WMIObject -Query "Select Freespace,Size from win32_logicaldisk where deviceid = 'c:'"
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
if ( (Get-Job -State Running).Count -ne 0) { $jobsCount = ( Get-Job -State Running ).Count }

#Set the PowerShell session time, computername and current location in the title bar.

#Get start time for the current PowerShell session, $pid is a special variable for the current PowerShell process ID.
[datetime]$psStart = ( Get-Process -id $pid ).StartTime
    
#Strip off the millisecond part with Substring(). The millisecond part will come after the last period.
$s = (( Get-Date ) - $psStart).ToString()
$elapsed = $s.Substring( 0,$s.LastIndexOf( "." )) 
        if ( $env:COMPUTERNAME -ne $env:USERDOMAIN ) {
$title = "{0}{1}{2}{3}{4}{5}{6}{7}{8}" -f ( Shorten-Path ( Get-Location ).Path )," | ",$env:USERDNSDOMAIN,"\",$env:USERNAME,"@",$env:computername," | ",$elapsed
    } else {
        $title = "{0}{1}{2}{3}{4}{5}{6}" -f ( Shorten-Path ( Get-Location ).Path )," | ",$env:USERDOMAIN,"@",$env:computername," | ",$elapsed
    }
$host.ui.rawui.WindowTitle = $title

Write-Host "$( ( Get-History -count 1 ).id + 1 ) " -NoNewline -ForegroundColor Yellow
    if ( $env:COMPUTERNAME -ne $env:USERDOMAIN ) {
        Write-Host $env:USERDNSDOMAIN -NoNewline -ForegroundColor DarkCyan
        Write-Host "\" -NoNewline
    }
Write-Host "[" -NoNewline
Write-Host $env:COMPUTERNAME -NoNewline -ForegroundColor Red
Write-Host "]" -NoNewline
Write-Host $env:USERNAME -NoNewline -ForegroundColor $color_Host
Write-Host " "-n -f $color_decoration
Write-Host ( Shorten-Path ( Get-Location ).Path ) -NoNewline -ForegroundColor $color_Location
    
if ( Get-Command Write-VcsStatus -EA 0 ) { Write-VcsStatus }
	
if ( $NestedPromptLevel -gt 0 ) {
$myPrompt = ( " " + "+" * $NestedPromptLevel + ">$jobsCount" )
$myPrompt
} else { Write-Host " >" -NoNewline ; Write-Host "$jobsCount" -ForegroundColor Red -NoNewline }
$global:LASTEXITCODE = $realLASTEXITCODE
return " "
}
#endregion

Write-Host "Welcome Bartosz, together we will rule the galaxy with an iron fist and Powershell - it's not a shell of you grandpa!"
Write-Host $systemInfo -ForegroundColor Green
Write-Host ""
Set-Location $HOME