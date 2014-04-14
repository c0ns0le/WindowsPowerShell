Add-PSSnapin Quest.ActiveRoles.ADManagement -ErrorAction SilentlyContinue
#Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Check for Administrator elevation
$isAdmin = (New-Object System.Security.principal.windowsprincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).isInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
 
if ( Test-Path "$env:LOCALAPPDATA\GitHub\shell.ps1x" ) { . ( Resolve-Path "$env:LOCALAPPDATA\GitHub\shell.ps1" ) }

if ($PSVersionTable.PSVersion.Major -ge 3 ) {
 #Write-Host "You are running PowerShell $($PSVersionTable.PSVersion.Major)" -ForegroundColor Green
 #insert 3.0 specific commands
 $PSDefaultParameterValues.Add("Format-Table:Autosize",$True)
}


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
Set-Alias -Name "tp" -Value "Test-Path"
#endregion

#region Update
function Get-WebFile { param( $url,$file )

$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

$request = New-Object System.Net.WebCLient
$request.UseDefaultCredentials = $true
$request.Proxy.Credentials = $request.Credentials
$request.DownloadFile( $url, $file )

}
 
function Update-Profile {

$psProfileFileName = "Microsoft.PowerShell_profile.ps1"
$psISEProfileFileName = "Microsoft.PowerShellISE_profile.ps1"

$urlPSProfile = "https://raw.githubusercontent.com/ALIENQuake/WindowsPowerShell/master/$psProfileFileName"

$psPersonalPatch = ($env:PSModulePath -split ";" -replace "\\Modules")[0]

$fullPathPSProfile = $psPersonalPatch + "\" + $psProfileFileName

Get-WebFile $urlPSProfile $fullPathPSProfile

Copy-Item -Path $fullPathPSProfile -Destination ($psPersonalPatch + "\" + $psISEProfileFileName) -Force

Reload-Profile
}
#endregion

#region File Search
[reflection.assembly]::loadwithpartialname("Microsoft.VisualBasic") | Out-Null
Function Search { param (
    [Parameter(Position=0,Mandatory=$true)][string]$SearchString,
    [Parameter(Position=1,Mandatory=$true, ValueFromPipeline = $true)][string]$Path
    )
    try {
    # Any exeption will break whole procedure!
    # .NET FindInFiles Method to Look for file
    # BENEFITS : Possibly running as background job (haven't looked into it yet)
    [Microsoft.VisualBasic.FileIO.FileSystem]::GetFiles( $Path,[Microsoft.VisualBasic.FileIO.SearchOption]::SearchAllSubDirectories,$SearchString )
    } catch { $_ }
}
#endregion

function Get-MemberDefinition {param(
    [Parameter(position=0,Mandatory=$true,ValueFromPipeline=$true)][Alias('Object')]$input,
    [Parameter(position=1)]$Name
    )
    process {
    if ( $Name ) {
    ( $input | Get-Member $Name).Definition.Replace("), ", ")`n") } else { ( $input | Get-Member | Out-Default ) }
    }
}

function Reload-Profile {
    @(
        $Profile.AllUsersAllHosts,
        $Profile.AllUsersCurrentHost,
        $Profile.CurrentUserAllHosts,
        $Profile.CurrentUserCurrentHost
    ) | % {
        if(Test-Path $_){
            Write-Verbose "Running $_"
            . $_
        }
    }    
}

function als { param ($arg)
gci $arg | ? { $_.PSIsContainer } | % { $d1 += $_.Fullname + ";" }
$d1.trim(";")
}

$color_decoration = [ConsoleColor]::DarkGreen
$color_Host = [ConsoleColor]::Green
$color_Location = [ConsoleColor]::Cyan
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

if ( !( Test-Path variable:global:userProfile )) {
	$userProfile = $env:USERPROFILE
    Set-Variable -name HOME -value ( (Get-PSProvider FileSystem).Home ) -force
}

function Shorten-Path { param( [string]$path )
   $location = $path.Replace( $USERPROFILE, '~' ) 
   # remove prefix for UNC paths 
   $location = $location -replace '^[^:]+::', '' 
   # make path shorter like tabs in Vim,
   # handle paths starting with \\ and . correctly
   # return ( $location -replace '\\( \.? )( [^\\] )[^\\]*( ?=\\ )','\$1$2' )

   # return standard location 
   return $location
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

function prompt {
	# Make sure that Windows and .Net know where we are at all times
	[Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath

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
    if ( $NestedPromptLevel -gt 0 ) {
    $myPrompt = ( " " + "+" * $NestedPromptLevel + ">" )
    $myPrompt
    } else { Write-Host " >" -n }
    return " "
}

Write-Host "Welcome Bartosz, together we will rule the galaxy with an iron fist and Powershell!"
Write-Host ""
Write-Host $systemInfo -ForegroundColor Green
Write-Host ""