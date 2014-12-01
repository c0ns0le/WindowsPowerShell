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

Write-Host ((Get-Date -Format s) -replace "T"," ") -ForegroundColor Cyan

function prompt {

     
    # Set Window Title
    $host.UI.RawUI.WindowTitle = "$ENV:USERNAME@$ENV:COMPUTERNAME - $(Get-Location)"
     
    # Set Prompt
    
    Write-Host "$ENV:USERNAME" -NoNewline -ForegroundColor Yellow
    Write-Host "@" -NoNewline -ForegroundColor White
    Write-Host "$ENV:COMPUTERNAME" -NoNewline -ForegroundColor Yellow
    Write-Host " " -NoNewline -ForegroundColor DarkGray
    Write-Host $(get-location) -ForegroundColor Green
 
    # Check Running Jobs
    $jobsCount = (Get-Job -State Running).Count
     
    # Check for Administrator elevation
	$isAdmin = (New-Object System.Security.principal.windowsprincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).isInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  
    if ($IsAdmin) {
        if ( $jobsCount -eq 0 ) {
            Write-Host "#" -NoNewline -ForegroundColor Red
            return " "
        } else {


            Write-Host "jobs:" $jobsCount -NoNewline -ForegroundColor Gray
            Write-Host "#" -NoNewline -ForegroundColor Red
            return " "
        }       
    } else {               


        if ( $jobsCount -eq 0 ) {
            Write-Host ">" -NoNewline -ForegroundColor White
            return " "
        } else {


            Write-Host "jobs:" $jobsCount  -NoNewline -ForegroundColor Gray
            Write-Host ">" -NoNewline -ForegroundColor White
            return " "
        }       
    }
 }