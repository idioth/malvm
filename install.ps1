Import-Module $PSScriptRoot\winconfig.psm1
Import-Module $PSScriptRoot\download.psm1

# check run as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "Please run as administrator"
    Read-Host "Press any key..."
    exit
}

# install chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# remove unnecessary windows apps
remove_apps

# disable windows updates
disable_update

# disable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# disable windows defender
disable_defender

# disable security maintenance icon
# refer: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.TaskBar2::HideSCAHealth
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAHealth" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null

# set timezone KST
# refer: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-timezone?view=powershell-7.1
Set-TimeZone -Id "Korea Standard Time"

# show hidden files
# refer: https://www.python2.net/questions-1237399.htm
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null

# remove startup program
disable_startup

# remove scheduled task
remove_task