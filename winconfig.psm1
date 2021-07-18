# Remove apps
# https://community.spiceworks.com/topic/2230169-powershell-script-to-remove-xbox-gamebar-from-the-app-list
function remove_apps
{
    $packages = @(
        "7EE7776C.LinkedInforWindows"
        "C27EB4BA.DropboxOEM"
        "Microsoft.3DBuilder"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.Advertising.Xaml"
        "Microsoft.Appconnector"
        "Microsoft.BingFinance"
        "Microsoft.BingFoodAndDrink"
        "Microsoft.BingHealthAndFitness"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTravel"
        "Microsoft.BingWeather"
        "Microsoft.CommsPhone"
        "Microsoft.ConnectivityStore"
        "Microsoft.DesktopAppInstaller"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MixedReality.Portal"
        "Microsoft.Netflix"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.Office.Desktop"
        "Microsoft.Office.OneNote"
        "Microsoft.Office.Sway"
        "Microsoft.OfficeLens"
        "Microsoft.OneConnect"
        "Microsoft.OneDrive"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.RemoteDesktop"
        "Microsoft.SkypeApp"
        "Microsoft.Wallet"
        "Microsoft.Windows.CloudExperienceHost"
        "Microsoft.Windows.NarratorQuickStart"
        "Microsoft.Windows.PeopleExperienceHost"
        "Microsoft.Windows.Photos"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera"
        "Microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsPhone"
        "Microsoft.WindowsReadingList"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameCallableUI"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxLive"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.YourPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "Windows.CBSPreview"
    )

    foreach($package in $packages)
    {
        Get-AppxPackage $package | Remove-AppxPackage
    }

    # remove onedrive
    taskkill.exe /f /im "OneDrive.exe"

    if((Get-WmiObject Win32_OperatingSystem | Select osarchitecture).osarchitecture -like "64*")
    {
        & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
    }
    else
    {
        & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
    }
}

# Disable Windows Defender
# https://github.com/fireeye/flare-vm/blob/master/install.ps1
function disable_defender
{
    try
    {
        Get-Service WinDefend | Stop-Service -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "Start" -Value 4 -Type DWORD -Force -ea 0 | Out-Null
    }
    catch
    {
        Write-Error "Failed disable WinDefend Service"
    }

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Windows Defender" -Force -ea 0 | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Spynet" -Force -ea 0 | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -PropertyType DWORD -Force -ea 0 | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0 -PropertyType DWORD -Force -ea 0 | Out-Null

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "MRT" -Force -ea 0 | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null

    if(-Not ((Get-WmiObject -Class Win32_OperatingSystem).Version -eq "6.1.7601"))
    {
        Add-MpPreference -ExclusionPath "C:\" -Force -ea 0 | Out-Null
        Set-MpPreference -DisableArchiveScanning $true  -ea 0 | Out-Null
        Set-MpPreference -DisableBehaviorMonitoring $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableBlockAtFirstSeen $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableCatchupFullScan $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableCatchupQuickScan $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableIntrusionPreventionSystem $true  -Force -ea 0 | Out-Null
        Set-MpPreference -DisableIOAVProtection $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableRealtimeMonitoring $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableRemovableDriveScanning $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableRestorePoint $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableScanningNetworkFiles $true -Force -ea 0 | Out-Null
        Set-MpPreference -DisableScriptScanning $true -Force -ea 0 | Out-Null
        Set-MpPreference -EnableControlledFolderAccess Disabled -Force -ea 0 | Out-Null
        Set-MpPreference -EnableNetworkProtection AuditMode -Force -ea 0 | Out-Null
        Set-MpPreference -MAPSReporting Disabled -Force -ea 0 | Out-Null
        Set-MpPreference -SubmitSamplesConsent NeverSend -Force -ea 0 | Out-Null
        Set-MpPreference -PUAProtection Disabled -Force -ea 0 | Out-Null    
    }

}

# Disable Windows Update
# https://social.technet.microsoft.com/Forums/lync/en-US/abde2699-0d5a-49ad-bfda-e87d903dd865/disable-windows-update-via-powershell?forum=winserverpowershell
function disable_update
{
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -ea 0 | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -ea 0 | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -PropertyType DWORD -Force -ea 0 | Out-Null
}

<#
get specific sid: https://techexpert.tips/powershell/powershell-get-user-sid/
remove all registry key under specific key
https://docs.microsoft.com/ko-kr/powershell/scripting/samples/working-with-registry-keys?view=powershell-7.1#removing-all-keys-under-a-specific-key
#>
function disable_startup
{
    $user = New-Object System.Security.Principal.NTAccount($env:username)
    $sid = ($user.Translate([System.Security.Principal.SecurityIdentifier])).Value

    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*" -Recurse
    Remove-Item -Path "Registry::HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*" -Recurse
    Remove-Item -Path "Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*" -Recurse
    Remove-Item -Path "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*" -Recurse
}

# https://community.spiceworks.com/how_to/159324-delete-scheduled-task-with-powershell
function remove_task
{
    $ts = New-Object -ComObject Schedule.Service
    $ts.Connect($env:computername)
    $taskfolder = $ts.GetFolder('\')
    $tasks = $taskfolder.GetTasks(1)

    foreach($task in $tasks)
    {
        $taskfolder.DeleteTask($task.Name, 0)
t}

}