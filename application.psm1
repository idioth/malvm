function download_apps
{
    # tools list
    $packages = @(
        "hxd"
        "7zip"
        "ghidra"
        "vscode"
        "procmon"
        "procexp"
        "processhacker"
        "python"
        "die"
        "pestudio"
        "googlechrome"
        "autoruns"
        "wireshark"
        "hashmyfiles"
        "strings"
        "ida-free"
    )

    foreach ($package in $packages)
    {
        choco install $package -y
    }
}

<# refer: https://serverfault.com/questions/1018220/how-do-i-install-an-app-from-windows-store-using-powershell
function download_windbg_preview
{
    $web_response = Invoke-WebRequest -Method 'POST' -Uri 'https://store.rg-adguard.net/api/GetFiles' -Body "type=url&url=https://www.microsoft.com/en-us/windbg-preview/9pgjgd53tn86&ring=Retail&lang=ko-KR" -ContentType 'application/x-www-form-urlencoded'
    $links_match = $web_response.Links | where {$_ -like '*_1.2104.13002.0_neutral__8wekyb3d8bbwe.appx*'} | Select-String -Pattern '(?<=a href=").+(?=" r)'
    $download_link = $links_match.matches.value

    Invoke-WebRequest -Uri $download_link -OutFile "C:\tools\windbg\windbg-preview.appx"
}
#>

# refer: https://dotnet-helpers.com/powershell/create-shortcuts-on-desktops-using-powershell/
function create_desktop_shortcut
{
    param (
        [string]$src,
        [string]$filename
    )
    
    $dst = Join-Path $env:userprofile "Desktop\$filename.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($dst)
    $shortcut.TargetPath = $src
    $shortcut.Save()
}

# refer: https://stackoverflow.com/questions/31720595/pin-program-to-taskbar-using-ps-in-windows-10
function pin_taskbar
{
    param (
        [string]$src
    )

    $value_data = (Get-ItemProperty("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\" +
    "Explorer\CommandStore\shell\Windows.taskbarpin")).ExplorerCommandHandler

    $classes_key = (Get-Item "HKCU:\SOFTWARE\Classes").OpenSubKey("*", $true)
    $shell_key = $classes_key.CreateSubKey("shell", $true)
    $verb_key = $shell_key.CreateSubKey("taskbarpin", $true)
    $verb_key.SetValue("ExplorerCommandHandler", $value_data)

    $shell = New-Object -ComObject "Shell.Application"
    $pin = $shell.NameSpace((Get-Item $src).DirectoryName).ParseName((Get-Item $src).Name)
    $pin.InvokeVerb("taskbarpin")

    $shell_key.DeleteSubKey("taskbarpin")
    if($shell_key.SubKeyCount -eq 0 -and $shell_key.ValueCount -eq 0)
    {
        $classes_key.DeleteSubKey("shell")
    }
}