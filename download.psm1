function download_apps()
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
    )

    foreach ($package in $packages)
    {
        choco install $package -y
    }
}

# https://adamtheautomator.com/powershell-download-file/
function download_idafree()
{
    $src = "https://out7.hex-rays.com/files/idafree76_windows.exe"
    $dst = "C:\Users\$env:username\Downloads\idafree76_windows.exe"
    Invoke-WebRequest -Uri $src -OutFile $dst
    Start-Process -FilePath $dst
}