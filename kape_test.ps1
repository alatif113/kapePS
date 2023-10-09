$CURRENT_PATH = Convert-Path $PWD

# Disable progress bars from writing to the standard output
$global:ProgressPreference = 'SilentlyContinue'

# Download KAPE from remote location
Invoke-WebRequest -Uri "https://github.com/alatif113/kape/archive/refs/heads/master.zip" -OutFile "kape.zip"

# Exapnd KAPE zip
Expand-Archive -Path "kape.zip" -DestinationPath $CURRENT_PATH -Force
Remove-Item -Path "kape.zip"

Start-Process -FilePath ".\kape-master\kape.exe" -ArgumentList "--tsource C: --tdest targets --target Chrome"
