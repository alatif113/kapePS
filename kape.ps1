<# 
.SYNOPSIS 
    Run Kroll Artifact Parser And Extractor (KAPE)

.DESCRIPTION
    The kape.ps1 script optionally downloads KAPE binaries and runs KAPE with pre-defined targets and modules

.LINK 
    https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

.Parameter RepoLocation 
    Specifies the repository location of KAPE binaries. If no location is defined, the script assumes binaries exist locally

.Parameter TargMods
    Specifies a JSON array of Targets and Modules to run. Each array item will trigger a new parallel instance of KAPE.
    Format:
    '[
        {
            "targets": ["target1, "target2", ...], 
            "modules": ["module1", "module2", ...]
        }, 
        {
            "targets": ["target1, "target2", ...], 
            "modules": ["module1", "module2", ...]
        },
        ...
    ]'
#>

param(
    [Parameter(Mandatory)]
    [string]$RepoLocation,

    [Parameter()]
    [double]$Version,

    [Parameter(Mandatory)]
    [string]$TargMods
)

$global:KAPE_WORKING_DIR = Convert-Path $([System.IO.Path]::Combine($PWD, "kape"))
$global:KAPE_INSTALL_DIR = [System.IO.Path]::Combine($KAPE_WORKING_DIR, "kape-master")
$global:KAPE_TEMP_ARCHIVE = [System.IO.Path]::Combine($KAPE_WORKING_DIR, "kape.zip")
$global:KAPE_VERSION_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_DIR, "version")
$global:KAPE_EXE_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_DIR, "kape.exe")
$global:KAPE_TSOURCE = "C:"
$global:KAPE_TDEST = [System.IO.Path]::Combine($KAPE_WORKING_DIR, "targets")
$global:KAPE_MDEST = [System.IO.Path]::Combine($KAPE_WORKING_DIR, "modules")
$global:KAPE_CLI_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_DIR, "_kape.cli")

function WriteLog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $LogObject = [PSCustomObject]@{
        Timestamp = Get-Date
        Severity  = $Severity
        Message   = $Message
    }

    #$logFilePath = [System.IO.Path]::Combine($PWD, "kapelog.json")
    #$LogObject | ConvertTo-Json -Compress | Out-File -FilePath $logFilePath -Append
    
    Write-Host "$($LogObject.Timestamp) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
}

function CreateTempEnv {
    if (Test-Path $KAPE_WORKING_DIR) {
        WriteLog -Severity "Warn" -Message "No need to create a temp working directory. $KAPE_WORKING_DIR already exists."
    } else {
        New-Item -ItemType Directory -Force -Path $KAPE_WORKING_DIR | Out-Null
        WriteLog -Severity "Info" -Message "Created working directory $KAPE_WORKING_DIR."
    }

    Set-Location $KAPE_WORKING_DIR
}

function GetKAPE {
    # Delete any existing KAPE binaries
    if ($(Test-Path -Path $KAPE_INSTALL_DIR)) {
        Remove-Item -Path $KAPE_INSTALL_DIR -Force -Recurse
        WriteLog -Severity "Info" -Message "Deleting existing KAPE install at $KAPE_INSTALL_DIR"
    }

    # Download KAPE from remote location
    Invoke-WebRequest -Uri $RepoLocation -OutFile $KAPE_TEMP_ARCHIVE
    WriteLog -Severity "Info" -Message "Downloading KAPE from $RepoLocation to $KAPE_TEMP_ARCHIVE"

    # Exapnd KAPE zip
    Expand-Archive -Path $KAPE_TEMP_ARCHIVE -DestinationPath $KAPE_WORKING_DIR -Force
    Remove-Item -Path $KAPE_TEMP_ARCHIVE
    WriteLog -Severity "Info" -Message "Unzipped $KAPE_TEMP_ARCHIVE to $KAPE_WORKING_DIR"
}

# Disable progress bars from writing to the standard output
$global:ProgressPreference = 'SilentlyContinue'

# Create working directory
CreateTempEnv "kape"

# get KAPE if it doesnt already exist
if (-not($(Test-Path -Path $KAPE_VERSION_PATH))) {
    WriteLog -Severity "Info" -Message "An existing KAPE version file was not found at $KAPE_VERSION_PATH, redownloading."
    GetKAPE
} 
# Otherwise, redownload if current version is less than required version
elseif ($PSBoundParameters.ContainsKey('Version')) {
    $currentVersion = $(Get-Content -Path $KAPE_VERSION_PATH)
    if ($($currentVersion -as [double]) -lt $Version) {
        WriteLog -Severity "Info" -Message "Current KAPE version $currentVersion is less than the required version of $Version, redownloading."
        GetKape
    }
} else {
    WriteLog -Severity "Info" -Message "Using existing installation of KAPE."
}

# Parse Targets and Modules
try {
    $targModsObj = $TargMods | ConvertFrom-Json
} catch {
    WriteLog -Severity "Info" -Message "Invalid JSON object: $TargMods"
}

New-Item -Path $KAPE_INSTALL_DIR -Name "_kape.cli" -ItemType "file" -Value "" -Force
ForEach ($obj in $targModsObj) {
    $kapeArgs = "--tsource $KAPE_TSOURCE --tdest $KAPE_TDEST --target $($obj.targets -join ',') --module $($obj.modules -join ',') --mdest $KAPE_MDEST"
    Add-Content -Path $KAPE_CLI_PATH -Value $kapeArgs
    WriteLog -Severity "Info" -Message "Adding arguments to ${KAPE_CLI_PATH}: $kapeArgs"
}

WriteLog -Severity "Info" -Message "Running KAPE from $KAPE_EXE_PATH"
Start-Process $KAPE_EXE_PATH

# Enable progress bars to write to the standard output
$global:ProgressPreference = 'Continue'
cd ..
