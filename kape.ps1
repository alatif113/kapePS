<# 
.SYNOPSIS 
    Run Kroll Artifact Parser And Extractor (KAPE)

.DESCRIPTION
    The kape.ps1 script optionally downloads KAPE binaries and runs KAPE with pre-defined targets and modules

.LINK 
    https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

.Parameter RepoLocation 
    Specifies the repository location of KAPE binaries. If no location is defined, the script assumes binaries exist locally

.Parameter Targets
    Specifies a comma separated list of KAPE Targets

.Parameter Modules
    Specifies a comma separated list of KAPE Modules
#>

param(
    [Parameter(Mandatory)]
    [string]$RepoLocation,

    [Parameter()]
    [double]$Version,

    [Parameter(Mandatory)]
    [string]$Targets,

    [Parameter()]
    [string]$Modules
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
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Severity) $($LogObject.Message)"
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    WriteLog -Severity "Error" -Message "Administrative privileges are required to run KAPE, exiting."
    exit 1
}

function CreateTempEnv {
    if (Test-Path $KAPE_WORKING_DIR) {
        WriteLog -Severity "Info" -Message "No need to create a temp working directory. $KAPE_WORKING_DIR already exists."
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
    WriteLog -Severity "Info" -Message "Downloading KAPE from $RepoLocation"

    Invoke-WebRequest -Uri $RepoLocation -OutFile $KAPE_TEMP_ARCHIVE

    if ($(Test-Path -Path $KAPE_TEMP_ARCHIVE)) {
        WriteLog -Severity "Info" -Message "Downloaded KAPE to to $KAPE_TEMP_ARCHIVE"
    } else {
        WriteLog -Severity "Error" -Message "Error downloading KAPE to to $KAPE_TEMP_ARCHIVE"
        exit 1
    }

    # Exapnd KAPE zip
    WriteLog -Severity "Info" -Message "Extracting $KAPE_TEMP_ARCHIVE"

    Expand-Archive -Path $KAPE_TEMP_ARCHIVE -DestinationPath $KAPE_WORKING_DIR -Force

    if ($(Test-Path -Path $KAPE_WORKING_DIR)) {
        WriteLog -Severity "Info" -Message "Extracted KAPE to $KAPE_INSTALL_DIR"
        Remove-Item -Path $KAPE_TEMP_ARCHIVE
    } else {
        WriteLog -Severity "Error" -Message "Error extracting KAPE to $KAPE_WORKING_DIR"
        exit 1
    }
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

# Create argument string to kape.exe
$kapeArgs = "--tsource $KAPE_TSOURCE --tdest $KAPE_TDEST --target $Targets --tflush"

# Append module arguments if Modules were declared
if($PSBoundParameters.ContainsKey('Modules')) {
    $kapeArgs = "$kapeArgs --mdest $KAPE_MDEST --module $Modules --mflush"
}

WriteLog -Severity "Info" -Message "Starting KAPE as background job with args: $kapeArgs"

# Start KAPE as a background job
Start-Process $KAPE_EXE_PATH -ArgumentList $kapeArgs

# Wait 10 seconds
Start-Sleep -Seconds 10

# Check if ConsoleLog.txt file has been created
$files = @(Get-ChildItem -Path $KAPE_INSTALL_DIR,$KAPE_TDEST -Filter *_ConsoleLog.txt -ErrorAction SilentlyContinue)
if ($files.length -eq 0) {
    WriteLog -Severity "Error" -Message "ConsoleLog.txt could not be found, something may have went wrong."
} else {
    WriteLog -Severity "Info" -Message "KAPE is logging to $($files.Name)"
}

# Enable progress bars to write to the standard output
$global:ProgressPreference = 'Continue'
