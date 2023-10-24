<# 
.SYNOPSIS 
    Run Kroll Artifact Parser And Extractor (KAPE)

.DESCRIPTION
    The kape.ps1 script downloads KAPE binaries and runs KAPE with pre-defined targets and modules

.LINK 
    https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

.Parameter RepoLocation 
    [Required] Specifies the repository location of KAPE binaries

.Parameter Version
    [Optional] Specifies the version of KAPE required based on the version.txt file

.Parameter Drive
    [Optional] Specifies the source drive to query and collect artifacts from.
    Default Value: C:

.Parameter Container
    [Optional] Specifies the type of container to collect artifacts within: vhd, vhdx, or zip. 
    Default Value: zip 

.Parameter Password
    [Optional] Specifies that zip files should be encrypted using this password

.Parameter Targets
    [Required] Specifies a comma separated list of KAPE Targets

.Parameter Modules
    [Required] Specifies a comma separated list of KAPE Modules

.Parameter AsBackgroundJob
    Specifies whether KAPE should run as a background job
#>

#########################################
# Parameters
#########################################

param(
    [Parameter(Mandatory)]
    [string]$RepoLocation,

    [Parameter()]
    [double]$Version,

    [Parameter()]
    [string]$Drive = "C:",

    [Parameter()]
    [ValidateSet("zip", "vhd", "vhdx")]
    [string]$Container = "zip",

    [Parameter()]
    [string]$Password,

    [Parameter(Mandatory)]
    [string]$Targets,

    [Parameter()]
    [string]$Modules,

    [Parameter()]
    [switch]$AsBackgroundJob
)

#########################################
# Global Variables
#########################################

$ROOT = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("C:")

$global:HOSTNAME = [System.Net.Dns]::GetHostName()                                      # Current host
$global:KAPE_WORKING_DIR = [System.IO.Path]::Combine($ROOT, "KAPE")                     # Working directory
$global:KAPE_INSTALL_DIR = [System.IO.Path]::Combine($KAPE_WORKING_DIR, "kape-master")  # KAPE package directory
$global:KAPE_TEMP_ARCHIVE = [System.IO.Path]::Combine($KAPE_WORKING_DIR, "kape.zip")    # Temporary name for KAPE zip file 
$global:KAPE_VERSION_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_DIR, "version")     # Path to KAPE version file
$global:KAPE_EXE_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_DIR, "kape.exe")        # Path to KAPE exe
$global:KAPE_TDEST = [System.IO.Path]::Combine($KAPE_WORKING_DIR, "targets")            # Directory to store KAPE target outupts
$global:KAPE_MDEST = [System.IO.Path]::Combine($KAPE_WORKING_DIR, "modules")            # Directory to store KAPE module outputs

#########################################
# Functions
#########################################

function WriteLog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "$(Get-Date) $Severity $Message"
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    WriteLog -Severity "Error" -Message "Administrative privileges are required to run KAPE, exiting."
    exit 1
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

#########################################
# Main
#########################################

# Disable progress bars from writing to the standard output
$global:ProgressPreference = 'SilentlyContinue'

# Create working directory
if (Test-Path $KAPE_WORKING_DIR) {
    WriteLog -Severity "Info" -Message "No need to create a temp working directory. $KAPE_WORKING_DIR already exists."
} else {
    New-Item -ItemType Directory -Force -Path $KAPE_WORKING_DIR | Out-Null
    WriteLog -Severity "Info" -Message "Created working directory $KAPE_WORKING_DIR."
}

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
$kapeArgs = "--tsource $Drive --tdest $KAPE_TDEST --target $Targets --tflush --$Container $HOSTNAME"

# Append module arguments if Modules were declared
if($PSBoundParameters.ContainsKey('Modules')) {
    $kapeArgs = "$kapeArgs --mdest $KAPE_MDEST --module $Modules --mflush --zm"
}

# Append zip password arguments if Password was declared
if($PSBoundParameters.ContainsKey('Password')) {
    $kapeArgs = "$kapeArgs --zpw $Password"
}

# Run KAPE
if ($AsBackgroundJob) {
    WriteLog -Severity "Info" -Message "Starting KAPE as background job with args: $kapeArgs"
    Start-Process $KAPE_EXE_PATH -WindowStyle Hidden -ArgumentList $kapeArgs
    
    # Wait 10 seconds for background job to start
    Start-Sleep -Seconds 10
} else {
    WriteLog -Severity "Info" -Message "Starting KAPE with args: $kapeArgs"
    Start-Process $KAPE_EXE_PATH -Wait -NoNewWindow -ArgumentList $kapeArgs
}

# Check if ConsoleLog.txt file has been created
$files = @(Get-ChildItem -Path $KAPE_INSTALL_DIR,$KAPE_TDEST -Filter *_ConsoleLog.txt -ErrorAction SilentlyContinue)
if ($files.length -eq 0) {
    WriteLog -Severity "Error" -Message "ConsoleLog.txt could not be found, something may have went wrong."
} else {
    WriteLog -Severity "Info" -Message "KAPE is logging to $($files.Name)"
}

# Enable progress bars to write to the standard output
$global:ProgressPreference = 'Continue'
