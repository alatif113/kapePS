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
    [Optional] Specifies the type of container to collect artifacts within: vhd or vhdx. 

.Parameter Password
    [Optional] Specifies that zip files should be encrypted using this password

.Parameter Targets
    [Required] Specifies a comma separated list of KAPE Targets

.Parameter Modules
    [Required] Specifies a comma separated list of KAPE Modules

.Parameter AsBackgroundJob
    [Optional] Specifies whether KAPE should run as a background job

.Parameter StorageAccount
    [Optional] Specifies the Azure blob storage account to store KAPE outputs

.Parameter StorageContainer
    [Optional] Specifies the Azure blob storage container to store KAPE outputs

.Parameter StorageToken
    [Optional] Specifies the Azure blob storage token to store KAPE outputs. Required if StorageContainer is set. 
#>

#########################################
# Parameters
#########################################

param(
    [Parameter(Mandatory, ParameterSetName = 'All')]
    [Parameter(Mandatory, ParameterSetName = 'RemoteStorage')]
    [string]$RepoLocation,

    [Parameter(ParameterSetName = 'All')]
    [Parameter(ParameterSetName = 'RemoteStorage')]
    [double]$Version,

    [Parameter(ParameterSetName = 'All')]
    [Parameter(ParameterSetName = 'RemoteStorage')]
    [string]$Drive = "C:",

    [Parameter(ParameterSetName = 'All')]
    [Parameter(ParameterSetName = 'RemoteStorage')]
    [ValidateSet("vhd", "vhdx")]
    [string]$Container,

    [Parameter(ParameterSetName = 'All')]
    [Parameter(ParameterSetName = 'RemoteStorage')]
    [string]$Password,

    [Parameter(Mandatory, ParameterSetName = 'All')]
    [Parameter(Mandatory, ParameterSetName = 'RemoteStorage')]
    [string]$Targets,

    [Parameter(ParameterSetName = 'All')]
    [Parameter(ParameterSetName = 'RemoteStorage')]
    [string]$Modules,

    [Parameter(ParameterSetName = 'All')]
    [Parameter(ParameterSetName = 'RemoteStorage')]
    [switch]$AsBackgroundJob,

    [Parameter(Mandatory, ParameterSetName = 'RemoteStorage')]
    [string]$StorageAccount,

    [Parameter(Mandatory, ParameterSetName = 'RemoteStorage')]
    [string]$StorageContainer,
    
    [Parameter(Mandatory, ParameterSetName = 'RemoteStorage')]
    [string]$StorageToken
)

#########################################
# Global Variables
#########################################

$global:ROOT = "C:\"                                                                                    # Root drive
$global:KAPE_WORKING_PATH = [System.IO.Path]::Combine($ROOT, "KAPE")                                    # Working directory
$global:KAPE_INSTALL_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "kape-master")                # KAPE package directory
$global:KAPE_ARCHIVE_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "kape.zip")                   # Temporary name for KAPE zip file 
$global:KAPE_VERSION_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_PATH, "version")                    # Path to KAPE version file
$global:KAPE_EXE_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_PATH, "kape.exe")                       # Path to KAPE exe
$global:AZCOPY_EXE_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_PATH, "azcopy.exe")                   # Path to azcopy exe
$global:7Z_EXE_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_PATH, "7za.exe")                          # Path to 7z exe
$global:KAPE_TARGETS_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "targets")                    # Directory to store KAPE target outupts
$global:KAPE_MODULES_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "modules")                    # Directory to store KAPE module outputs
$global:KAPE_ALL_OUTPUTS_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "outputs")                # KAPE outputs
$global:AZCOPY_TEST_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "azcopy_test_file.txt")    # File to test azcopy

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

function GetKAPE {
    # Delete any existing KAPE binaries
    if ($(Test-Path -Path $KAPE_INSTALL_PATH)) {
        Remove-Item -Path $KAPE_INSTALL_PATH -Force -Recurse
        WriteLog -Severity "Info" -Message "Deleting existing KAPE install at $KAPE_INSTALL_PATH"
    }

    # Download KAPE from remote location
    WriteLog -Severity "Info" -Message "Downloading KAPE from $RepoLocation"
    try {
        Invoke-WebRequest -Uri $RepoLocation -OutFile $KAPE_ARCHIVE_PATH
    } catch {
        WriteLog -Severity "Error" -Message "Error downloading KAPE to to $KAPE_ARCHIVE_PATH; $_"
        exit 1
    }
    WriteLog -Severity "Info" -Message "Downloaded KAPE to to $KAPE_ARCHIVE_PATH"

    # Exapnd KAPE zip
    WriteLog -Severity "Info" -Message "Extracting $KAPE_ARCHIVE_PATH"
    try {
        Expand-Archive -Path $KAPE_ARCHIVE_PATH -DestinationPath $KAPE_WORKING_PATH -Force
    } catch {
        WriteLog -Severity "Error" -Message "Error extracting KAPE to $KAPE_WORKING_PATH; $_"
        exit 1
    }
    WriteLog -Severity "Info" -Message "Extracted KAPE to $KAPE_INSTALL_PATH"
    Remove-Item -Path $KAPE_ARCHIVE_PATH
}

function TestAzCopy {
    $Return = $true
    New-Item -ItemType File -Path $AZCOPY_TEST_PATH | Out-Null
    $Output = & $AZCOPY_EXE_PATH copy $AZCOPY_TEST_PATH https://$StorageAccount.blob.core.windows.net/$StorageContainer/$StorageToken
    
    if ($LASTEXITCODE -eq 1) {
        WriteLog -Severity "Error" -Message "Error running azcopy test; try storing KAPE outputs locally instead, exiting."
        $Return = $false
    } 

    if ($Output -match 'AuthenticationFailed') {
        WriteLog -Severity "Error" -Message "AuthenticationFailed error running azcopy test; try checking if the SAS token is still valid, exiting."
        $Return = $false
    }

    Remove-Item $AZCOPY_TEST_PATH
    return $Return
}

#########################################
# Main
#########################################

# Check for Admin privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    WriteLog -Severity "Error" -Message "Administrative privileges are required to run KAPE, exiting."
    exit 1
}

# Check if Root directory exists
if(-not($(Test-Path $ROOT))) {
    WriteLog -Severity "Error" -Message "Root directory $ROOT not found, exiting."
    exit 1
}

# Disable progress bars from writing to the standard output
$global:ProgressPreference = 'SilentlyContinue'

# Create working directory
if (Test-Path $KAPE_WORKING_PATH) {
    WriteLog -Severity "Info" -Message "No need to create a temp working directory. $KAPE_WORKING_PATH already exists."
} else {
    New-Item -ItemType Directory -Force -Path $KAPE_WORKING_PATH | Out-Null
    WriteLog -Severity "Info" -Message "Created working directory $KAPE_WORKING_PATH."
}

# get KAPE if it doesnt already exist
if (-not($(Test-Path -Path $KAPE_VERSION_PATH))) {
    WriteLog -Severity "Info" -Message "An existing KAPE version file was not found at $KAPE_VERSION_PATH, re-downloading."
    GetKAPE
} 
# Otherwise, re-download if current version is less than required version
elseif ($PSBoundParameters.ContainsKey('Version')) {
    $currentVersion = $(Get-Content -Path $KAPE_VERSION_PATH)
    if ($($currentVersion -as [double]) -lt $Version) {
        WriteLog -Severity "Info" -Message "Current KAPE version $currentVersion is less than the required version of $Version, redownloading."
        GetKape
    }
} else {
    WriteLog -Severity "Info" -Message "Using existing installation of KAPE."
}

# Test azcopy
if($PSBoundParameters.ContainsKey('StorageAccount')) {
    WriteLog -Severity "Info" -Message "Azure storage account set, testing upload to https://$StorageAccount.blob.core.windows.net/$StorageContainer."
    if(TestAzCopy) {
        WriteLog -Severity "Info" -Message "Successfully tested connection to https://$StorageAccount.blob.core.windows.net/$StorageContainer."
    } else {
        exit 1
    }
}

# Create argument string to kape.exe
$KapeArgs = @('--tsource', $Drive, '--tdest', $KAPE_TARGETS_PATH, '--target', $Targets, '--tflush')

# Append module arguments if Modules were declared
if($PSBoundParameters.ContainsKey('Modules')) {
    $KapeArgs += @('--mdest', $KAPE_MODULES_PATH, '--module', $Modules, '--mflush')
}

# Append module arguments if Modules were declared
if($PSBoundParameters.ContainsKey('Container')) {
    $KapeArgs += @("--$Container", $(Hostname), '--zv', 'false')
}

$KapeOutputsArchive = "$(Hostname)_$(Get-Date -Format "yyyyMMdd_hhmmss").zip"                   
$KapeOutputsPath = [System.IO.Path]::Combine($KAPE_ALL_OUTPUTS_PATH, $KapeOutputsArchive)

# Create argument string to azcopy.exe
if($PSBoundParameters.ContainsKey('StorageAccount')) {
    $AzcopyArgs = @('copy', $KapeOutputsPath, "https://$StorageAccount.blob.core.windows.net/$StorageContainer/$StorageToken")
}

# Create argument string to 7za.exe
$7zArgs = @('a', '-tzip', '-sdel', $KapeOutputsPath, $KAPE_TARGETS_PATH)

# Append module path if Modules parameter set
if($PSBoundParameters.ContainsKey('Modules')) {
    $7zArgs += $KAPE_MODULES_PATH
}

# Set zip password if Password parameter set
if($PSBoundParameters.ContainsKey('Password')) {
    $7zArgs += "-p$Password"
}

# Arguments to script block
$ScriptBlockParams = [PSCustomObject]@{
    KapeArgs = $KapeArgs
    AzcopyArgs = $AzcopyArgs
    ZipArgs = $7zArgs
    KapeOutputsPath = $KapeOutputsPath                 
    KapeExePath = $KAPE_EXE_PATH
    AzcopyExePath = $AZCOPY_EXE_PATH
    ZipExePath = $7Z_EXE_PATH
    KapeTargetsPath = $KAPE_TARGETS_PATH
    KapeModulesPath = $KAPE_MODULES_PATH
}

# Define script block for Job
$ScriptBlock = {
    param($ScriptBlockParams)
    
    # Start KAPE
    & $ScriptBlockParams.KapeExePath $ScriptBlockParams.KapeArgs

    # If Targets directory not created, something went wrong; exit
    if (-not($(Test-Path $ScriptBlockParams.KapeTargetsPath))) {
        exit 1
    }

    # Create Zip 
    Write-Host "$(Get-Date) Info Running 7z to compress KAPE outputs."
    & $ScriptBlockParams.ZipExePath $ScriptBlockParams.ZipArgs

    # If zip archive not created, something went wrong; exit
    if (-not($(Test-Path $ScriptBlockParams.KapeOutputsPath))) {
        exit 1
    }

    # Upload to Azure
    if ($ScriptBlockParams.AzcopyArgs -ne $null) {
        Write-Host "$(Get-Date) Info Running azcopy to upload $($ScriptBlockParams.KapeOutputsPath) to remote storage."
        & $ScriptBlockParams.AzcopyExePath $ScriptBlockParams.AzcopyArgs
    }

    # If storing to a remote location, delete local outputs
    if (($ScriptBlockParams.AzcopyArgs -ne $null) -AND $(Test-Path $ScriptBlockParams.KapeOutputsPath)) {
        Write-Host "$(Get-Date) Info Removing $($ScriptBlockParams.KapeOutputsPath)"
        Remove-Item $ScriptBlockParams.KapeOutputsPath -Recurse
    }

    # Clean up targets 
    if ($(Test-Path $ScriptBlockParams.KapeTargetsPath)) {
        Write-Host "$(Get-Date) Info Removing $($ScriptBlockParams.KapeTargetsPath)"
        Remove-Item $ScriptBlockParams.KapeTargetsPath -Recurse
    }

    # Clean up modules
    if ($(Test-Path $ScriptBlockParams.KapeModulesPath)) {
        Write-Host "$(Get-Date) Info Removing $($ScriptBlockParams.KapeModulesPath)"
        Remove-Item $ScriptBlockParams.KapeModulesPath -Recurse
    }
}

# Start Job
if ($AsBackgroundJob) {
    WriteLog -Severity "Info" -Message "Starting KAPE as background job with args: $KapeArgs"
    
    # Start background job
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ScriptBlockParams
    
    # Wait 10 seconds and check Job has not failed
    Start-Sleep -Seconds 10
    if ($job.State -eq 'Failed') {
        WriteLog -Severity "Error" -Message "Background job failed with error: $($job.ChildJobs[0].JobStateInfo.Reason.Message)"
    } else {
        if ($PSBoundParameters.ContainsKey('StorageAccount')) {
            WriteLog -Severity "Info" -Message "KAPE is running, outputs will be stored at https://$StorageAccount.blob.core.windows.net/$StorageContainer/$KapeOutputsArchive; This may take a couple minutes."
        } else {
            WriteLog -Severity "Info" -Message "KAPE is running, outputs will be stored in $KapeOutputsPath; This may take a couple minutes."
        }
    }

} else {
    WriteLog -Severity "Info" -Message "Starting KAPE with args: $KapeArgs"

    # Start in foreground
    & $ScriptBlock -ScriptBlockParams $ScriptBlockParams
    if ($PSBoundParameters.ContainsKey('StorageAccount')) {
        WriteLog -Severity "Info" -Message "Done; Outputs are stored at https://$StorageAccount.blob.core.windows.net/$StorageContainer/$KapeOutputsArchive."
    } else {
        WriteLog -Severity "Info" -Message "Done; Outputs are stored in $KapeOutputsPath."
    }
}

# Enable progress bars to write to the standard output
$global:ProgressPreference = 'Continue'
