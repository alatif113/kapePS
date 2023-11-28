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
$global:LOGGING_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "kape_powershell.log")             # Log file
$global:KAPE_INSTALL_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "kape-master")                # KAPE package directory
$global:KAPE_ARCHIVE_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "kape.zip")                   # Temporary name for KAPE zip file 
$global:KAPE_VERSION_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_PATH, "version")                    # Path to KAPE version file
$global:KAPE_EXE_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_PATH, "kape.exe")                       # Path to KAPE exe
$global:AZCOPY_EXE_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_PATH, "azcopy.exe")                   # Path to azcopy exe
$global:7Z_EXE_PATH = [System.IO.Path]::Combine($KAPE_INSTALL_PATH, "7za.exe")                          # Path to 7z exe
$global:KAPE_TARGETS_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "targets")                    # Directory to store KAPE target outupts
$global:KAPE_MODULES_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "modules")                    # Directory to store KAPE module outputs
$global:KAPE_ALL_OUTPUTS_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "outputs")                # KAPE outputs
$global:AZCOPY_TEST_PATH = [System.IO.Path]::Combine($KAPE_WORKING_PATH, "azcopy_test_file.txt")        # File to test azcopy
$global:MAX_LOG_SIZE = 1                                                                                # Log file size threshold in MB before rotating
$global:MIN_FREE_SPACE_TARGETS = 2048                                                                   # Minimum available space in MB in order for KAPE to run

#########################################
# Functions
#########################################

# Write a log to a log file and the console simultaneously
function WriteLog {
    param($Severity, $Message)
    $ProcessID = [System.Diagnostics.Process]::GetCurrentProcess().Id
    "$(Get-Date) $Severity [$ProcessID] $Message" | Tee-Object -FilePath $LOGGING_PATH -Append | Write-Host
}

# Check if log file exceeds size threshold, and rotate file if so
function RotateLog {
    if (-not(Test-Path $LOGGING_PATH)) {
        return
    }

    $Log = Get-Item $LOGGING_PATH
    if ($Log.Length/1024/1024 -ge $MAX_LOG_SIZE) { 
        WriteLog -Severity "Info" -Message "Log file is larger than $MAX_LOG_SIZE MB"
        $NewName = "$($Log.BaseName)_$(Get-Date -Format "yyyyMMdd").log"
        Rename-Item -Path $LOGGING_PATH -NewName $NewName -Force
        WriteLog -Severity "Info" -Message "Rotated file to $NewName" 
    }
}

# Download KAPE from remote repository
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
        WriteLog -Severity "Error" -Message "Failed to download KAPE to to $KAPE_ARCHIVE_PATH; $_"
        exit
    }
    WriteLog -Severity "Info" -Message "Downloaded KAPE to to $KAPE_ARCHIVE_PATH"

    # Exapnd KAPE zip
    WriteLog -Severity "Info" -Message "Extracting $KAPE_ARCHIVE_PATH"
    try {
        Expand-Archive -Path $KAPE_ARCHIVE_PATH -DestinationPath $KAPE_WORKING_PATH -Force
    } catch {
        WriteLog -Severity "Error" -Message "Unable to extract KAPE to $KAPE_WORKING_PATH; $_"
        exit
    }
    WriteLog -Severity "Info" -Message "Extracted KAPE to $KAPE_INSTALL_PATH"
    Remove-Item -Path $KAPE_ARCHIVE_PATH
}

#########################################
# Main
#########################################

# Check if log file is too big. If so, rotate
RotateLog

# Check for Admin privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host "$(Get-Date) Error [$([System.Diagnostics.Process]::GetCurrentProcess().Id)] Administrative privileges are required to run KAPE, exiting."
    exit
}

# Check if Root directory exists
if(-not($(Test-Path $ROOT))) {
    Write-Host "$(Get-Date) Error [$([System.Diagnostics.Process]::GetCurrentProcess().Id)] Root directory $ROOT not found, exiting."
    exit
}

# Disable progress bars from writing to the standard output
$global:ProgressPreference = 'SilentlyContinue'

# Create working directory
if (Test-Path $KAPE_WORKING_PATH) {
    WriteLog -Severity "Info" -Message "########################## kape.ps1 PowerShell session started ##########################"
    WriteLog -Severity "Info" -Message "No need to create a working directory. $KAPE_WORKING_PATH already exists."
} else {
    try {
        New-Item -ItemType Directory -Force -Path $KAPE_WORKING_PATH | Out-Null
    } catch {
        Write-Host "$(Get-Date) Error [$([System.Diagnostics.Process]::GetCurrentProcess().Id)] Unable to create $KAPE_WORKING_PATH, exiting."
        exit
    }
    WriteLog -Severity "Info" -Message "########################## kape.ps1 PowerShell session started ##########################"
    WriteLog -Severity "Info" -Message "Created working directory $KAPE_WORKING_PATH."
}

# Check if available space meets threshold
$FreeSpace = [math]::floor((Get-PSDrive C | Select-Object -ExpandProperty Free) / 1mb)
if($FreeSpace -gt $MIN_FREE_SPACE_TARGETS) {
    WriteLog -Severity "Info" -Message "Available space of $FreeSpace MB meets threshold of $MIN_FREE_SPACE_TARGETS MB for KAPE targets."
} else {
    WriteLog -Severity "Error" -Message "Available space of $FreeSpace MB is less than the required threshold of $MIN_FREE_SPACE_TARGETS MB for KAPE targets, exiting."
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
    WriteLog -Severity "Info" -Message "Using existing installation of KAPE, version $(Get-Content -Path $KAPE_VERSION_PATH)."
}

# Test azcopy
if($PSBoundParameters.ContainsKey('StorageAccount')) {
    WriteLog -Severity "Info" -Message "Azure storage account set, testing upload to https://$StorageAccount.blob.core.windows.net/$StorageContainer."
    
    # Create small test file to upload
    New-Item -ItemType File -Path $AZCOPY_TEST_PATH -Force | Out-Null

    # Attempt upload as a background job with a 60 second timeout and check output for errors
    $Job = Start-Job -ScriptBlock {
        & $using:AZCOPY_EXE_PATH copy "$using:AZCOPY_TEST_PATH" "https://$using:StorageAccount.blob.core.windows.net/$using:StorageContainer/$using:StorageToken"
    }
    $Job | Wait-Job -Timeout 60 | Out-Null
    $State = $Job.State

    if ($State -eq 'Running') {
        $Job | Stop-Job
        WriteLog -Severity "Error" -Message "Connection timeout to https://$StorageAccount.blob.core.windows.net/$StorageContainer, exiting."
        exit
    } elseif ($State -eq 'Failed') {
        $ErrorString = $($Job.ChildJobs[0].JobStateInfo.Reason.Message)
    } elseif ($State -eq 'Completed') {
        $ErrorString = $Job | Receive-Job | Select-String -Pattern 'RESPONSE 403:|error' | Select-Object -First 1
    }

    # Delete small test file
    Remove-Item $AZCOPY_TEST_PATH -Force

    # If errors, log and exit
    if ($null -ne $ErrorString) {
        WriteLog -Severity "Error" -Message "Connection test to https://$StorageAccount.blob.core.windows.net/$StorageContainer failed; $ErrorString"
        exit
    }

    WriteLog -Severity "Info" -Message "Connection test successful."
}

# Create argument string to kape.exe
$KapeArgs = @('--tsource', $Drive, '--tdest', $KAPE_TARGETS_PATH, '--target', $Targets, '--tflush')

# Append module arguments if Modules were declared
if($PSBoundParameters.ContainsKey('Modules')) {
    $MemSize = [math]::floor((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1mb)
    WriteLog -Severity "Info" -Message "Modules declared to capture $MemSize MB of memory."

    $MinFreeSpaceModules = $MIN_FREE_SPACE_TARGETS + $MemSize

    if($FreeSpace -gt $MinFreeSpaceModules) {
        WriteLog -Severity "Info" -Message "Available space of $FreeSpace MB meets threshold of $MinFreeSpaceModules MB for KAPE modules."
        $KapeArgs += @('--mdest', $KAPE_MODULES_PATH, '--module', $Modules, '--mflush')
    } else {
        WriteLog -Severity "Warn" -Message "Available space of $FreeSpace MB is less than the required threshold of $MinFreeSpaceModules MB for KAPE modules, skipping."
    }
}

# Append container arguments if Container parameter set
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
    LoggingPath = $LOGGING_PATH
}

# Define script block for Job
$ScriptBlock = {
    param($ScriptBlockParams)

    function WriteLog {
        param($Severity, $Message)
        $ProcessID = [System.Diagnostics.Process]::GetCurrentProcess().Id
        "$(Get-Date) $Severity [$ProcessID] $Message" | Tee-Object -FilePath $($ScriptBlockParams.LoggingPath) -Append | Write-Host
    }
    
    # Start KAPE
    try {
        & $ScriptBlockParams.KapeExePath $ScriptBlockParams.KapeArgs
    } catch {
        WriteLog -Severity "Error" -Message "$_."
        Throw "$_"
        exit
    }

    # If Targets directory not created, something went wrong; exit
    if (-not($(Test-Path $ScriptBlockParams.KapeTargetsPath))) {
        WriteLog -Severity "Error" -Message " KAPE did not run successfully, $($ScriptBlockParams.KapeTargetsPath) is missing, exiting."
        Throw "$($ScriptBlockParams.KapeTargetsPath) is missing."
        exit
    } else {
        WriteLog -Severity "Info" -Message "KAPE ran successfully."
    }

    # Create Zip 
    WriteLog -Severity "Info" -Message "Attempting to compress KAPE outputs."
    try {
        & $ScriptBlockParams.ZipExePath $ScriptBlockParams.ZipArgs
    } catch {
        WriteLog -Severity "Error" -Message " $_."
        exit
    }

    # If zip archive not created, something went wrong; exit
    if (-not($(Test-Path $ScriptBlockParams.KapeOutputsPath))) {
        WriteLog -Severity "Error" -Message " Failed to compress KAPE outputs, exiting."
        exit
    } else {
        WriteLog -Severity "Info" -Message "Successfully compressed KAPE outputs to $($ScriptBlockParams.KapeOutputsPath)."
    }

    # Upload to Azure with a 300 second timeout
    if ($null -ne $ScriptBlockParams.AzcopyArgs) {
        WriteLog -Severity "Info" -Message "Running azcopy to upload $($ScriptBlockParams.KapeOutputsPath) to remote storage."
    
        $Job = Start-Job -ScriptBlock {
            & $using:ScriptBlockParams.AzcopyExePath $using:ScriptBlockParams.AzcopyArgs
        }
        $Job | Wait-Job -Timeout 300 | Out-Null
        if ($Job.State -eq 'Running') {
            $Job | Stop-Job
            $ErrorString = "Connection timeout to https://$StorageAccount.blob.core.windows.net/$StorageContainer"
        } elseif ($Job.State -eq 'Failed') {
            $ErrorString = $($Job.ChildJobs[0].JobStateInfo.Reason.Message)
        } elseif ($Job.State -eq 'Completed') {
            $ErrorString = $Job | Receive-Job | Select-String -Pattern 'RESPONSE 403:|error' | Select-Object -First 1
        }

        if ($null -ne $ErrorString) {
            WriteLog -Severity "Error" -Message "Upload to remote storage failed; $ErrorString."
            exit
        } else {
            WriteLog -Severity "Info" -Message "Successfully uploaded KAPE outputs to remote storage."
        }
    }

    # If storing to a remote location, delete local outputs
    if (($null -ne $ScriptBlockParams.AzcopyArgs) -AND $(Test-Path $ScriptBlockParams.KapeOutputsPath)) {
        WriteLog -Severity "Info" -Message "Removing $($ScriptBlockParams.KapeOutputsPath)"
        Remove-Item $ScriptBlockParams.KapeOutputsPath -Recurse -Force
    }

    # Clean up targets 
    if ($(Test-Path $ScriptBlockParams.KapeTargetsPath)) {
        WriteLog -Severity "Info" -Message "Removing $($ScriptBlockParams.KapeTargetsPath)"
        Remove-Item $ScriptBlockParams.KapeTargetsPath -Recurse -Force
    }

    # Clean up modules
    if ($(Test-Path $ScriptBlockParams.KapeModulesPath)) {
        WriteLog -Severity "Info" -Message "Removing $($ScriptBlockParams.KapeModulesPath)"
        Remove-Item $ScriptBlockParams.KapeModulesPath -Recurse -Force
    }
}

# Start Job
if ($AsBackgroundJob) {
    WriteLog -Severity "Info" -Message "Starting KAPE as background job with args: $KapeArgs"
    
    # Start background job
    $Job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ScriptBlockParams
    
    # Wait 10 seconds and check Job has not failed
    Start-Sleep -Seconds 20
    if ($Job.State -eq 'Failed') {
        WriteLog -Severity "Error" -Message "Background job failed with error: $($Job.ChildJobs[0].JobStateInfo.Reason.Message)"
    } else {
        WriteLog -Severity "Info" -Message "KAPE is running, this may take a couple minutes."
        if ($PSBoundParameters.ContainsKey('StorageAccount')) {
            WriteLog -Severity "Info" -Message "Once the job is complete, outputs will be stored at https://$StorageAccount.blob.core.windows.net/$StorageContainer/$KapeOutputsArchive."
        } else {
            WriteLog -Severity "Info" -Message "Once the job is complete, outputs will be stored in $KapeOutputsPath."        
        }
        WriteLog -Severity "Info" -Message "Once the job is complete, a full console log of this session will be stored within $LOGGING_PATH"
    }
} else {
    WriteLog -Severity "Info" -Message "Starting KAPE with args: $KapeArgs"

    # Start in foreground
    & $ScriptBlock -ScriptBlockParams $ScriptBlockParams
    if ($PSBoundParameters.ContainsKey('StorageAccount')) {
        WriteLog -Severity "Info" -Message "Outputs are stored at https://$StorageAccount.blob.core.windows.net/$StorageContainer/$KapeOutputsArchive."
    } else {
        WriteLog -Severity "Info" -Message "Outputs are stored in $KapeOutputsPath."
    }
    WriteLog -Severity "Info" -Message "A full console log of this session is stored within $LOGGING_PATH"
}

# Enable progress bars to write to the standard output
$global:ProgressPreference = 'Continue'
