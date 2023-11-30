$TotalMem = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory
$CPUCores = (Get-WMIObject Win32_ComputerSystem).NumberOfLogicalProcessors
$ProcessList = "kape", "7za", "azcopy"

Write-Host ("{0,20} {1,10} {2,10} {3,10} {4,10} {5,10} {6,10} {7,10}" -f "time","kape_cpu","kape_mem","7za_cpu","7za_mem","azcopy_cpu","azcopy_mem","bandwidth")
Write-Host ("{0,20} {1,10} {1,10} {1,10} {1,10} {1,10} {1,10} {1,10}" -f "--------------------","----------")

Clear-Content -Path ./kape_resource_usage.csv
Add-Content -Path ./kape_resource_usage.csv -Value "time,kape_cpu,kape_mem,7za_cpu,7za_mem,azcopy_cpu,azcopy_mem,bandwidth"

do {
    $Row = "" | Select-Object timestamp,kape_cpu,kape_mem,7za_cpu,7za_mem,azcopy_cpu,azcopy_mem,bandwidth

    foreach ($Process in $ProcessList) {
        $Row.timestamp = Get-Date -UFormat %s
        $Proc = (get-process $Process -ErrorAction SilentlyContinue)

        if ($null -eq $Proc) {
            $Row."$($Process)_cpu" = 0
            $Row."$($Process)_mem" = 0
            continue
        }

        $ProcId = $Proc.Id[0]
        $ProcPath = ((Get-Counter "\Process(*)\ID Process" -ErrorAction SilentlyContinue).CounterSamples | Where-Object {$_.RawValue -eq $ProcId}).Path

        if ($null -eq $ProcPath) {
            $Row."$($Process)_cpu" = 0
            $Row."$($Process)_mem" = 0
            continue
        }

        $CPUPercent = [Math]::Round(((Get-Counter ($ProcPath -replace "\\id process$","\% Processor Time") -ErrorAction SilentlyContinue).CounterSamples.CookedValue) / $CPUCores)
        $MemPercent = [Math]::Round(((Get-Process -Id $ProcId -ErrorAction SilentlyContinue).WorkingSet / $TotalMem) * 100)

        $Row."$($Process)_cpu" = $CPUPercent
        $Row."$($Process)_mem" = $MemPercent
    }

    $Interface = Get-CimInstance -class Win32_PerfFormattedData_Tcpip_NetworkInterface | Select-Object BytesTotalPersec, CurrentBandwidth
    $Row.bandwidth = [Math]::Round($Interface.BytesTotalPersec * 8 / $Interface.CurrentBandwidth * 100)

    Add-Content -Path ./kape_resource_usage.csv -Value "$($Row.timestamp),$($Row.kape_cpu),$($Row.kape_mem),$($Row."7za_cpu"),$($Row."7za_mem"),$($Row.azcopy_cpu),$($Row.azcopy_mem),$($Row.bandwidth)"
    Write-Host ("{0,20} {1,10} {2,10} {3,10} {4,10} {5,10} {6,10} {7,10}" -f $Row.timestamp,$Row.kape_cpu,$Row.kape_mem,$Row."7za_cpu",$Row."7za_mem",$Row.azcopy_cpu,$Row.azcopy_mem,$Row.bandwidth)

    Start-Sleep -Seconds 1
} while ($true)
