$Counter = 0
$MaxCounter = 100
$Output = @()

$TotalRam = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).Sum

$StartTime = Get-Date

$UsedBandwidth = do {
	$Percent = [math]::Round($Counter/$MaxCounter * 100)
	Write-Progress -Activity "Collecting Resource Usage Metrics" -Status "$Percent% Complete:" -PercentComplete $Percent 

	$Counter ++
	
	$Row = "" | Select Bandwidth_Percent,CPU_Percent,Memory_Percent
	
	$Interface = Get-CimInstance -class Win32_PerfFormattedData_Tcpip_NetworkInterface | select BytesTotalPersec,CurrentBandwidth,PacketsPersec
	
    $Row.Bandwidth_Percent = $Interface.BytesTotalPersec / $Interface.CurrentBandwidth * 100
	
	$Row.CPU_Percent = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
	
	$Mem_Avail = (Get-Counter '\Memory\Available KBytes').CounterSamples.CookedValue * 1024
	$Row.Memory_Percent = ($TotalRam - $Mem_Avail)/$TotalRam * 100
	
	$Output += $Row
	
	Start-Sleep -milliseconds 100
	
} while ($Counter -le $MaxCounter)

$EndTime = Get-Date

$Output | Export-Csv -Path .\kape_resource_usage.csv -NoTypeInformation

Write-Host "Timespan: $StartTime - $EndTime"
Write-Host "Average Bandwidth Usage: $(($Output.Bandwidth_Percent | Measure-Object -Average).Average) %"
Write-Host "Average CPU Usage: $(($Output.CPU_Percent | Measure-Object -Average).Average) %"
Write-Host "Average Memory Usage: $(($Output.Memory_Percent | Measure-Object -Average).Average) %"

