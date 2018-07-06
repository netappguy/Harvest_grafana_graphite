#requires -version 4
<#
.NOTES
Information on running PowerShell scripts can be found here, as the SaaS methodology TR:
    -http://ss64.com/ps/syntax-run.html
    -https://technet.microsoft.com/en-us/library/bb613481.aspx
    -http://www.netapp.com/us/media/tr-4548.pdf
File Name:  IODensityReport.ps1
Version: 1.0 (Also reflected in -ShowVersion parameter)
.COMPONENT  
    -PowerShell version 4.0 or greater required (which requires .NET Framework 4.5 or greater be installed first)
    -PowerShell must be preferably launched "Run as Administrator"
    -NetApp PowerShell Toolkit 3.2.1 or newer: http://mysupport.netapp.com/NOW/download/tools/powershell_toolkit/
.DESCRIPTION
This script create an IO Density report from Graphite data, that can be used for the SDW.

Available parameters are:
* naboxip: This parameter should match the Graphite server IP address
* Protocol: This parameter indicates the protocol to be used to access the Graphite Database: HTTP or HTTPS (default).
* Port: This parameter indicates the Port to be used to access the Graphite Dtabase: Defaut is 443
* ItemToReport: This parameter indicates the item to report on : Volume (Default) or LUN
* Period: Default 14 Days. This parameter define the collection period we want to use for the object in the format defined by graphite:
  (See http://graphite.readthedocs.io/en/latest/render_api.html#from-until for detailled informations.)
	 Abbreviation 	Unit
	 s 				Seconds
	 min 			Minutes
	 h 				Hours
	 d 				Days
	 w 				Weeks
	 mon 			30 Days (month)
	 y 				365 Days (year)
* NetAppSelection: If provided, this parameter indicates the comma separated list of NetApp arrays/clusters we want to extract the IODensity report.
* NetAppDetailsCSVFile: CSV file of the list of NetApp arrays/clusters we want to extract the IODensity report:
	CSV file column should be done this way:
	First Line should contain this text: NetApp,MgmtIP,Account,Password,Encrypted
	Column 1: Controler/cluster Name
	Column 2: Management IP
	Column 3: Admin Account
	Column 4: Password (if empty password will be asked on run)
	Column 5: 0: Password is in clear text ; 1: Encrypted password (created using: read-host -assecurestring | convertfrom-securestring) 
	Example of file content:
	
	NetApp,MgmtIP,Account,Password,Encrypted
	MyNetApp1,192.168.0.11,root,NetApp123,0
	MyNetApp2,192.168.0.15,admin,,0
	MyNetApp3,192.168.0.19,admin,01000000d08c9ddf0115d1118c7a00c04fc297eb010000001e74617e62df5946952183ea7f531047000000000200000000001066000000010000200000006b8f3e685fe6750526023e10183ae772edce05528a647ca13643017d698d94c0000000000e800000000200002000000063b1fdacf2dc243777d9668345c3009a56d024fb9eb20e9a8be00c3cdc7b30a320000000c3a8c010db47a17e72de4ded5f9e502676d62e47aaca1d2bc3ed73b85c1b98fe400000001e3e91192dc2a0bdd1ec44f89ca398f54c04ff77998ace13730599937bc4b7dd7e94a50b637dbe5e74a45604679650996e8815c7373e6e10056c4d41c3938944,1
	
	==> First NetApp:  Password is provided in cleartext
	==> Second NetApp: Password is not provided : it will be asked during script execution
	==> Third NetApp:  Password is provided encrypted.
	
	Note : an easy method is to put the password in clear text in the file, run the script and answers y when asked to overwrite the file with encrypted password.
* ExcludeRootVol: if set, all root volumes will be exlcuded from the report (included SVMs root volume)
* ExcludeMDVVol: if set, all MetaData (MDV_???_xxxx) volume will be excluded from the report
* ShowVersion: Get the script version.
.EXAMPLE
.\IODensity_report.ps1
Running without any parameters will prompt for all necessary values (NetApp arrays are extracted from Graphite Database and will be selectable in for of a Menu List.
.EXAMPLE
.\IODensity_report.ps1 -naboxip "192.168.0.20"
The IO Density report will be generated using the data from Graphite server 192.168.0.20. The script will output the list of NetApp found on the Graphite server and let you choose the one you want to use.
.EXAMPLE
.\IODensity_report.ps1 -naboxip "192.168.0.20" -protocol http -port 8080 -NetAppSelection "mynetapp1,mynetapp2,mynetapp3"
The IO Density report will be generated only for the 3 listed NetApp from the Graphite Database using the http protocol on port 8080. Management IPs and credential will be asked by the script.
.EXAMPLE
.\IODensity_report.ps1 -naboxip "192.168.0.20" -NetAppDetailsCSVFile ".\IODensityDetails.csv" -ExcludeRootVol
The IO Density report will be generated for all the non root volume for the Arrays/Clusters listed in the IODensityDetails CSV file located in the current directory.

#IO density report
cd "F:\babyftp\Scripts\HGG_WFA_Integration"
$naboxip="192.168.121.154"
$Protocol="https"
$Port="443"
$ItemToReport="volume"
$Period="7d"
$NetAppDetailsCSVFile=".\IODensityDetails.csv"
#>

#########################################################################
#
# Script to create an IODensity Report from Graphite Database (read: from nabox)
# Version: 1.2
# 09-14-2017
# Marc Ferber NetApp
#
#########################################################################

param (
	[parameter(Mandatory=$false, HelpMessage="nabox instance IP")]
	[string]$naboxip,
	
	[parameter(Mandatory=$false, HelpMessage="Protocol to be used to connect the nabox graphite server")]
	[ValidateSet("http", "https")] 
	[string]$Protocol="https",

	[parameter(Mandatory=$false, HelpMessage="Port to be used to connect the nabox graphite Server")]
	[ValidateRange(1,65535)] 
	[int]$Port="443",
	
	[parameter(Mandatory=$false, HelpMessage="Item to report on to be choosen between: volume, lun")]
	[ValidateSet("volume", "lun")]
	[string]$ItemToReport="volume",
	
	[parameter(Mandatory=$false, HelpMessage="Period to look at. Default 7 Days")]
	[string]$Period="7d",
	
	[parameter(Mandatory=$false, HelpMessage="comma separated list of NetApp to include in the IO density report if not using the csv entries")]
	#[parameter(ParameterSetName="seta")]
	[string]$NetAppSelection,
	
	[parameter(Mandatory=$false, HelpMessage="CSV File containing all the controlers information if not provided by using NetAppSelection")]
	#[parameter(ParameterSetName="setb")]
	[string]$NetAppDetailsCSVFile,

	[parameter(Mandatory=$false, HelpMessage="Do we want to exclude the root volumes..")]
	[switch]$ExcludeRootVol,
	
	[parameter(Mandatory=$false, HelpMessage="Do we want to exclude the MDVs volumes..")]
	[switch]$ExcludeMDVVol,
	
	[parameter(Mandatory=$false, HelpMessage="Get the script version..")]
	[switch]$ShowVersion
)

# CSV file column should be done this way:
# First Line should contain this text: NetApp,MgmtIP,Account,Password,Encrypted
# Column 1: Controler/cluster Name
# Column 2: Management IP
# Column 3: Admin Account
# Column 4: Password (if empty password will be asked on run)
# Column 5: Password is in clear text=0 ; Encrypted password=1 (created using: read-host -assecurestring | convertfrom-securestring) 
# Example of file content:
#
# NetApp,MgmtIP,Account,Password,Encrypted
# MyNetApp1,192.168.0.11,root,NetApp123,0
# MyNetApp2,192.168.0.15,admin,,0
# MyNetApp3,192.168.0.19,admin,01000000d08c9ddf0115d1118c7a00c04fc297eb010000001e74617e62df5946952183ea7f531047000000000200000000001066000000010000200000006b8f3e685fe6750526023e10183ae772edce05528a647ca13643017d698d94c0000000000e800000000200002000000063b1fdacf2dc243777d9668345c3009a56d024fb9eb20e9a8be00c3cdc7b30a320000000c3a8c010db47a17e72de4ded5f9e502676d62e47aaca1d2bc3ed73b85c1b98fe400000001e3e91192dc2a0bdd1ec44f89ca398f54c04ff77998ace13730599937bc4b7dd7e94a50b637dbe5e74a45604679650996e8815c7373e6e10056c4d41c3938944,1
#
# ==> First NetApp :everything is provided in cleartext
# ==> Second NetApp :Password is not provided : it will be asked during script execution
# ==> Third NetApp :Password is provided encrypted.
#
# Note : an easy method is to put the password in clear text in the file, run the script and answers y when asked to overwrite the file with encrypted password.
#
cls

$ScriptVersion="1.2.0"
if ($ShowVersion.IsPresent)
{
    Write-Host "==> Current script version is: $ScriptVersion" -ForegroundColor green
    Write-Host "==> Download updates at: https://github.com/netappguy/Harvest_grafana_graphite" -ForegroundColor green
    Exit
}

if (!($naboxip))
{
	$naboxip=read-host -Prompt "Enter the nabox IP address"
}

# Check the Powershell version. We need at least V3.
write-host "Checking Powershell Version: " -NoNewline
if ($PSVersionTable.PSVersion.Major -lt 4)
{
	write-host ":NOK" -ForegroundColor red
	throw "You need at least powershell version 4 to execute this script. Exiting"
}
write-host "OK" -ForegroundColor green

# Load the DataONTAP Module if not already done.
write-host "Checking DataONTAP module: " -NoNewline
if (!(Get-Module DataONTAP))
{
	if (Get-Module -ListAvailable | Where-Object { $_.name -eq "DataONTAP" })
	{
		Import-Module DataONTAP
	}
	else
	{
		write-host ""
		throw "DataONTAP Module not found. Exiting !"
	}
}
write-host "OK" -ForegroundColor green

write-host "Checking Protocol: " -NoNewline
if ($Protocol -eq "https")
{
#Solve certificate issue with powershell no character should be inserted before each line !
$TAllCPolicy = @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem) {
return true;
}
}
"@
Add-Type -TypeDefinition $TAllCPolicy
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}
write-host "OK" -ForegroundColor green

write-host "Grabbing Graphite Inventory: " -NoNewline
if (!(Test-Connection $naboxip -Count 1 -Quiet))
{
	write-host "NOK" -ForegroundColor red
	throw "Error getting inventory from graphite server... Server not responding !"
}

#Grabbing nabox monitored storage list.
$URI=$Protocol + "://" + $naboxip + ":" + $Port + "/graphite/"
$Global:NetAppInstances=Invoke-WebRequest -usebasicparsing -Uri ($URI + "metrics/find?query=netapp.perf.*.*") -TimeoutSec 30 -ErrorAction Stop | ConvertFrom-Json
$Global:NetAppInstances+=Invoke-WebRequest -usebasicparsing -Uri ($URI + "metrics/find?query=netapp.perf7.*.*") -TimeoutSec 30 -ErrorAction Stop | ConvertFrom-Json
if ($Global:NetAppInstances)
{
	write-host "OK" -ForegroundColor green
}
else
{
	write-host "NOK" -ForegroundColor red
	throw "Error: no inventory!"
}

#Define the Counters we need from Graphite with their IODensity report equivalance
write-host "Defining needed counters: " -NoNewline
#,"other_latency","other_ops"
$GraphiteCounters=@()
$Prop = New-Object PSObject
$Prop | Add-Member -type NoteProperty -Name 'avg_latency' -Value "Latency (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'read_data' -Value "Read Throughput (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'read_latency' -Value "Read Latency (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'read_ops' -Value "Read IOPS (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'total_data' -Value "Throughput (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'total_ops' -Value "IOPS (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'write_data' -Value "Write Throughput (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'write_latency' -Value "Write Latency (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'write_ops' -Value "Write IOPS (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'Mode' -Value "Classic"
$GraphiteCounters+=$Prop
$Prop = New-Object PSObject
$Prop | Add-Member -type NoteProperty -Name 'avg_latency' -Value "Latency (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'read_data' -Value "Read Throughput (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'read_latency' -Value "Read Latency (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'read_ops' -Value "Read IOPS (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'total_data' -Value "Throughput (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'total_ops' -Value "IOPS (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'write_data' -Value "Write Throughput (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'write_latency' -Value "Write Latency (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'write_ops' -Value "Write IOPS (Avg)"
$Prop | Add-Member -type NoteProperty -Name 'Mode' -Value "Cluster"
$GraphiteCounters+=$Prop
write-host "OK" -ForegroundColor green

$GetGraphiteData = {
    Param (
		[string]$Volume
	)
	$ProgressPreference='SilentlyContinue'
	$GraphiteMetric=$global:IODensity| where {$_.Volume -ceq $Volume}
	#foreach ($GraphiteMetric in $global:IODensity)
	#{
	#	if ($GraphiteMetric.Volume -eq $Volume)
	#	{
			$fromfor=$GraphiteMetric.'Data Center'.Split("/")[0]
			$Mode=$GraphiteMetric.'Data Center'.Split("/")[1]
			$GraphiteMetric.'Data Center'="N/A"
			$GraphiteURI=$GraphiteMetric.'Storage Tier'
			$GraphiteMetric.'Storage Tier'="N/A"
			#$Counters=$GraphiteCounters | where {$_.Mode -eq $Mode}
			#$Counters.PSOBject.Properties.Remove('Mode')
			
			foreach ($Counter in $((($GraphiteCounters |where {$_.Mode -eq $Mode}).PSObject.Properties).Name | where {$_ -ne "Mode"}))
			{
				$TmpDataPoints=Invoke-WebRequest -usebasicparsing -Uri $($GraphiteURI + "." + $Counter + $fromfor)
				[void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")        
				$jsonserial= New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer 
				$jsonserial.MaxJsonLength = [int]::MaxValue
				$TargetDataPoints = $jsonserial.DeserializeObject($TmpDataPoints)
				if ($TargetDataPoints.count -gt 0)
				{
					foreach ($TargetDataPoint in $TargetDataPoints)
					{
						
						$perfs=@()
						foreach ($DataPoint in $TargetDataPoint.datapoints)
						{
							if ($DataPoint[0] -ne $null)
							{
								$val=$DataPoint[0]
								$tmestp=$DataPoint[1].ToString()
								$Prop = New-Object PSObject
								$Prop | Add-Member -type NoteProperty -Name 'val' -Value $val
								$Prop | Add-Member -type NoteProperty -Name 'tmestp' -Value $tmestp
								$perfs+=$Prop
							}
						}
					}

					$perfStats=$perfs.val | Measure-Object -Minimum -Maximum -Average
					$GraphiteMetric.$(($GraphiteCounters |where {$_.Mode -eq $Mode}).$counter)=[math]::ceiling($perfStats.Average)
					#write-host "$volume $counter "$GraphiteMetric.$($counters.$counter)
					if ($Counter -eq "avg_latency")
					{
						$GraphiteMetric.'Latency (Peak)'=[math]::ceiling($perfStats.Maximum)
					}
					if ($Counter -eq "total_ops")
					{
						$GraphiteMetric.'IOPS (Peak)'=[math]::ceiling($perfStats.Maximum)
					}
				}
			}
			if ($GraphiteMetric.'Used (TB)' -ne 0)
			{
				#I/O Density (Avg) ??????
				$GraphiteMetric.'I/O Density (Avg)'=[math]::ceiling($GraphiteMetric.'IOPS (Avg)'/$GraphiteMetric.'Used (TB)')
				#I/O Density (Peak) = IOPS (Peak) / Used (TB)
				$GraphiteMetric.'I/O Density (Peak)'=[math]::ceiling($GraphiteMetric.'IOPS (Peak)'/$GraphiteMetric.'Used (TB)')
			}
			#Block Size (Avg KB/IOPS) = Throughput (Avg) IN KB / IOPS (Avg)
			if ($GraphiteMetric.'IOPS (Avg)' -ne 0)
			{
				$GraphiteMetric.'Block Size (Avg KB/IOPS)'=$GraphiteMetric.'Throughput (Avg)'*1024/$GraphiteMetric.'IOPS (Avg)'
			}
		#}
	#}
}

function Show-Menu
{
	param (
	[string]$Title = 'NetApp Selection (list generated from Graphite Database)'
	)
	$Title = "================ $Title ================"
    cls
	Write-host $("=" * $Title.length)
	Write-host "| Graphite URI: " -NoNewLine
	Write-host $URI -ForeGroundColor green
    Write-Host $Title
	Write-Host ""
    $i=0
	foreach ($NetApp in $Global:NetAppInstances)
	{
		if ($NetApp.allowChildren -eq "1")
		{
			$Check="X"
			$option="un"
		}
		else
		{
			$Check=" "
			$option=""
		}
		Write-Host "[" -NoNewLine
		Write-Host $Check -NoNewLine -ForeGroundColor Yellow
		Write-Host "] " -NoNewLine
		Write-Host $NetApp.text -NoNewLine -ForeGroundColor Green
		Write-Host ": Press '" -NoNewLine
		Write-Host $i -NoNewLine -ForeGroundColor Yellow
		Write-Host "' to ${option}select this NetApp."
		$i++
	}
	Write-Host ""
	Write-Host "Press 'A' to select all NetApp."
	Write-Host "Press 'N' to select none."
    Write-Host "Press 'L' to launch the report for the selected NetApp."
	Write-Host "Press 'Q' to quit."
	Write-Host ""
}

if (($NetAppSelection) -and ($NetAppDetailsCSVFile))
{
	throw "you cannot use both NetAppSelection and NetAppDetailsCSVFile switch at the same time ! exiting"
}
$SelectionnedNetApps=@()
$global:IODensity=@()

#Create-TheMatrixNeo -NetApp $NetAppDetails[2].NetApp -NetAppMgmtIP $NetAppDetails[2].MgmtIP -AdminAccount $NetAppDetails[2].Account -Password $NetAppDetails[2].Password
function Create-TheMatrixNeo
{
	param (
		[string]$NetApp,
		[string]$NetAppMgmtIP,
		[string]$AdminAccount,
		[string]$Password
	)
	
	write-host "Grabbing information for: " -NoNewline
	write-host $NetApp -ForegroundColor green 
	$NetAppInstance=$Global:NetAppInstances | where {$_.text -eq $NetApp }
	$secstr = $Password | ConvertTo-SecureString
	$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $AdminAccount, $secstr
		#(Get-Credential -Message $("Credential to access " + $NetApp.Netapp))
	$connection=Connect-NaController $NetAppMgmtIP -Credential $cred -ErrorAction Stop
	# Cluster (cDOT) or Classic (7-mode)
	$perfURIs=@()
	if ($connection.Mode -eq "Classic")
	{
		$SysInfos=Get-Nasysteminfo
		$Ontap=Get-NaSystemVersion
		write-host $(" ==> " + $Ontap) -ForegroundColor yellow 
		if ($Global:ExcludeRootVol.IsPresent)
		{
			$VolRoot=(get-navolroot).Name
			$Volumes=get-navol | where {$_.Name -ne $VolRoot}
		}
		else
		{
			$Volumes=get-navol
		}
		$disks=get-nadisk | where {$_.Aggregate -ne $null}
		$Luns=Get-NaLun
		$SnapMirrors=Get-NcSnapmirror
		$SnapMirrorsDest=Get-NcSnapmirrorDestination
		
		$VolURIs=(Invoke-WebRequest -usebasicparsing -Uri ($URI + "metrics/find?query=" + $NetAppInstance.id + ".vol.*") | ConvertFrom-Json).id
		foreach($volume in $volumes)
		{
			$CheckVol=$NetAppInstance.id + ".vol." + $volume.Name
			if ($volURIs -contains $CheckVol)
			{
				$Prop = New-Object PSObject
				$Prop | Add-Member -type NoteProperty -Name 'Storage Tier' -Value $($URI + "render?target=" + $CheckVol)
				$Prop | Add-Member -type NoteProperty -Name 'Data Center' -Value $("&format=json&from=-" + $Period + "/" + $connection.Mode)
				$Prop | Add-Member -type NoteProperty -Name 'Virtualized' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Virtualizer Vendor' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Virtualizer Model' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Virtualizer Name' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Vendor' -Value "NetApp"
				$Prop | Add-Member -type NoteProperty -Name 'Model' -Value $sysinfos.SystemModel
				$Prop | Add-Member -type NoteProperty -Name 'Array' -Value $sysinfos.SystemName
				$Prop | Add-Member -type NoteProperty -Name 'Aggregate' -Value $($sysinfos.SystemName + ":" + $volume.ContainingAggregate)
				$Prop | Add-Member -type NoteProperty -Name 'Volume' -Value $($sysinfos.SystemName + ":" + $volume.OwningVfiler + ":" + $volume.Name)
				$Prop | Add-Member -type NoteProperty -Name 'Volume Type' -Value $volume.VolumeIdAttributes.Style
				if (($SnapMirrors).DestinationLocation -match (":" + $volume.Name + "$"))
				{
					$Prop | Add-Member -type NoteProperty -Name 'Destination Volume' -Value "TRUE"
				} else
				{
					$Prop | Add-Member -type NoteProperty -Name 'Destination Volume' -Value "FALSE"
				}
				if (($SnapMirrorsDest).SourceLocation -match (":" + $volume.Name + "$"))
				{
					$Prop | Add-Member -type NoteProperty -Name 'Source Volume' -Value "TRUE"
				} else
				{
					$Prop | Add-Member -type NoteProperty -Name 'Source Volume' -Value "FALSE"
				}
				$diskTypes=($disks | where {$_.Aggregate -eq $volume.Aggregate}).StorageDiskInfo.DiskInventoryInfo.DiskType | Select-Object -Unique
				if (@($diskTypes).count -eq 1)
				{
					$Flashpool="Disabled"
					$Prop | Add-Member -type NoteProperty -Name 'Disk Type' -Value $diskTypes
					if ($diskTypes -eq "SSD")
					{
						$Prop | Add-Member -type NoteProperty -Name 'Disk Speed' -Value ""
					}
					else
					{
						$Prop | Add-Member -type NoteProperty -Name 'Disk Speed' -Value $(($disks | where {$_.Aggregate -eq $volume.Aggregate}).StorageDiskInfo.DiskInventoryInfo.Rpm | Select-Object -Unique)
					}
				}
				else
				{
					#Flashpool ..
					$Prop | Add-Member -type NoteProperty -Name 'Disk Type' -Value $diskTypes | where {$_ -ne "SSD"}
					$Flashpool="Enabled"
					$Prop | Add-Member -type NoteProperty -Name 'Disk Speed' -Value $(($disks | where {$_.Aggregate -eq $volume.Aggregate -and $_.StorageDiskInfo.DiskInventoryInfo.DiskType -ne "SSD"}).StorageDiskInfo.DiskInventoryInfo.Rpm | Select-Object -Unique)
				}
				if (($Prop.'Disk Type' -eq "FSAS") -and ($Prop.'Disk Speed' -eq "7200"))
				{
					$Prop.'Disk Type'="SATA"
				}
				$Prop | Add-Member -type NoteProperty -Name 'Flash Pool' -Value $Flashpool
				if (($Luns | where {$_.Volume -eq $volume.Name}).count -eq 0)
				{
					$Prop | Add-Member -type NoteProperty -Name 'Access Type' -Value "NAS"
				}
				else
				{
					$Prop | Add-Member -type NoteProperty -Name 'Access Type' -Value "SAN"
				}
				$Prop | Add-Member -type NoteProperty -Name 'Read Latency (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Write Latency (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Latency (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Latency (Peak)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Read Throughput (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Write Throughput (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Throughput (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Read IOPS (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Write IOPS (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'IOPS (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'IOPS (Peak)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'I/O Density (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Block Size (Avg KB/IOPS)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'I/O Density (Peak)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Allocated (TB)' -Value $([math]::Round($volume.SizeTotal/1024/1024/1024/1024,3))
				$Prop | Add-Member -type NoteProperty -Name 'Used (TB)' -Value $([math]::Round(($volume.SizeUsed)/1024/1024/1024/1024,3))
				$global:IODensity+=$Prop
			}
		}
	}
	else
	{
		write-host "cDOT detected, changing the connection type (using Connect-NcController rather than Connect-NaController)" -ForegroundColor green
		$connection=Connect-NcController $NetAppMgmtIP -Credential $cred -WarningAction silentlyContinue
		$SysInfos=Get-NcNode
		$Ontap=(Get-NcSystemVersion).value
		write-host $(" ==> " + $Ontap) -ForegroundColor yellow 
		if ($Global:ExcludeRootVol.IsPresent)
		{
			$volumes=get-ncvol | where { $_.VolumeStateAttributes.IsNodeRoot -ne $true -and $_.VolumeStateAttributes.IsVserverRoot -ne $true }
		}
		else
		{
			$volumes=get-ncvol
		}
		if ($Global:ExcludeMDVVol.IsPresent)
		{
			$volumes=$volumes | where {$_.Name -notlike "MDV_???_*"}
		}
		$disks=get-ncdisk
		$Luns=Get-NcLun
		$Aggrs=Get-NcAggr
		$VolURIs=(Invoke-WebRequest -usebasicparsing -Uri ($URI + "metrics/find?query=" + $NetAppInstance.id + ".svm.*.vol.*") | ConvertFrom-Json).id
		foreach($volume in $volumes)
		{
			$CheckVol=$NetAppInstance.id + ".svm.*.vol." + $volume.Name
			if ($volURIs -contains $CheckVol)
			{
				$Aggr=$Aggrs| where {$_.Name -eq $volume.VolumeIdAttributes.ContainingAggregateName}
				$Node=$sysinfos | where {$_.Node -eq $Aggr.Nodes}
				$Prop = New-Object PSObject
				$Prop | Add-Member -type NoteProperty -Name 'Storage Tier' -Value $($URI + "render?target=" + $CheckVol)
				$Prop | Add-Member -type NoteProperty -Name 'Data Center' -Value $("&format=json&from=-" + $Period + "/" + $connection.Mode)
				$Prop | Add-Member -type NoteProperty -Name 'Virtualized' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Virtualizer Vendor' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Virtualizer Model' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Virtualizer Name' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Vendor' -Value "NetApp"
				$Prop | Add-Member -type NoteProperty -Name 'Model' -Value $Node.NodeModel
				$Prop | Add-Member -type NoteProperty -Name 'Array' -Value $NetApp
				$Prop | Add-Member -type NoteProperty -Name 'Aggregate' -Value $($Node.Node + ":" + $volume.VolumeIdAttributes.ContainingAggregateName)
				$Prop | Add-Member -type NoteProperty -Name 'Volume' -Value $($NetApp + ":" + $volume.Vserver + ":" + $volume.Name)
				$Prop | Add-Member -type NoteProperty -Name 'Volume Type' -Value $volume.VolumeIdAttributes.StyleExtended
				$Prop | Add-Member -type NoteProperty -Name 'Destination Volume' -Value "N/A"
				$Prop | Add-Member -type NoteProperty -Name 'Source Volume' -Value "N/A"
				$diskTypes=($disks | where {$_.Aggregate -eq $volume.Aggregate}).DiskInventoryInfo.DiskType | Select-Object -Unique
				if (@($diskTypes).count -eq 1)
				{
					$Flashpool="Disabled"
					$Prop | Add-Member -type NoteProperty -Name 'Disk Type' -Value $diskTypes
					if ($diskTypes -eq "SSD")
					{
						$Prop | Add-Member -type NoteProperty -Name 'Disk Speed' -Value ""
					}
					else
					{
						$Prop | Add-Member -type NoteProperty -Name 'Disk Speed' -Value $(($disks | where {$_.Aggregate -eq $volume.Aggregate}).DiskInventoryInfo.Rpm | Select-Object -Unique)
					}
				}
				else
				{
					#Flashpool ..
					$Prop | Add-Member -type NoteProperty -Name 'Disk Type' -Value $($diskTypes | where {$_ -ne "SSD"})
					$Flashpool="Enabled"
					$Prop | Add-Member -type NoteProperty -Name 'Disk Speed' -Value $(($disks | where {$_.Aggregate -eq $volume.Aggregate -and $_.DiskInventoryInfo.DiskType -ne "SSD"}).DiskInventoryInfo.Rpm | Select-Object -Unique)
				}
				if (($Prop.'Disk Type' -eq "FSAS") -and ($Prop.'Disk Speed' -eq "7200"))
				{
					$Prop.'Disk Type'="SATA"
				}
				$Prop | Add-Member -type NoteProperty -Name 'Flash Pool' -Value $Flashpool
				if (($Luns | where {$_.Vserver -eq $volume.Vserver -and $_.Volume -eq $volume.Name}).count -eq 0)
				{
					$Prop | Add-Member -type NoteProperty -Name 'Access Type' -Value "NAS"
				}
				else
				{
					$Prop | Add-Member -type NoteProperty -Name 'Access Type' -Value "SAN"
				}
				$Prop | Add-Member -type NoteProperty -Name 'Read Latency (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Write Latency (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Latency (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Latency (Peak)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Read Throughput (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Write Throughput (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Throughput (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Read IOPS (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Write IOPS (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'IOPS (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'IOPS (Peak)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'I/O Density (Avg)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Block Size (Avg KB/IOPS)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'I/O Density (Peak)' -Value 0.0
				$Prop | Add-Member -type NoteProperty -Name 'Allocated (TB)' -Value $([math]::Round($volume.VolumeSpaceAttributes.Size/1024/1024/1024/1024,3))
				$Prop | Add-Member -type NoteProperty -Name 'Used (TB)' -Value $([math]::Round(($volume.VolumeSpaceAttributes.SizeUsed+$volume.VolumeSpaceAttributes.SizeUsedBySnapshots)/1024/1024/1024/1024,3))
				$global:IODensity+=$Prop
			}
		}
	}	
}

if ($NetAppDetailsCSVFile)
{
	$overwrite=$false
	if (Test-Path $NetAppDetailsCSVFile)
	{
		$NetAppDetails=Import-Csv $NetAppDetailsCSVFile
	}
	else
	{
		throw "The provided csv file ($NetAppDetailsCSVFile) was not found. Exiting !"
	}
	foreach ($NetApp in $NetAppDetails)
	{
		if ($Global:NetAppInstances.text -contains $NetApp.Netapp)
		{
			$NetAppInstance=$Global:NetAppInstances | where {$_.text -eq $NetApp.Netapp }
			if ($NetApp.Password -eq "")
			{
				$NetApp.Password=read-host -Prompt $("Provide the password for '" + $NetApp.Account+ "' to access " + $NetApp.Netapp) -AsSecureString | convertfrom-securestring
				$NetApp.Encrypted="1"
				$overwrite=$true
			}
			else
			{
				if ($NetApp.Encrypted -eq "0")
				{
					$NetApp.Encrypted="1"
					$secstr = New-Object -TypeName System.Security.SecureString
					$NetApp.Password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
					$NetApp.Password=$secstr | convertfrom-securestring
					$overwrite=$true
				}
			}
			#write-host "Create-TheMatrixNeo -NetApp "$NetApp.NetApp" -NetAppMgmtIP "$NetApp.MgmtIP" -AdminAccount "$NetApp.Account" -Password "$NetApp.Password
			Create-TheMatrixNeo -NetApp $NetApp.NetApp -NetAppMgmtIP $NetApp.MgmtIP -AdminAccount $NetApp.Account -Password $NetApp.Password
		}
	}
	if ($overwrite)
	{
		$answer=read-host -Prompt "Do you want to overwrite the $NetAppDetailsCSVFile file with the new encrypted data ? [Y] or [N]"
		if ($answer -eq "Y")
		{
			$NetAppDetails | Export-Csv $NetAppDetailsCSVFile -Force
		}
	}
}

if ($NetAppSelection)
{
	foreach ($NetApp in $NetAppSelection.split(","))
	{
		if ($Global:NetAppInstances.text -contains $NetApp)
		{
			$NetApp=$NetApp.Trim()
			$MgmtIP=read-host "Enter '"$NetApp"' Management IP address"
			$AdminAccount=read-host "Enter '"$NetApp"' Admin account        "
			$Password=read-host -Prompt $("Enter '" + $AdminAccount + "' password for " + $Netapp + "    ") -AsSecureString | convertfrom-securestring 
			Create-TheMatrixNeo -NetApp $NetApp -NetAppMgmtIP $MgmtIP -AdminAccount $AdminAccount -Password $Password
		}
		else
		{
			write-host $NetApp" not found in Graphite Database ! skipping it.." -ForegroundColor red
		}
	}
}
else
{
	if (!($NetAppDetailsCSVFile))
	{
		do
		{
			Show-Menu
			$key = Read-host "Enter your selection: "
			switch -regex($key)
			{
				"^([0-9]?[0-9])$" {
					if (@($global:NetAppInstances).count -gt [int]$key)
						{
							[int]$selection=$key
							if ($global:NetAppInstances[$selection].allowChildren -eq "1")
							{
								$global:NetAppInstances[$selection].allowChildren="0"
							}
							else
							{
								$global:NetAppInstances[$selection].allowChildren="1"
							}
						}
						break;
				}
				"a" {
					foreach ($Netapp in $global:NetAppInstances)
						{
							$Netapp.allowChildren="1"
						}
						break;
				}
				"n" {
					foreach ($Netapp in $global:NetAppInstances)
						{
							$Netapp.allowChildren="0"
						}
						break;
				}
				"q" {
					return
				}
				"l" {
					break
				}
			}
			pause
		}
		until ($key -eq 'q' -or $key -eq 'l')

		if ($key -eq "q") { exit 1 }
		
		foreach ($NetApp in (($Global:NetAppInstances | where {$_.allowChildren -eq "1"}).text))
		{
			$NetApp=$NetApp.Trim()
			Write-Host "Enter '" -NoNewLine
			Write-Host $NetApp -NoNewLine -Foregroundcolor green
			Write-Host "' Management IP address" -NoNewLine -Foregroundcolor Yellow
			Write-Host "  : " -NoNewLine
			$MgmtIP=read-host 
			Write-Host "Enter '" -NoNewLine
			Write-Host $NetApp -NoNewLine -Foregroundcolor green
			Write-Host "' Admin account" -NoNewLine -Foregroundcolor Yellow
			Write-Host "          : " -NoNewLine
			$AdminAccount=read-host
			Write-Host "Enter '" -NoNewLine
			Write-Host $AdminAccount -NoNewLine -Foregroundcolor green
			Write-Host "' password for '"-NoNewLine -Foregroundcolor Yellow
			Write-Host $Netapp -NoNewLine -Foregroundcolor green
			Write-Host "'    : " -NoNewLine
			$Password=read-host -AsSecureString | convertfrom-securestring 
			Create-TheMatrixNeo -NetApp $NetApp -NetAppMgmtIP $MgmtIP -AdminAccount $AdminAccount -Password $Password
		}
	}
}
write-host "Calculating optimum number of thread...: " -NoNewline
$MaxThreads=((Get-WmiObject -class Win32_processor).NumberOfLogicalProcessors | Measure-Object -sum).sum*2
Write-host "Will use $MaxThreads Threads" -ForegroundColor Magenta
$StopWatch = New-Object System.Diagnostics.Stopwatch
$StopWatch.Start()
$sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
$sessionstate.Variables.Add(
    (New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry('IODensity', $IODensity, $null))
)
$sessionstate.Variables.Add(
    (New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry('GraphiteCounters', $GraphiteCounters, $null))
)

$Global:RunspaceCollection = @()
[Collections.Arraylist]$Results = @()

$RunspacePool = [RunspaceFactory ]::CreateRunspacePool(1, $MaxThreads,$sessionstate, $Host)
$RunspacePool.Open()

foreach ($vol in $global:IODensity.volume)
{
	write-host "Opening new Thread for volume: " -NoNewline
	write-host $vol -ForegroundColor Green
	$Powershell = [PowerShell]::Create().AddScript($GetGraphiteData).AddParameter("Volume",$vol)
	$Powershell.RunspacePool = $RunspacePool
	#New-Object PSObject -Property 
	$Global:RunspaceCollection += @{
		Handle = $PowerShell.BeginInvoke()
		PowerShell = $PowerShell  
	} 
	$process++
}


$totalJob=($Global:RunspaceCollection.handle).count
#write-host "Estimated completion time is: " -NoNewline
#write-host "~ "$($totalJob*0.28*$MaxThreads)" sec" -ForegroundColor Magenta
$arr=$Global:RunspaceCollection.Handle.IsCompleted
$Done=$False

Do {
	
	# Just a simple ForEach loop for each Runspace to get resolved
	Foreach ($Runspace in $Global:RunspaceCollection) {
		
		# Here's where we actually check if the Runspace has completed
		If ($Runspace.Handle.IsCompleted) {
			
			# Since it's completed, we get our results here
			$results+=$Runspace.PowerShell.EndInvoke($Runspace.Handle)
			
			# Here's where we cleanup our Runspace
			$Runspace.PowerShell.Dispose()
			#$Global:RunspaceCollection.remove($Runspace)
			$Runspace=$null
			$Done=$True
		} #/If
	} #/ForEach
	
	$complete=($Global:RunspaceCollection.handle | where {$_.IsCompleted -eq $true }).count
	$elapsed=[int]($StopWatch.Elapsed).TotalSeconds
	write-host "`rJob completed : $complete / $totalJob (MaxThread: $MaxThreads | Elapsed in sec.: $elapsed)" -NoNewline
	If ($Global:RunspaceCollection.Handle.IsCompleted -contains $false) {$Done=$False} Else {$Done=$True}
} Until ($Done)

$TMSTAMP=get-date -Format "yyyyMMddHHmm"
write-host ""
write-host "Saving result in: " -NoNewline
write-host $(".\IODensityReport_" + $TMSTAMP + ".csv") -ForegroundColor Green
$global:IODensity | Export-Csv $(".\IODensityReport_" + $TMSTAMP + ".csv")

write-host ""
$RunspacePool.Close() | Out-Null
$RunspacePool.Dispose() | Out-Null
$Global:RunspaceCollection.Clear() | Out-Null
$elapsed=[int]($StopWatch.Elapsed).TotalSeconds
write-host "Script executed in: " -NoNewLine
write-host $elapsed -NoNewLine -ForeGroundColor Green
write-host " sec"
$StopWatch.Stop()

<#
$Volumes=@()
foreach ($NetApp in ($global:NetAppList | where {$_.Selected -eq "1"}))
{
	if ($NetApp.Mode -eq "Classic")
	{
		$perfTree=""
	}
	$TmpVolList=Invoke-WebRequest -usebasicparsing -Uri ($NetApp.URI + "*") | ConvertFrom-Json
	$Volumes=$Volumes + $TmpVolList
	$connect=Connect-NaController 192.168.121.175 -Credential(Get-Credential)
}

foreach ($volume in $Volumes)
{
	$VolumeStats=@()
}


7-Mode:


wv_fsinfo_blks_used


select * from cm_storage.aggregate aggr,cm_storage.disk_aggregate dska,cm_storage.disk disk
where aggr.id=dska.aggregate_id
and disk.id=dska.disk_id;
select * from cm_storage.volume;

#>
