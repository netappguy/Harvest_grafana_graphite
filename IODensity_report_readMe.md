This script create an IO Density report from Graphite data, that can be used for the SDW.

Information on running PowerShell scripts can be found here, as the SaaS methodology TR:
    * http://ss64.com/ps/syntax-run.html
    * https://technet.microsoft.com/en-us/library/bb613481.aspx
    * http://www.netapp.com/us/media/tr-4548.pdf

File Name:  IODensityReport.ps1
Version: 1.1 (Also reflected in -ShowVersion parameter)

Pre Requisite:

    -PowerShell version 4.0 or greater required (which requires .NET Framework 4.5 or greater be installed first)
    -PowerShell must be preferably launched "Run as Administrator"
    -NetApp PowerShell Toolkit 3.2.1 or newer: http://mysupport.netapp.com/NOW/download/tools/powershell_toolkit/

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
