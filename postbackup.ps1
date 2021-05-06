<# 
.SYNOPSIS
	Postbackup script that removes the temporary restored SimpliVity Backup VMs restored on the DR/Central site
	(c) Thomas Beha, May 2019
.DESCRIPTION
	This script will do the following tasks:
		1. removes the temporary restored SimpliVity Backup VMs restored on the DR/Central site 
.NOTES
	Paramters are given as a XML-File that was created with the createXMLbackupfile.ps1 script.
	
	Requirements:
		SimpliVity RestAPI powershell commands: OmniStack.Cmds.psm1
		VMware powercli

	Please note: 

.SYNTAX
	powershell.exe  <prebackup.ps1> <configuration-file.xml> 

.RETURNVALUE
	none

.EXAMPLE
	powershell.exe c:\temp\prebackup.ps1 c:\temp\prebackup.xml
#>
param( $xmlfile )
<# Example XML file
<?xml version="1.0"?>
<!-- Prebackup Resource Pool Parameter File -->
<!-- Thomas Beha -->

<ScriptInputs>
  <VMtoBackup id="TBvbackupTest" destination="DR" retention="60" restore="SuperCruise" restoreTag="DC1"></VMtoBackup>
  <VMtoBackup id="Contrail" destination="DR" retention="60" restore="SuperCruise" restoreTag="DC1"></VMtoBackup>
  <VMtoBackup id="Concorde" destination="DR" retention="60" restore="SuperCruise" restoreTag="DC1"></VMtoBackup>
  <VMtoBackup id="FirrstStrike" destination="DR" retention="60" restore="SuperCruise" restoreTag="DC1"></VMtoBackup>
  <VMtoBackup id="Flare" destination="DR" retention="60" restore="SuperCruise" restoreTag="DC1"></VMtoBackup>
  <VMtoBackup id="LinuxFileServer" destination="DR" retention="60" restore="SuperCruise" restoreTag="DC1"></VMtoBackup>
  <OVC id="10.0.40.10"> </OVC>
  <VCENTER id="10.0.40.15"> </VCENTER>
  <Username id="username"></Username>
  <Password id="76492d1116743f04"></Password>
  <VeeamPool id="VeeamBackup"></VeeamPool>
</ScriptInputs>
#>
Import-Module -Name "c:\posh\SimpliVity-PS-Cmdlets.psm1"
Import-Module -Name "C:\Program Files (x86)\VMware\Infrastructure\PowerCLI\Modules\VMware.VimAutomation.Core"


try
{
	$Key = Get-Content ("C:\posh\veeam\veeam.key") -ErrorAction Stop
}
Catch
{
}

#[xml] $xml = (get-content "C:\posh\veeam\ResourcePool.lIN.xml")
[xml] $xml = (get-content $xmlfile)

$VMs  = ($xml.GetElementsByTagName("VMtoBackup"))
$ovc = ($xml.GetElementsByTagName("OVC")).id
$vcenter = ($xml.GetElementsByTagName("VCENTER")).id
$veeam_pool = ($xml.GetElementsByTagname("VeeamPool")).id

$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($xml.GetElementsByTagName("Username")).id , (($xml.GetElementsByTagName("Password")).id | ConvertTo-SecureString -Key $Key)


function ConnectvCenter
{
 	<#
	.SYNOPSIS
		Connect to the vCenter server
	.DESCRIPTION
		This function opens a connection to the vCenter server
	
	.NOTES
		Parameters:
			$vCenter:  FQDN or IP address of the vCenter server 
			$Username: Username
			$Password: Password
	.SYNTAX
		$response = Connect-vCenter -vCenter $vcenter -Username $user -Password $password
	.RETURNVALUE
		VIServer Object (https://www.vmware.com/support/developer/PowerCLI/PowerCLI651/html/VIServer.html)
	.EXAMPLE
		Connect-vCenter -vCenter 192.168.1.1 -Username administrator@vsphere.local -Password password
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]
        [string]$vCenter,
        [string]$Username,
        [string]$Password
	) 

	#Disconnect any existing vCenter connections
	Try
	{
	    Disconnect-VIServer * -Force -Confirm:$False
	}
	Catch
	{
	    # Nothing to do - no open connections!
	}

    $response = Connect-VIServer -Server $vCenter -Protocol https -User $Username -Password $Password
    log "Connected to vCenter: $response.Name"
}

function DisconnectvCenter
{
	<#
	.SYNOPSIS
		Disconnects from the current vCenter server
	.DESCRIPTION
		Disconnects from the current vCenter server without asking for any confirmation
	.NOTES
		No Parameters
	.SYNTAX
		Disconnect-vcenter
	.RETURNVALUE
		None	
	.EXAMPLE
		Disconnect-vcenter	
	#>
	Disconnect-VIServer * -Force -Confirm:$false
}

function RemoveVMs
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Checks whether a VM exists on the current vCenter and remove the VM if it exists
	.NOTES
		Parameters
			$VMname VM name 
	.SYNTAX
		$response = Check-VM-Existence -VMname $vmname
	.RETURNVALUE
		None
	.EXAMPLE
		$response = Ceck-VM-Existence -VMname "DemoVM"
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]
        [string]$VMname
	) 

    $response = Get-VM -Name $VMname
    if($response){
        log "VM $VMname exists and will be deleted"
        $response = Remove-VM -VM $VMname -DeletePermanently -Confirm:$false
    }   
}


function log
{
	[CmdletBinding()]
	param(
		[Parameter(mandatory=$true)]
            [string] $Value
	)   
    process{
        Add-Content -path $backuplog -Value $Value
        Write-Host $Value
    }
}

$date = (Get-Date -format yyyy-MM-dd-hh-mm-ss)
$logname = "SVT-Veeam-PostBackup-"+$date+".log"
$backuplog = "C:\posh\Veeam\Logfiles\"+$logname
new-item -path $backuplog -ItemType File -Force


# Open a connection to the OVC RestAPI
log "Get OmniStack Connection..."
ConnectOmniStack -Server $ovc -IgnoreCertReqs -OVCusername $MyCredential.GetNetworkCredential().UserName -OVCpassword $MyCredential.GetNetworkCredential().Password
# Open a connection to the vCenter
log "Open vCenter Connection ..."
ConnectvCenter -vCenter $vcenter -Username $MyCredential.GetNetworkCredential().UserName -Password $MyCredential.GetNetworkCredential().Password

# Work the list VMs
# <VMtoBackup id="TBvbackupTest" destination="DR" retention="60" restore="SuperCruise" restoreTag="DC1"></VMtoBackup>

log "$VMs.Count VMs to backup"
foreach($vm in $VMs)
{
	# Define the name of the restore VM
	$restorename = $vm.id + $vm.restoreTag
    log "Remove VM : $restorename"
	# Check if the VM already exists on this vCenter
	# if yes, delete the old VM before you attempt a restore

	RemoveVMs -VMname $restorename
}
# Disconnect from vCenter
DisconnectvCenter
#>
