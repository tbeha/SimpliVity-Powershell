<# 
.SYNOPSIS
	Prebackup script that creates a SimpliVity Backup, followed by a SimpliVity Restore Operation 
	before the external backup software backs up the restored VM on the DR/Central site
	(c) Thomas Beha, April 2018
.DESCRIPTION
	This script will do the following tasks:
		1. Create a SimpliVity Backup (app-aware/VSS if possible) 
		2. Restore this backup in the remote cluster as a new VM (if the VM with the given name already exists, than this VM will first be deleted)
.NOTES
	Paramters are given as a XML-File that was created with the createXMLbackupfile.ps1 script.
	
	Requirements:
		SimpliVity RestAPI powershell commands: OmniStack.Cmds.psm1
		VMware powercli
		Veeam powershell snapin

	Please note: 
		a restore over an existing VM is not possible if this is not the VM that was the source of the backup used for the restore. 
		Hence, this script is checking if a target with the given VM name (Restore-VM parameter) already exists in the vCenter. If this is the case,
		than the existing VM will be deleted without any confirmation request before the restore takes place. 
		Another draw back of this approach is, that each restore creates a new VM with a new VMware VM-id. It is not clear whether the backup software can cope 
		with the different VM-id's properly (Veeam, cannot). 
	
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
Import-Module -Name "c:\posh\OmniStackCmds.psm1"
Import-Module -Name "C:\Program Files (x86)\VMware\Infrastructure\PowerCLI\Modules\VMware.VimAutomation.Core"

#[xml] $xml = (get-content "C:\posh\test.xml")

try
{
	$Key = Get-Content ("C:\Users\Administrator\AES.key") -ErrorAction Stop
}
Catch
{
}

[xml]$xml = (get-content $xmlfile)

$VMs  = ($xml.GetElementsByTagName("VMtoBackup"))
$ovc = ($xml.GetElementsByTagName("OVC")).id
$vcenter = ($xml.GetElementsByTagName("VCENTER")).id
$veeam_pool = ($xml.GetElementsByTagname("VeeamPool")).id
$VMs  = ($xml.GetElementsByTagName("VMtoBackup"))
$ovc = ($xml.GetElementsByTagName("OVC")).id


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
    Write-Host "Connected to vCenter: " $response.Name
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

function CheckVMExistence
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
        Write-Host "VM $VMname already exists and will be deleted before the next restore"
        $response = Remove-VM -VM $VMname -DeletePermanently -Confirm:$false
    }   
}


# Open a connection to the OVC RestAPI
Write-Host "Get OmniStack Connection..."
ConnectOmniStack -Server $ovc -IgnoreCertReqs -OVCusername $MyCredential.GetNetworkCredential().UserName -OVCpassword $MyCredential.GetNetworkCredential().Password
# Open a connection to the vCenter
Write-Host "Open vCenter Connection ..."
ConnectvCenter -vCenter $vcenter -Username $MyCredential.GetNetworkCredential().UserName -Password $MyCredential.GetNetworkCredential().Password

# Work the list VMs
# <VMtoBackup id="TBvbackupTest" destination="DR" retention="60" restore="SuperCruise" restoreTag="DC1"></VMtoBackup>

Write-Host $VMs.Count"VMs to backup"
foreach($vm in $VMs)
{
    Write-Host "Backup VM: " $vm.id
	# Get the last backup of the VM
	$bck = GetLastVMBackup -VMname $vm.id
    $Bkpid = $bck.id
	if(-Not $bck){
        Write-Host "No Backup of VM " $vm.id "available!"
        Write-Host "Create a Backup first!"
        # Initiate a SimpliVity Backup of the VM to backup
        # Use an app-aware/VSS backup if possible
        $backupname = BackupVM -VM $vm.id -Destination $vm.destination -Retention $vm.retention
        Write-Host "VM backup complet - Backupname: " $backupname
        # Get the backup id of the just completed backup
        $Bkpid = GetBackupID -Backupname $backupname
        Write-Host "   Backup ID: " $Bkpid
    }
	# Define the name of the restore VM
	$restorename = $vm.id + $vm.restoreTag

	# Check if the VM already exists on this vCenter
	# if yes, delete the old VM before you attempt a restore

	CheckVMExistence -VMname $restorename

	# Restore the backup
    Write-Host "Restore Backup " $Bkpid "of " $vm.id " to " + $vm.restore
	RestoreVM -Bkpid $Bkpid -Restorename $restorename -Datastore $vm.restore

	# Move the restored VM to the Veeam Backup Resource Pool 
    Write-Host "Move VM $restorename to $veeam_pool"
	Move-VM $restorename -Destination $veeam_pool

}
# Disconnect from vCenter
DisconnectvCenter
#>
