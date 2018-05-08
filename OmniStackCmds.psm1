<# 
.SYNOPSIS
	OmniStack powershell cmdlets
	(c) Thomas Beha, April 2018
.DESCRIPTION
	The cmdlets use the HPE SimpliVity 380 RestAPI: https://api.simplivity.com/
.NOTES
	The following functions are available:

	General Operations:
		ConnectOmniStack
		InvokeOmnistatckREST
		GetOmniStackTask
	Backup/Restore Operations
		BackupReport
		BackupVM
		GetBackupID
		RestoreVM
		DeleteBackup
	Cluster Operations
		GetOmniStackCluster
		GetClusterMetric
		GetClusterThrougput
	VM Operations
		GetOmniStackVM
		SetVMBackupPolicy
		GetVMMetric
	DataStore Operations
		GetOmniStackDataStore
		GetDataStoreId
		NewOmniStackDataStore
		RemoveOmniStackDataStore
		ResizeOmniStackDataStore
		SetOmniStackDataStorePolicy
	Backup Policy Operations
		GetBackupPolicy
		DefineBackupPolicy
		AddPolicyRule 
	Host Operartions
		GetHosts
		GetHostMetric
		GetHostCapacity

	The following functions are not yet fully tested:
		GetVMMetric
		AddPolicyRule
		GetHosts
		GetHostMetric
		GetHostCapacity
	
#>

<# Genereal operations #######################################################################>

function ConnectOmniStack
{
<#
.SYNOPSIS 
	Obtain the Oauth from SimpliVity OVC 
.DESCRIPTION
	Using credentials for the OVC of the Simplivity Controller
.NOTES
	Required parameter: (This will prompt for username and password input)
		-Server <IP Address of OVC>
		-IgnoreCertReqs <Self-signed SSL cert is accepted>
	Not required parameters: (This will bypass the prompt for username and password)
		-OVCusername <OVC username has admin rights to Federation>
		-OVCpassword <OVC password>
		-OVCcred <User generated credential as System.Management.Automation.PSCredential"
.SYNTAX
	PS> ConnectOmniStack -Server <IP Address of OVC>  
	PS> ConnectOmniStack -Server <IP Address of OVC> -OVCusername <username@domain> -OVCpassword <P@55w0rd>
	PS> ConnectOmniStack -Server <IP Address of OVC> -OVCcred <User generated Secure credentials>
.RETURNVALUE
	The Omnistack OAuth:
		{
		    "Server":  "https://10.20.4.161",
		    "Username":  "CLOUD\\Ron.Dharma",
		    "Token":  "31e39218-a2c3-407c-b4bf-7eb9d53e0d08",

		    "SignedCertificates":  false
		}
.EXAMPLE
	To generate a credential file that can be used for this API, please use the export-CLIXML and then reimport using import-CLIXML
	$MyCredentials=Get-Credential -Credential"CONTOSO\Username"| export-CLIXML C:\scriptforlder\SecureCredentials.XML
	
	This SecureCredentials can be read back as long as the import action is being done in the same host as export.
	This credentials can then passed as the -OVCcred 
	$MyCredentials=import-CLIXML C:\Scriptfolder\SecureCredentials.xml
#>
    [CmdletBinding()][OutputType('System.Management.Automation.PSObject')]

    param(
	    [parameter(Mandatory=$True,ValueFromPipeline=$True)]
	    [ValidateNotNullOrEmpty()]
	    [String]$Server,

	    [parameter(Mandatory=$false)]
	    [switch]$IgnoreCertReqs,
		[String]$OVCusername,
		[String]$OVCpassword,
		[System.Management.Automation.PSCredential]$OVCcred
    )


    if ($IgnoreCertReqs.IsPresent)
    {
       	if ( -not ("TrustAllCertsPolicy" -as [type])) {
Add-Type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy
            {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem)
                    {  return true; }
            }
"@
    	}
    
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
		[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $SignedCertificates = $false
    } else { 
		$SignedCertificates = $true 
	}

# Check if IP Address is a valid one
	$IsValid = ($Server -as [Net.IPAddress]) -as [Bool]
	If ( $IsValid -eq $false ) {
		Write-Error "$Server has invalid IP Address, please provide valid IP Address!"
		Break
	}

#Allow any of three in priority: $cred object, cleartext cred, and no credential at all.
	if ($OVCcred) {
		$cred = $OVCcred
	} elseif (($OVCusername) -and ($OVCpassword)) {	
		$secPasswd = ConvertTo-SecureString $OVCpassword -AsPlainText -Force
		$cred = New-Object System.Management.Automation.PSCredential ($OVCusername, $secPasswd)
	} else {
		$cred = $host.ui.PromptForCredential("Enter in your OmniStack Credentials", "Enter in your username & password.", "", "")
	}
    $username = $cred.UserName
    $pass_word = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))
    $uri = "https://" + $Server + "/api/oauth/token"
    $base64 = [Convert]::ToBase64String([System.Text.UTF8Encoding]::UTF8.GetBytes("simplivity:"))
    $body = @{username="$username";password="$pass_word";grant_type="password"}
    $headers = @{}
    $headers.Add("Authorization", "Basic $base64")
    $headers.Add("Accept", "application/json")
	try {
    	$response = Invoke-RestMethod -Uri $uri -Headers $headers -Body $body -Method Post
	} catch {
		Write-Error $_.Exception.Message
		if ($_.Exception.Response.STatusCode.value__) {
			$stream = $_.Exception.Response.GetResponseStream()
	        $reader = New-Object System.IO.StreamReader($stream)
	        $reader.BaseStream.Position = 0
			return $reader.ReadToEnd()	
		}
		exit
	} 
    $Global:OmniStackConnection = [pscustomobject]@{
        Server = "https://$($Server)"
    	OVCcred = $cred
        Token = $response.access_token
		UpdateTime = $response.updated_at
		Expiration = $response.expires_in
        SignedCertificates = $SignedCertificates
    }
	return $OmniStackConnection
}

function InvokeOmnistackREST
{
	<#
	.SYNOPSIS
		Invoke a RestAPI call to the SimpliVity cluster
	.DESCRIPTION
		
	.NOTES
		Required Parameters
			Uri      	RestAPI Uri
			Headers	  	RestAPI Call Header
			Method		RestAPI Methods (Put, Get)
		Optional Paramets
			Body		RestAPI Body
	.SYNTAX
		
	.RETURNVALUE
	
	.EXAMPLE
	
	#>
	[CmdletBinding()] [OutputType('System.Management.Automation.PSObject')]
	param(
		[parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.Object]$uri,
		[System.Collections.IDictionary]$headers,
		[string]$Method,
		[parameter(Mandatory=$false)]
		[System.object]$body
	)

	try {
	    $local_response = Invoke-RestMethod -Uri $uri -Headers $headers -Body $body -Method $Method
	} catch {
		if ($_.Exception.Message -match "401")
	    {   
		    $local_cred = $Global:OmnistackConnection.OVCcred
			$local_username = $local_cred.UserName
    		$local_Passwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($local_cred.Password))
			$local_uri = $($Global:OmniStackConnection.Server) + "/api/oauth/token"
			$local_body = @{username="$local_username";password="$local_Passwd";grant_type="password"}
		    $local_base64 = [Convert]::ToBase64String([System.Text.UTF8Encoding]::UTF8.GetBytes("simplivity:"))
		    $local_headers = @{}
		    $local_headers.Add("Authorization", "Basic $local_base64")
		    $local_headers.Add("Accept", "application/json")
		    $local_response = Invoke-RestMethod -Uri $local_uri -Headers $local_headers -Body $local_body -Method Post
			$Global:OmnistackConnection.Token = $local_response.access_token
			$header.Remove("Authorization")
            $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
            $local_response = Invoke-RestMethod -Uri $uri -Headers $headers -Body $body -Method $Method
	    } else {
			Write-Host -ForegroundColor Red $_.Exception.Message
			if ($_.Exception.Response.STatusCode.value__) {
				$local_stream = $_.Exception.Response.GetResponseStream()
		        $local_reader = New-Object System.IO.StreamReader($local_stream)
		        $local_reader.BaseStream.Position = 0
				$local_response = $local_reader.ReadToEnd() | convertfrom-json
			}
		}
	}
	if ($Method -match "[Pp]ost" -or $Method -match "[Dd]elete") {
		if (($_.Exception.Message -match "4[0-9][0-9]") -or ($local_response.task -eq $NULL) ) { 
			Write-Debug "Failed POST or DELETE" 
			return $local_response
		} else {
			do {
				$Task_response = GetOmniStackTask $local_response.task
				Write-Debug $Task_response.task.state
				Start-Sleep -Milliseconds 500
			} 	until ($Task_response.task.state -notmatch "IN_PROGRESS")
			return $Task_response
		}
	} else {
		return $local_response
	}
}

function GetOmniStackTask
{
<#
.SYNOPSIS 
	Pooling for completion of the REST API operation
.DESCRIPTION
	External function for polling completion of REST API
.NOTES
	Required parameter: TaskID.ID
	Required Variable: $OmniStackConnection.Token
.SYNTAX
	GetOmniStackTask
#>
    [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    	[psobject]$Task
    )

    $uri = $($Global:OmniStackConnection.Server) + "/api/tasks/" + $($Task.ID)
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
	$body = @{}
	$response = InvokeOmnistackREST -uri $uri -header $header -body $body -Method Get
	return $response
}

<# Backup Restore Operations ########################################################################>

function BackupReport
{
	<#
	.SYNOPSIS
		Get all backups of a SimpliVity federation for a given past time period
	.DESCRIPTION
		Generates a list of backups run during the last x hours
	.NOTES
		Required Parameters
			PastHours
		Optional Parameters
			VMname
			DSListOffset
			DSListLimit
	.SYNTAX
		$response = BackupReport -PastHours $hours [-DSListOffset 0 -DSListLimit 500]
	.RETURNVALUE
		None
	.EXAMPLE
		C:\posh> $response = Backup-Report -PastHours 24$
		C:\posh> $response.backups[0]

		virtual_machine_name                        : DevOps
		unique_size_bytes                           : 0
		expiration_time                             : 2018-05-08T16:00:01Z
		unique_size_timestamp                       : NA
		created_at                                  : 2018-05-08T10:00:01Z
		consistency_type                            : FAILEDVSS
		type                                        : POLICY
		omnistack_cluster_name                      : DR
		datastore_name                              : SuperCruise
		sent                                        : 0
		application_consistent                      : True
		virtual_machine_id                          : 0fc3500c-93a5-43d6-a816-21c3ce9abf2c
		size                                        : 1192566784
		virtual_machine_state                       : ALIVE
		name                                        : 2018-05-08T06:00:01-04:00
		datastore_id                                : 2d857b9c-4798-4faa-ad84-b0ac9c66f0dc
		compute_cluster_parent_hypervisor_object_id : a5ffac0e-5c77-4384-a339-b3557b2df266:Datacenter:datacenter-26
		compute_cluster_parent_name                 : BER
		hypervisor_type                             : VSPHERE
		id                                          : dfdf81b2-6bf1-40b6-b87e-d238666d8cca
		state                                       : PROTECTED
		omnistack_cluster_id                        : 16c7bc30-e6b0-420e-a7d0-b22b85229ed2
		virtual_machine_type                        : VM
#>
    [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$True)]
    	[string]$PastHours,
		[Parameter(Mandatory=$false,Position=2)]
		[int]$DSListOffset=0,
		[Parameter(Mandatory=$false,Position=3)]
		[int]$DSListLimit=500
    )
	
	process
	{

        # Get Date Back x Hours - Format Correctly for SVT REST API
        $yesterday = (get-date).AddHours(-$PastHours)
        $yesterday = $yesterday.ToUniversalTime()
        $createdafter = (get-date $yesterday -format s) + "Z"

        $header = @{}
        $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
        $header.Add("Accept", "application/json")

        $uri = $($Global:OmniStackConnection.Server) + "/api/omnistack_clusters" 
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get 

        For ($i=0; $i -lt [int]$response.count; $i++) {
            # Get Backups in OmniStack Cluster
            $uri = $($Global:OmniStackConnection.Server) + "/api/backups?show_optional_fields=false&omnistack_cluster_id=" + $response.omnistack_clusters[$i].id + "&created_after=" + $createdafter
            $bursp = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
            For ($d=0; $d -lt [int]$bursp.count; $d++) {
                $bursp.backups[$d] | Select virtual_machine_name, virtual_machine_state, created_at, type, state, expiration_time, datastore_name, consistency_type, omnistack_cluster_name | FT
            }
        }
		return $bursp
    }
}

function GetVMBackupList
{
	<#
	.SYNOPSIS
		Get all backups of a VM for a given past time period
	.DESCRIPTION
		Delivers the list of backups run during the last x hours
	.NOTES
		Required Parameters
			PastHours
			VMname
		Optional Parameters
			
	.SYNTAX
		$response = Get-VM-Backup-List -PastHours $hours -VMname $vmname
	.RETURNVALUE
		$bursp  - BackupMO Object (https://api.simplivity.com/rest-api-generated-docs/backupmo.html)
	.EXAMPLE
		$result = GetVMBackupList -PastHours 24 -VMname "Test"
		$vmane = $results.backups[0].virtual_machine_name
		$bkpid = $results.backups[0].id	
	#>

	[CmdletBinding()]
    param(
    	[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
		[string]$VMname,
		[Parameter(Mandatory=$false,ValueFromPipeline=$True)]
    	[string]$PastHours
    )

	process{

		$header = @{}
        $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
        $header.Add("Accept", "application/json")

		if($PastHours){
			# Get Date Back x Hours - Format Correctly for SVT REST API
			$yesterday = (get-date).AddHours(-$PastHours)
			$yesterday = $yesterday.ToUniversalTime()
			$createdafter = (get-date $yesterday -format s) + "Z"
			$uri = $($Global:OmniStackConnection.Server) + "/api/backups?show_optional_fields=false&virtual_machine_name=" + $VMname + "&created_after=" + $createdafter
		} else {
			$uri = $($Global:OmniStackConnection.Server) + "/api/backups?show_optional_fields=false&virtual_machine_name=" + $VMname
		}
		$response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
		return $response
	}
}

function GetLastVMBackup 
{
	<#
	.SYNOPSIS
		Retrieves the last backup of a VM
	.DESCRIPTION
		Delivers the information of the last backup of a VM
	.NOTES
		Required Parameters
			VMname
		Optional Parameters
			
	.SYNTAX
		$response = Get-Last-VM-Backup -VMname $vmname
	.RETURNVALUE
		$bursp  - BackupMO Object (https://api.simplivity.com/rest-api-generated-docs/backupmo.html)
	.EXAMPLE
		$result = GetVMBackupList -PastHours 24 -VMname "Test"
		$vmane = $results.backups[0].virtual_machine_name
		$bkpid = $results.backups[0].id	
	#>

	[CmdletBinding()]
    param(
    	[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
		[string]$VMname
    )

	process{
		$bck = GetVMBackupList -VMname $VMname
		$z = $bck.backups.created_at | sort descending
		$last_backup_time = $z[0]
		foreach($b in $bck.backups){
			if($b.created_at -eq $last_backup_time){
				$last_backup = $b
			}
		}
		return $last_backup
	}
}


function BackupVM 
{
	<#
	.SYNOPSIS
		Backup a VM on a SimpliVity cluster 
	.DESCRIPTION
		Using the SimpliVity backup to create a backup of a VM on a SimpliVity cluster. The backup can be local or remote backup.
		The retention period of this backup needs to be defined.
	.NOTES
		Required Parameters
			VM: VM name
			Retention: retention time in seconds
			Destination: backup destination cluster
	.SYNTAX
		BackupVM -VM $vmname -Retention $retention 
	.RETURNVALUE
		Backupname
	.EXAMPLE
		bname = backup-VM -VM $vmname -Retention $retention
	#>

    [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$True)]
    	[string]$VM,
        [string]$Retention,
        [string]$Destination
    )

    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $Header.Add("Accept", "application/json")

    #Get VM Id of Source VM
    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines?limit=1&show_optional_fields=true&name=" + $VM
    $results = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    $vmid = $results.virtual_machines.id
    $appaware = $results.virtual_machines.app_aware_vm_status 


    # Prepare backup parameters
    $date = Get-Date
    $date = $date.ToUniversalTime()
    $date = $date -replace '/',''
    $date = $date -replace ' ',''
    $backupname = $VM + $date
    $backupparams = @{}
    $backupparams.Add("backup_name", "$backupname")
    $backupparams.Add("destination_id", "$Destination")
    $backupparams.Add("retention", "$Retention")
    # Check if a App-aware backup is possible
    if( $appaware -eq "CAPABLE"){
        $backupparams.Add("app_consistent", "$true")
        $backupparams.Add("consistency_type", "VSS")
    }

    #Convert backupparams to json
    $backupjson = $backupparams | ConvertTo-Json

    #Add Content-Type for Json to headers
    $header.Add("Content-Type", "application/vnd.simplivity.v1.1+json")

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines/" + $vmid + "/backup"
    #Invoke-OmnistackREST -Uri $uri -Headers $header -Method Post -Body $backupjson
    try {
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Post -Body $backupjson 
    } catch {
        Write-Host "Backup Error: "  $_.Exception.Response.StatusCode.Value__
        exit 1
    }

    $header.Remove("Content-Type")

    return $backupname
}

function GetBackupID
{
	<#
	.SYNOPSIS
		Retrieve the SimpliVity backup ID 
	.DESCRIPTION
		Retrieves the SimpliVity backup ID for a backup with a given name
	.NOTES
		Required Parameter
			Backupname	the name of the backup
	.SYNTAX
		$bkpid = Get-Backup-ID -Backupname $bname
	.RETURNVALUE
		The backup ID
	.EXAMPLE
		$bkpid = GetBackupID -Backupname $backupname
	#>

  [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$True)]
    	[string]$Backupname
    )

    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $Header.Add("Accept", "application/json")

    $uri = $($Global:OmniStackConnection.Server) + "/api/backups?show_optional_fields=true&name=$Backupname"
    $result = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    $bkpid = $result[0].backups.id
    return $bkpid
}

function RestoreVM
{
	<#
	.SYNOPSIS
		Initiates a SimpliVity Restore VM command
	.DESCRIPTION
		This function restores a VM from a backup to new VM on a given datastore
	.NOTES
		Required Parameters:
			Bkpid:	ID of the backup that should be used for the restore operation
			Restorename: name of the newly restored VM
			Datastore: VMware datastore location for the restored VM
	.SYNTAX
		Restore-VM -Bkpid $id -Restorename $VMname -Datastore $datastore
	.RETURNVALUE
		none
	.EXAMPLE
		Restore-VM -Bkpid $backuptorestore -Restorename $restorename -Datastore $DestinationStore
	#>

 	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]
        [string]$Bkpid,
        [string]$Restorename,
        [string]$Datastore
	) 
    
    
    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")

    # Get the datastore id of the destination datastore
    $uri = $($Global:OmniStackConnection.Server) + "/api/datastores?show_optional_fields=true&name=$Datastore"
    $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    $dsid = $response[0].datastores.id

    # Create the body for the Restore Command
    $body = @{}
    $body.Add("datastore_id", "$dsid")
    $body.Add("virtual_machine_name", "$Restorename") 
    # Convert restore parameter to json
    $restorejson = $body | ConvertTo-Json

    # Check that the backup is in protected state
    $uri =  $($Global:OmniStackConnection.Server) + "/api/backups/" + $Bkpid
    $d = 0
    do {
    #for($d=0;$d -le 10; $d++){
        $d++
        $response = $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
        $backupstate = $response.backup.state
        if($backupstate -ne "PROTECTED"){
            Write-Host $d "Backup not yet ready (sleep 30s): " $backupstate 
            Start-Sleep 30
        } else {
            Write-Host "Backup ready: " $backupstate
            $d = 25
        }    
    } while(($backupstate -ne "PROTECTED") -and ($d -lt 20))

    #Add Content-Type for Json to headers
    $header.Add("Content-Type", "application/vnd.simplivity.v1.1+json")

    $uri = $($Global:OmniStackConnection.Server) + "/api/backups/" + $Bkpid + "/restore?restore_original=false"
    try{
        InvokeOmnistackREST -Uri $uri -Headers $header -Method Post -Body $restorejson
    } catch {
        Write-Host "Backup Error: "  $_.Exception.Response.StatusCode.Value__
        #DisconnectvCenter
        $header.Remove("Content-Type")
        exit 1
    }
    $header.Remove("Content-Type")
}

function DeleteBackup
{
	<#
	.SYNOPSIS
		Deletes a Backup
	.DESCRIPTION
		This function the backup with Backup ID Bkpid
	.NOTES
		Required Parameters:
			Bkpid:	ID of the backup that should be used for the restore operation
	.SYNTAX
		DeleteBackup -Bkpid $id 
	.RETURNVALUE
		none
	.EXAMPLE
		DeleteBackup -Bkpid $bckid
	#>

 	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]
        [string]$Bkpid
	) 

    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")

	$uri = $($Global:OmniStackConnection.Server) + "/api/backups/" + $Bkpid

	try{
        InvokeOmnistackREST -Uri $uri -Headers $header -Method Delete
    } catch {
        Write-Host "Delete Backup Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
}

<# Cluster operations ###########################################################################>
function GetOmniStackCluster
{
	<#
	.SYNOPSIS
		Retrieve all instance of SimpliVity Clusters that are defined on this system
	.DESCRIPTION
		Delivers the list of SimpliVity cluster
	.NOTES
		Required Parameters
			
		Optional Parameters
			clustername: Clustername
	.SYNTAX
		$response = Get-OmniStackCluster [-clustername $clustername]
	.RETURNVALUE
		$cluster  - OmniStack Cluster Object (https://api.simplivity.com/rest-api-generated-docs/omnistack_cluster.html)
	.EXAMPLE
		$response = GetOmniStackCluster
		$cluster0_name = $response.omnistack_clusters[0].name # Name of the first cluster in the list
		$nclusters = $response.count  # number of clusters
		C:\posh> $response.omnistack_clusters

		used_logical_capacity         : 603951366144
		used_capacity                 : 40730345472
		hypervisor_object_parent_id   : a5ffac0e-5c77-4384-a339-b3557b2df266:Datacenter:datacenter-26
		type                          : OMNISTACK
		compression_ratio             : 1.7 : 1
		hypervisor_object_id          : a5ffac0e-5c77-4384-a339-b3557b2df266:ClusterComputeResource:domain-c33
		stored_uncompressed_data      : 68377694208
		stored_compressed_data        : 40730902528
		members                       : {5ac32a42-9247-7311-9582-4f95cdb05c01}
		efficiency_ratio              : 14.8 : 1
		id                            : 16c7bc30-e6b0-420e-a7d0-b22b85229ed2
		deduplication_ratio           : 8.8 : 1
		upgrade_state                 : SUCCESS_COMMITTED
		local_backup_capacity         : 447949799424
		hypervisor_object_parent_name : BER
		arbiter_connected             : True
		time_zone                     : America/New_York
		version                       : Release 3.7.3.95
		name                          : DR
		capacity_savings              : 563221020672
		arbiter_address               : 10.0.40.41
		allocated_capacity            : 6091815282278
		stored_virtual_machine_data   : 92406267904
		hypervisor_type               : VSPHERE
		remote_backup_capacity        : 63595298816
		hypervisor_management_system  : 10.0.40.15
		free_space                    : 6051084936806
	#>

   [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$True)]
    	[string]$clustername
    )

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

	# Get the datastore id of the destination datastore
	$uri = $($Global:OmniStackConnection.Server) + "/api/omnistack_clusters?show_optional_fields=true&name=$clustername"
	$response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
	return $response
}

function GetOmniStackClusterMetric
{
	<#
	.SYNOPSIS
		Retrieve the performance metrics of a SimpliVity cluster
	.DESCRIPTION
		Get throughput, IOPS and latency data of a SimpliVity cluster
	.NOTES
		Required Parameters
			clustername: Clustername
		Optional Parameters
			range: A range in seconds (the duration from the specified point in time) Default: 43200
			resolution: The resolution (SECOND, MINUTE, HOUR or DAY) Default: MINUTE
			time_offset: A time offset in seconds (from now) or a datetime, expressed in ISO-8601 form, based on UTC; Default: 0
	.SYNTAX
		$response = GetOmniStackClusterMetric -clustername $clustername]
	.RETURNVALUE
		$clusterperformance  - OmniStack Cluster Throughput Object (https://api.simplivity.com/rest-api-generated-docs/omnistack_cluster_throughput.html)
		https://api.simplivity.com/rest-api_getting-started_metrics/rest-api_getting-started_metrics_performance-metrics.html
	.EXAMPLE
		$response = GetOmniStackClusterMetric -clustername "Prod"
		$iops = $response[0].metrics[0].data_points
		$reads = $response[0].metrics[0].data_points.reads
		$response.metrics
		name       data_points                                                                                            
		----       -----------                                                                                            
		iops       {@{reads=0; writes=35; date=2018-05-07T23:40:00Z}, @{reads=0; writes=36; date=2018-05-07T23:41:00Z},...
		throughput {@{reads=1012; writes=299475; date=2018-05-07T23:40:00Z}, @{reads=1257; writes=299957; date=2018-05-...
		latency    {@{reads=0; writes=564; date=2018-05-07T23:40:00Z}, @{reads=0; writes=517; date=2018-05-07T23:41:00Z...

	#>

   [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,ValueFromPipeline=$True)]
    	[string]$clustername,

        [Parameter(Mandatory=$false)]
        [int]$range=43200,
        [string]$resolution="MINUTE",
        [int]$time_offset=0
        
    )
    
    $cid = (GetOmniStackCluster -clustername $clustername)[0].omnistack_clusters.id

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

    $uri = $($Global:OmniStackConnection.Server) + "/api/omnistack_clusters/" + $cid + "/metrics?range="+$range+"&resolution="+$resolution+"&offset="+$offset+"&show_optional_fields=true"
	try{
        InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    } catch {
        Write-Host "Get-Cluster-Metric Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
    return $response
}

function GetOmniStackClusterThroughput
{
  	<#
	.SYNOPSIS
		Retrieve the throughput between each pair of omnistack_clusters in a federation
	.DESCRIPTION
		Delivers the list of SimpliVity cluster
	.NOTES
		Required Parameters
			
		Optional Parameters
			
	.SYNTAX
		$response = Get-Cluster-Throughput
	.RETURNVALUE
		$
	.EXAMPLE
		$result = Get-Cluster-Throughput
		$source_0 = $result[0].source_omnistack_cluster_name
		$result
		source_omnistack_cluster_id                                 : 16c7bc30-e6b0-420e-a7d0-b22b85229ed2
		source_omnistack_cluster_name                               : DR
		source_omnistack_cluster_hypervisor_object_parent_id        : a5ffac0e-5c77-4384-a339-b3557b2df266:Datacenter:data
																	  center-26
		source_omnistack_cluster_hypervisor_object_parent_name      : BER
		destination_omnistack_cluster_id                            : 37cea874-e2c8-43ff-8c7d-9beadfaff2df
		destination_omnistack_cluster_name                          : Prod
		destination_omnistack_cluster_hypervisor_object_parent_id   : a5ffac0e-5c77-4384-a339-b3557b2df266:Datacenter:data
																	  center-21
		destination_omnistack_cluster_hypervisor_object_parent_name : BBN
		throughput                                                  : 151
		date                                                        : 2018-05-08T11:41:40Z

		source_omnistack_cluster_id                                 : 37cea874-e2c8-43ff-8c7d-9beadfaff2df
		source_omnistack_cluster_name                               : Prod
		source_omnistack_cluster_hypervisor_object_parent_id        : a5ffac0e-5c77-4384-a339-b3557b2df266:Datacenter:data
																	  center-21
		source_omnistack_cluster_hypervisor_object_parent_name      : BBN
		destination_omnistack_cluster_id                            : 16c7bc30-e6b0-420e-a7d0-b22b85229ed2
		destination_omnistack_cluster_name                          : DR
		destination_omnistack_cluster_hypervisor_object_parent_id   : a5ffac0e-5c77-4384-a339-b3557b2df266:Datacenter:data
																	  center-26
		destination_omnistack_cluster_hypervisor_object_parent_name : BER
		throughput                                                  : 142
		date                                                        : 2018-05-08T11:40:20Z

		metrics : {@{name=iops; data_points=System.Object[]}, @{name=throughput; data_points=System.Object[]}, 
				  @{name=latency; data_points=System.Object[]}}

		offset             : 0
		count              : 1
		limit              : 500
		omnistack_clusters : {@{used_logical_capacity=603951366144; used_capacity=40730345472; 
							 hypervisor_object_parent_id=a5ffac0e-5c77-4384-a339-b3557b2df266:Datacenter:datacenter-26; 
							 type=OMNISTACK; compression_ratio=1.7 : 1; 
							 hypervisor_object_id=a5ffac0e-5c77-4384-a339-b3557b2df266:ClusterComputeResource:domain-c33; 
							 stored_uncompressed_data=68377694208; stored_compressed_data=40730902528; 
							 members=System.Object[]; efficiency_ratio=14.8 : 1; id=16c7bc30-e6b0-420e-a7d0-b22b85229ed2; 
							 deduplication_ratio=8.8 : 1; upgrade_state=SUCCESS_COMMITTED; 
							 local_backup_capacity=447949799424; hypervisor_object_parent_name=BER; 
							 arbiter_connected=True; time_zone=America/New_York; version=Release 3.7.3.95; name=DR; 
							 capacity_savings=563221020672; arbiter_address=10.0.40.41; allocated_capacity=6091815282278; 
							 stored_virtual_machine_data=92406267904; hypervisor_type=VSPHERE; 
							 remote_backup_capacity=63595298816; hypervisor_management_system=10.0.40.15; 
							 free_space=6051084936806}}	
	#>

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

	# Get 
	$uri = $($Global:OmniStackConnection.Server) + "/api/omnistack_clusters/throughput?show_optional_fields=true"
	try{
        InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    } catch {
        Write-Host "Get-Cluster-Throughput Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
    return $response	
}

<# OmniStack VM Operations ###################################################################>
function GetOmniStackVM
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Retrieves all instances of HPE SimpliVity based VMs that are defined on this system
	.NOTES
		Required Parameters
			
		Optional Parameters
			$VMname 
	.SYNTAX
		$response = Get-OmniStackVM
	.RETURNVALUE
		virtual_machine schema (https://api.simplivity.com/rest-api-generated-docs/virtual_machine.html)
	.EXAMPLE
		GetOmniStackVM

		offset limit count virtual_machines                                                                               
		------ ----- ----- ----------------                                                                               
			 0   500   101 {@{hypervisor_total_memory=4096; policy_id=a30a775d-5375-456b-8b26-c8e5de2cdeed; created_at=...

	#>

   [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,ValueFromPipeline=$True)]
    	[string]$VMname
    )

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

	# Get 
	$uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines?show_optional_fields=true&name=$VMname"
	try{
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    } catch {
        Write-Host "Get Virtual Machine Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
	return $response
}

function SetOmnistackVMBackupPolicy
{
	<#
	Not Yet Implemented!
	.SYNOPSIS
		
	.DESCRIPTION
		Assigns a Backup Policy to a VM
	.NOTES
		Required Parameters
			$VMname
			$Policy
		Optional Parameters
			
	.SYNTAX
		$response = Set-VM-BackupPolicy -VMname $VM -Policy $pid
	.RETURNVALUE
		
	.EXAMPLE
	
	#>

}

function GetOmniStackVMMetric
{
	<#
	.SYNOPSIS
		Retrieve the performance metrics of a SimpliVity VM
	.DESCRIPTION
		Get throughput, IOPS and latency data of a SimpliVity VM
	.NOTES
		Required Parameters
			VMname: VMname
		Optional Parameters
			range: A range in seconds (the duration from the specified point in time) Default: 43200
			resolution: The resolution (SECOND, MINUTE, HOUR or DAY) Default: MINUTE
			time_offset: A time offset in seconds (from now) or a datetime, expressed in ISO-8601 form, based on UTC; Default: 0
	.SYNTAX
		$response = Get-VM-Metric -VMname $clustername [-range $range -resolution $resolution -time_offset $timeOffset]
	.RETURNVALUE
		$VMperformance  - MetricsDataMO Object (https://api.simplivity.com/rest-api-generated-docs/metricsdatamo.html)
		https://api.simplivity.com/rest-api_getting-started_metrics/rest-api_getting-started_metrics_performance-metrics.html
	.EXAMPLE
		$response = Get-VM-Metric -VMname "VMtest"
		$iops = $response[0].metrics[0].data_points
		$reads = $response[0].metrics[0].data_points.reads
	#>	

	[CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,ValueFromPipeline=$True)]
    	[string]$VMname,

        [Parameter(Mandatory=$false)]
        [int]$range=43200,
        [string]$resolution="MINUTE",
        [int]$time_offset=0
        
    )
    
    $vmid = (GetOmniStackVM -VMname $VMname)[0].virtual_machine.id

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

    $uri = $($Global:OmniStackConnection.Server) + "/api/virtual_machines/" + $vmid + "/metrics?range="+$range+"&resolution="+$resolution+"&offset="+$offset+"&show_optional_fields=true"
	try{
        InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    } catch {
        Write-Host "Get-VM-Metric Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
    return $response

}

function CopyOmniStackVM
{}

function MoveOmniStackVM
{}

<# OmniStack DataStore Operations #>
function GetOmniStackDataStore
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Retrieves all instances of datastores that are defined on this system
	.NOTES
		Required Parameters
			
		Optional Parameters
			$ClusterName
	.SYNTAX
		$response = Get-OmniStack-DataStore [-ClusterName $cname]
	.RETURNVALUE
		OmniStack datastore Schema (https://api.simplivity.com/rest-api-generated-docs/datastore.html)
	.EXAMPLE
		$result = GetOmniStackDataStore
		PS C:\Users\Administrator> $result.datastores[0]

			policy_id                                   : a30a775d-5375-456b-8b26-c8e5de2cdeed
			mount_directory                             : 2d857b9c-4798-4faa-ad84-b0ac9c66f0dc
			created_at                                  : 2017-12-12T13:02:59Z
			policy_name                                 : Simple
			omnistack_cluster_name                      : DR
			hypervisor_free_space                       : 2114841477120
			shares                                      : {@{address=10.0.40.31; host=; rw=True}, @{address=10.0.41.31; host=; rw=True}}
			deleted                                     : False
			hypervisor_object_id                        : a5ffac0e-5c77-4384-a339-b3557b2df266:Datastore:datastore-59
			size                                        : 2199023255552
			name                                        : SuperCruise
			compute_cluster_parent_hypervisor_object_id : a5ffac0e-5c77-4384-a339-b3557b2df266:Datacenter:datacenter-26
			compute_cluster_parent_name                 : BER
			hypervisor_type                             : VSPHERE
			id                                          : 2d857b9c-4798-4faa-ad84-b0ac9c66f0dc
			omnistack_cluster_id                        : 16c7bc30-e6b0-420e-a7d0-b22b85229ed2

	#>
   [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,ValueFromPipeline=$True)]
    	[string]$ClusterName
    )

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

	# Get 
	$uri = $($Global:OmniStackConnection.Server) + "/api/datastores?show_optional_fields=true&omnistack_cluster_name=$ClusterName"
	try{
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    } catch {
        Write-Host "Get Virtual Machine Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
	return $response
}

function GetOmniStackDataStoreId
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Retrieves the UID of the datastore with name $Name
	.NOTES
		Required Parameters
			$Name        DataStore name
		Optional Parameters
			None
	.SYNTAX
		$datastore_id = Get-DataStore-Id -Name "NewDataStore" 
	.RETURNVALUE
		UID of the new datastore
	.EXAMPLE
		Get-DataStore-Id -Name ProdDS-Mach-2
			89341d89-5dac-4e19-9b8e-019de03b3347
	#>

    [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$true,ValueFromPipeline=$True)]
    	[string]$Name
    )

	$result = GetOmniStackDataStore
	foreach($ds in $result.datastores){
		if($ds.name -eq $Name){
			$datastore_id = $ds.id
		}
	}
    return $datastore_id
}

function NewOmniStackDataStore
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Creates a new datastore
	.NOTES
		Required Parameters
			$Name        DataStore name
			$Cluster_id	 OmniStack Cluster UID
			$Policy_id	 OmniStack Policy UID
			$Size		 DataStore size in bytes
		Optional Parameters
			None
	.SYNTAX
		$response = New-OmniStack-DataStore -Name "NewDataStore" -Cluster_id $cid -Policy_id $pid -Size $size 
	.RETURNVALUE
		UID of the new datastore
	.EXAMPLE
		$result = New-OmniStack-DataStore -Name "Test-Datastore" -Cluster_id $cluster_id -Policy_id $policy_id -Size "1000000000"
	#>

    [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$true,ValueFromPipeline=$True)]
    	[string]$Name,
        [string]$Cluster_id,
        [string]$Policy_id,
		[string]$Size
    )

    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $Header.Add("Accept", "application/json")

	$params = @{}
    $params.Add("name", $Name)
    $params.Add("omnistack_cluster_id", $Cluster_id)
    $params.Add("policy_id", $Policy_id)
	$params.Add("size", $Size)

    #Convert params to json
    $paramsjson = $params | ConvertTo-Json

    #Add Content-Type for Json to headers
    $header.Add("Content-Type", "application/vnd.simplivity.v1.1+json")
	$uri = $($Global:OmniStackConnection.Server) + "/api/datastores"
    try {
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Post -Body $paramsjson 
    } catch {
        Write-Host "Create DataStore Error: "  $_.Exception.Response.StatusCode.Value__
        exit 1
    }
    $header.Remove("Content-Type")
	
    return (GetDataStoreId -Name $Name)
}

function RemoveOmniStackDataStore
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Deletes a datastore
	.NOTES
		Required Parameters
			$DS_id	
		Optional Parameters
			None
	.SYNTAX
		$response = Remove-OmniStack-DataStore -DS_id $datastoreID
	.RETURNVALUE
		RestAPI call result: Task information regarding the Datastore removal
			task : @{id=33832a42-bbe5-182e-a34c-8fbf99557bba:33832a42-bbe5-182e-a34c-8fbf99557bba:56fdde34-249c-4cea-a6db-03d69f1d6f13; 
			   state=COMPLETED; affected_objects=System.Object[]; error_code=0; start_time=2018-04-05T10:29:55Z; 
			   end_time=2018-04-05T10:30:09Z}
	.EXAMPLE
		$response = RemoveOmniStackDataStore -DS_id $ds_id
	#>


	[CmdletBinding()]
    param(
    	[Parameter(Mandatory=$true,ValueFromPipeline=$True)]
    	[string]$DS_id
    )

    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $Header.Add("Accept", "application/json")

	$uri = $($Global:OmniStackConnection.Server) + "/api/datastores/"+$DS_id
    try {
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Delete 
    } catch {
        Write-Host "Delet$re DataStore Error: "  $_.Exception.Response.StatusCode.Value__
        exit 1
    }
    return $response
}

function ResizeOmniStackDataStore
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Resizes a datastore
	.NOTES
		Required Parameters
			$DS_id	datastoreid
			$Size	The size in bytes
		Optional Parameters
			None
	.SYNTAX
		$response =  ResizeOmniStackDataStore -DS_id $dsid -Size $size
	.RETURNVALUE
		RestAPI Call result - Task information
			task                                                                                                                             
			----                                                                                                                             
			@{id=33832a42-bbe5-182e-a34c-8fbf99557bba:33832a42-bbe5-182e-a34c-8fbf99557bba:77bb8e9c-fe70-499b-bccf-1da5ea527697; state=COM...
	.EXAMPLE
		$response = Resize-OmniStack-DataStore -DS_id $datastore_id -Size $size

	#>

   [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$true,ValueFromPipeline=$True)]
    	[string]$DS_id,
		[string]$Size
    )

    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $Header.Add("Accept", "application/json")

	$params = @{}
	$params.Add("size", $Size)

    #Convert params to json
    $paramsjson = $params | ConvertTo-Json

    #Add Content-Type for Json to headers
    $header.Add("Content-Type", "application/vnd.simplivity.v1.1+json")
	$uri = $($Global:OmniStackConnection.Server) + "/api/datastores/"+$DS_id+"/resize"
    try {
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Post -Body $paramsjson 
    } catch {
        Write-Host "Resize DataStore Error: "  $_.Exception.Response.StatusCode.Value__
        exit 1
    }
    $header.Remove("Content-Type")
    return $response
}

function SetOmniStackDataStorePolicy
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Sets the backup policy for a datastore
	.NOTES
		Required Parameters
			$DS_id	datastoreid
			$Policy_id	 OmniStack Policy UID
		Optional Parameters
			None
	.SYNTAX
		$response = Set-OmniStack-DataStore-Policy -DS_id $dsid -Policy_id $pid
	.RETURNVALUE
		RestAPI task information
			task                                                                                                                             
			----                                                                                                                             
			@{id=33832a42-bbe5-182e-a34c-8fbf99557bba:33832a42-bbe5-182e-a34c-8fbf99557bba:49889762-4736-496d-a093-37b16fff0ed0; state=COM...
	.EXAMPLE
		$response = SetOmniStackDataStorePolicy -DS_id $datastore_id -Policy_id $policy
	#>
   [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$true,ValueFromPipeline=$True)]
    	[string]$DS_id,
		[string]$Policy_id
    )

    $header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $Header.Add("Accept", "application/json")

	$params = @{}
	$params.Add("policy_id", $Policy_id)

    #Convert params to json
    $paramsjson = $params | ConvertTo-Json

    #Add Content-Type for Json to headers
    $header.Add("Content-Type", "application/vnd.simplivity.v1.1+json")
	$uri = $($Global:OmniStackConnection.Server) + "/api/datastores/"+$DS_id+"/set_policy"
    try {
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Post -Body $paramsjson 
    } catch {
        Write-Host "Resize DataStore Error: "  $_.Exception.Response.StatusCode.Value__
        exit 1
    }
    $header.Remove("Content-Type")
    return $response
}

<# Backup Policy Operations #############################################################>

function GetOmniStackBackupPolicy
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Retrieves all instances of policies that are defined on this system
	.NOTES
		Required Parameters
			
		Optional Parameters
			Name - Policyname  !!!! Attention: The name flag is not working currently (3.7.2)!!!
	.SYNTAX
		$response = GetBackupPolicy [-Name $policyname]
	.RETURNVALUE
		policy schema https://api.simplivity.com/rest-api-generated-docs/policy.html
	.EXAMPLE
	    $response = Get-Backup-Policy

		Write-Host $response.policies
		@{name=Fixed Default Backup Policy; id=f2609cba-42d8-4365-be3c-ad4689119ef0; rules=System.Object[]} @{name=Simple; id=a30a775d-5375-456b-8b26-c8e5de2cdeed; rules=Syst
		em.Object[]} @{name=MissionCritical; id=06006de1-a35c-46e9-b0c4-00ab69982086; rules=System.Object[]} @{name=CrashConsistent; id=83f19363-882a-409d-a2ec-6cc629b4f642; 
		rules=System.Object[]} @{name=Gold-Hourly; id=1150579a-e96f-4231-ae2e-de5395edada6; rules=System.Object[]} @{name=RPO=10-Mins; id=6c480463-9860-4ced-95ce-0a5b31ed6951
		; rules=System.Object[]} @{name=CentOS; id=76678318-d930-49ab-9a7b-686d40ccde79; rules=System.Object[]}
	
		Write-Host $response.policies[0]
		@{name=Fixed Default Backup Policy; id=f2609cba-42d8-4365-be3c-ad4689119ef0; rules=System.Object[]}

		$response.policies[1].rules
		@{frequency=1440; retention=10080; days=All; id=714ba236-6b7a-4cc9-82b3-6a27c1af6ee2; number=0; destination_id=<local>; start_time=00:00; end_time=00:00; application_
		consistent=True; consistency_type=VSS; destination_name=<local>; max_backups=7} @{frequency=60; retention=120; days=Sun; id=1b290b11-629c-44a0-b250-612b542a96ab; numb
		er=1; destination_id=<local>; start_time=00:00; end_time=00:00; application_consistent=True; consistency_type=VSS; destination_name=<local>; max_backups=2} @{frequenc
		y=1440; retention=10080; days=All; id=03ca4205-d618-4aa3-a9f0-ebd3f2804bfa; number=2; destination_id=37cea874-e2c8-43ff-8c7d-9beadfaff2df; start_time=00:00; end_time=
		00:00; application_consistent=True; consistency_type=VSS; destination_name=Prod; max_backups=7} @{frequency=1440; retention=10080; days=Last; id=d1e637f8-a11f-4153-87
		0d-0cc93ea37ba2; number=3; destination_id=16c7bc30-e6b0-420e-a7d0-b22b85229ed2; start_time=00:00; end_time=00:00; application_consistent=True; consistency_type=VSS; d
		estination_name=DR; max_backups=7}

		$response.policies[1].rules[0]
		@{frequency=1440; retention=10080; days=All; id=714ba236-6b7a-4cc9-82b3-6a27c1af6ee2; number=0; destination_id=<local>; start_time=00:00; end_time=00:00; application_
		consistent=True; consistency_type=VSS; destination_name=<local>; max_backups=7}
	#>
   [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,ValueFromPipeline=$True)]
    	[string]$Name
    )

    Write-Host "Get Backup Policies"

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

	# Get 
	$uri = $($Global:OmniStackConnection.Server) + "/api/policies?show_optional_fields=true&name=$Name"
	try{
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    } catch {
        Write-Host "Get Backup Policy Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
	return $response
}

function DefineOmniStackBackupPolicy
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Create a new Backup policy
	.NOTES
		Required Parameters
			$Name   - Policy name
		Optional Parameters

	.SYNTAX
		$response = Define-Backup-Policy -Name $name -Policy @policy  
	.RETURNVALUE
		$policy_id - The UID of the new Backup Policy
	.EXAMPLE
	
	#>
	[CmdletBinding()]
    param(
    	[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    		$Name 
    )

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")
	$header.Add("Content-Type", "application/vnd.simplivity.v1.1+json")

    $params = @{}
    $params.Add("name", $Name)
    #Convert params to json
    $paramsjson = $params | ConvertTo-Json
    
    $uri = $($Global:OmniStackConnection.Server) + "/api/policies"
	try{
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Post -Body $paramsjson
    } catch {
        Write-Host "Define Backup Policy Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
    $header.Remove("Content-Type")
    # the UID of the new policy
    $response = GetBackupPolicy -Name $Name
    foreach($result in $response.policies){
        if($result.name -eq $Name){
            $policy_id = $result.id
        }
    }
	return $policy_id
}

function AddOmniStackPolicyRule
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Adds a new policy rule
	.NOTES
		Required Parameters
			$Policy_id  - The UID of the backup policy where the $Rule should be added to. 
			$Rule - The backup policies rule, each rule is an array:
				@{frequency, retention[, application_consistent, consistency_type, days, destination_id, end_time, start_time]} 
				https://api.simplivity.com/rest-api-generated-docs/create_or_edit_rule.html
				https://api.simplivity.com/rest-api-generated-docs/rule.html
		Optional Parameters
			None
	.SYNTAX
		$response = DefineBackupPolicy -Name $name -Policy @policy  
	.RETURNVALUE
		Result of the RestAPI call
	.EXAMPLE
		
	#>
	[CmdletBinding()]
	param(
		[Parameter(mandatory=$true)]
			[string]$policyID,
			[string]$DestinationClusterId,
			[string]$EndTime,
			[string]$StartTime,
			[int]$Frequency,
			[int]$Retention,
		[Parameter(mandatory=$false)]
			[string]$Days="All",
			[bool]$Replace=$false,
			[bool]$AppConsistent=$false
	)

    $uri = $($Global:OmnistackConnection.Server) + "/api/policies/" + $policyid + "/rules?replace_all_rules=" + $Replace
	$header = @{}
    $header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
    $header.Add("Accept", "application/json")
    $header.Add("Content-Type", "application/vnd.simplivity.v1.1+json")
	$body = @{}
	$body.Add("application_consistent",$AppConsistent)
	$body.Add("days","$Days")
	$body.Add("destination_id", "$DestinationClusterId")
	$body.Add("end_time","$EndTime")
	$body.Add("frequency",$Frequency)
	$body.Add("retention",$Retention)
	$body.Add("start_time","$StartTime")
	$body = ConvertTo-Json -InputObject @($body)
  	$result = Invoke-OmnistackREST -Uri $uri -Headers $header -Body $body -Method Post
	return $result
}

<# Host Operations #############################################################>

funciton GetOmniStackHosts
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Retrieves all instances of hosts that are defined on this system
	.NOTES
		Required Parameters
			None
		Optional Parameters
			Hostname
	.SYNTAX
		$response = Get-OmniStack-Hosts [-HostName $hostname]
	.RETURNVALUE
		Host schema
		https://api.simplivity.com/rest-api-generated-docs/host.html
	.EXAMPLE
		
	#>

   [CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,ValueFromPipeline=$True)]
    	[string]$Hostname
    )

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

	# Get 
	$uri = $($Global:OmniStackConnection.Server) + "/api/hosts?show_optional_fields=true&name=$Hostname"
	try{
        $response = InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    } catch {
        Write-Host "Get Virtual Machine Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
	return $response

}

function GetOmniStackHostMetric
{
	<#
	.SYNOPSIS
		
	.DESCRIPTION
		Retrieves throughput, IOPS, and latency data for the host
	.NOTES
		Required Parameters
			HostName
		Optional Parameters
			range: A range in seconds (the duration from the specified point in time) Default: 43200
			resolution: The resolution (SECOND, MINUTE, HOUR or DAY) Default: MINUTE
			time_offset: A time offset in seconds (from now) or a datetime, expressed in ISO-8601 form, based on UTC; Default: 0			
	.SYNTAX
		$response = Get-Host-Metric -HostName $hostname [-range $range -resolution $resolution -time_offset $timeOffset]
	.RETURNVALUE
		analytics info schema
		https://api.simplivity.com/rest-api-generated-docs/analytics_info.html
	.EXAMPLE
		
	#>


	[CmdletBinding()]
    param(
    	[Parameter(Mandatory=$false,ValueFromPipeline=$True)]
    	[string]$Hostname,

        [Parameter(Mandatory=$false)]
        [int]$range=43200,
        [string]$resolution="MINUTE",
        [int]$time_offset=0
        
    )
    
    $hostid = (GetOmniStackHosts -Hostname $Hostname)[0].host.id

	$header = @{}
	$header.Add("Authorization", "Bearer $($Global:OmniStackConnection.Token)")
	$header.Add("Accept", "application/json")

    $uri = $($Global:OmniStackConnection.Server) + "/api/hosts/" + $hostid + "/metrics?range="+$range+"&resolution="+$resolution+"&offset="+$offset+"&show_optional_fields=true"
	try{
        InvokeOmnistackREST -Uri $uri -Headers $header -Method Get
    } catch {
        Write-Host "Get-VM-Metric Error: "  $_.Exception.Response.StatusCode.Value__
        $header.Remove("Content-Type")
        exit 1
    }
	$header.Remove("Content-Type")
    return $response
}

function GetOmniStackHostCapacity
{

}

