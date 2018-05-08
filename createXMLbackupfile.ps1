<# 
.SYNOPSIS
	Secure Login for the OmniStackCmds
	(c) Thomas Beha, April 2018
.DESCRIPTION
	This powershell script creates the XML file (SvtBackupJob.xml) that is used by the prebackup.ps1 / prebackup.ResourcePool.ps1 scripts
	This script will generate a key-file (AES.key) and encrypts the password used for the SimpliVity RestAPI connection. 
	AES.key will be stored in the same directory as the SvtBackupJob.xml file. It is recommended to move AES.key into a directory 
	with restricted access and to update the backup scripts accordingly. 
.NOTES
	
#>

$Key = New-Object Byte[] 16 
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
$Path = (Get-Location)
Write-Host "PATH: " $PATH
$Key | Out-File -FilePath "$PATH\AES.key"


$xmlfile = "$PATH\SvtBackupJob.xml"
Write-Host "XML-File: " $xmlfile
# Create the XML File Tags
$xmlWriter = New-Object System.XMl.XmlTextWriter($xmlfile,$Null)
$xmlWriter.Formatting = 'Indented'
$xmlWriter.Indentation = 1
$XmlWriter.IndentChar = "`t"
$xmlWriter.WriteStartDocument()
$xmlWriter.WriteComment('Store the backup information and the encrypted SimpliVity RestAPI Passwords')
$xmlWriter.WriteStartElement('RestAPI')
$xmlWriter.WriteEndElement()
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()

$xmlDoc = [System.Xml.XmlDocument](Get-Content $xmlfile);  

$nVMs = Read-Host -Verbose "Number of VMs to backup:"

for($i=1;$i -le $nVMs; $i++){
	$siteCollectionNode = $xmlDoc.CreateElement("VMtoBackup")
	$xmlDoc.SelectSingleNode("//RestAPI").AppendChild($siteCollectionNode)
	
	$data = Read-Host -Verbose "Enter VM $i name: "
	$siteCollectionNode.SetAttribute("id", $data)
	$data = Read-Host -Verbose "Enter backup destination cluster name (VM $i): "
	$siteCollectionNode.SetAttribute("destination", $data)
	$data= Read-Host -Verbose "Enter backup retention time (VM $i) [min]: "
	$siteCollectionNode.SetAttribute("retention", $data)
	$data= Read-Host -Verbose "Enter restore datastore name (VM $i): "
	$siteCollectionNode.SetAttribute("restore", $data)
	$data= Read-Host -Verbose "Enter restore VM tag (VM $i):"
	$siteCollectionNode.SetAttribute("restoreTag", $data)
}
$siteCollectionNode = $xmlDoc.CreateElement("OVC")
$xmlDoc.SelectSingleNode("//RestAPI").AppendChild($siteCollectionNode)
$data=Read-Host -Verbose "Enter OVC IP address:"
$siteCollectionNode.SetAttribute("id", $data)

$siteCollectionNode = $xmlDoc.CreateElement("VCENTER")
$xmlDoc.SelectSingleNode("//RestAPI").AppendChild($siteCollectionNode)
$data = Read-Host -Verbose "Enter vCenter IP address or FQDN:"
$siteCollectionNode.SetAttribute("id", $data)

$siteCollectionNode = $xmlDoc.CreateElement("VeeamBackupServer")
$xmlDoc.SelectSingleNode("//RestAPI").AppendChild($siteCollectionNode)
$data= Read-Host -Verbose "Enter Veeam Backup Server IP address (or FQDN):"
$siteCollectionNode.SetAttribute("id", $data)

$siteCollectionNode = $xmlDoc.CreateElement("VeeamBackupJob")
$xmlDoc.SelectSingleNode("//RestAPI").AppendChild($siteCollectionNode)
$data= Read-Host -Verbose "Enter Veeam Backup Job name: "
$siteCollectionNode.SetAttribute("id", $data)

$siteCollectionNode = $xmlDoc.CreateElement("Username")
$xmlDoc.SelectSingleNode("//RestAPI").AppendChild($siteCollectionNode)
$data = Read-Host -Verbose "Enter OmniStack Username: "
$siteCollectionNode.SetAttribute("id", $data)

$siteCollectionNode = $xmlDoc.CreateElement("Password")
$xmlDoc.SelectSingleNode("//RestAPI").AppendChild($siteCollectionNode)
$SecureString = Read-Host -AsSecureString -Verbose "Enter OmniStack Password"
$data = ConvertFrom-SecureString $SecureString -Key $Key
$siteCollectionNode.SetAttribute("id", $data)

$siteCollectionNode = $xmlDoc.CreateElement("VeeamPool")
$xmlDoc.SelectSingleNode("//RestAPI").AppendChild($siteCollectionNode)
$data= Read-Host -Verbose "Enter Backup Resource Pool (leave blank if not needed): "
$siteCollectionNode.SetAttribute("id", $data)

$xmlDoc.Save($xmlfile)

