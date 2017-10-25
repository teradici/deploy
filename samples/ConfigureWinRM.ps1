#################################################################################################################################
#  Name        : Configure-WinRM.ps1                                                                                            #
#                                                                                                                               #
#  Description : Configures the WinRM on a local machine                                                                        #
#                                                                                                                               #
#  Arguments   : HostName, specifies the FQDN of machine or domain                                                           #
#################################################################################################################################

param
(
    [string] $hostname,
	[string] $svrAccountName
)

#################################################################################################################################
#                                             Helper Functions                                                                  #
#################################################################################################################################

function Delete-WinRMListener
{
    $config = Winrm enumerate winrm/config/listener
    foreach($conf in $config)
    {
        if($conf.Contains("HTTPS"))
        {
            Write-Verbose "HTTPS is already configured. Deleting the exisiting configuration."

            winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
            break
        }
    }
}

function Get-Thumbprint
{
    param([string] $hostname)

	$certLoc = 'cert:Localmachine\My'
    
    $thumbprint = (Get-ChildItem $certLoc | Where-Object { $_.Subject -eq "CN=" + $hostname } | Select-Object -Last 1).Thumbprint
    
    $thumbprint
}

function Create-Certificate
{
    param([string] $hostname)

	# create self signed certificate
	$certLoc = 'cert:Localmachine\My'
  	$startDate = [DateTime]::Now.AddDays(-1)
  	$endDate = [DateTime]::Now.AddDays(365)
   	$subject = "CN=" + $hostname
   	$cert = New-SelfSignedCertificate -Type Custom -certstorelocation $certLoc -Subject $subject `
    		-NotBefore $startDate -NotAfter $endDate -KeySpec KeyExchange -KeyExportPolicy Exportable `
    		-Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    		-TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")  
    
    $thumbprint=Get-Thumbprint($hostname)
    if(-not $thumbprint)
    {
        throw "Failed to create the test certificate."
    }
    
    $cert
}

function Configure-WinRMHttpsListener
{
    param([string] $hostname)

    # Delete the WinRM Https listener if it is already configured
    Delete-WinRMListener

    $thumbprint = Get-Thumbprint($hostname)
    if(-not $thumbprint)
    {
    	Create-Certificate($hostname)
        $thumbprint = Get-Thumbprint($hostname)
    }	

    $winargs = '@{Hostname="'+$hostname+'";CertificateThumbprint="'+$thumbprint+'"}'
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS $winargs
}

function Add-FirewallException
{
    param([string] $port)

    # Delete an exisitng rule
    netsh advfirewall firewall delete rule name="Windows Remote Management (HTTPS-In)" dir=in protocol=TCP localport=$port

    # Add a new firewall rule
    netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=$port
}


function Delegate-Join-VM-Domain
{
    param([string] $saAccount)

	$domain = Get-ADDomain
	$ouDN = $domain.ComputersContainer

	$SearchAccount = Get-ADUser $saAccount
 
	$SAM = $SearchAccount.SamAccountName
	$UserAccount = $domain.NetBIOSName+"\"+$SAM

	dsacls.exe $ouDN /G $UserAccount":CCDC;Computer" /I:T | Out-Null
	dsacls.exe $ouDN /G $UserAccount":LC;;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":RC;;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":WD;;Computer" /I:S  | Out-Null
	dsacls.exe $ouDN /G $UserAccount":WP;;Computer" /I:S  | Out-Null
	dsacls.exe $ouDN /G $UserAccount":RP;;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":CA;Reset Password;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":CA;Change Password;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":WS;Validated write to service principal name;Computer" /I:S | Out-Null
	dsacls.exe $ouDN /G $UserAccount":WS;Validated write to DNS host name;Computer" /I:S | Out-Null
}

#################################################################################################################################
#                                              Configure WinRM                                                                  #
#################################################################################################################################

$winrmHttpsPort=5986

#Configure https listener
Configure-WinRMHttpsListener $hostname

# Add firewall exception
Add-FirewallException -port $winrmHttpsPort

#Enable-PSRemoting –force
#Set-WSManQuickConfig -UseSSL -force

Delegate-Join-VM-Domain $svrAccountName
#################################################################################################################################
#################################################################################################################################
