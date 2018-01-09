configuration CreateDCCA 
{ 
   param 
   ( 
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    ) 
    
#    Import-DscResource -ModuleName xActiveDirectory,xDisk, xNetworking, cDisk, PSDesiredStateConfiguration, xAdcsDeployment
    Import-DscResource -ModuleName xActiveDirectory,xDisk, xNetworking, PSDesiredStateConfiguration, xAdcsDeployment
    Import-DscResource -ModuleName cDisk

    [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    $Interface=Get-NetAdapter|Where Name -Like "Ethernet*"|Select-Object -First 1
    $InterfaceAlias=$($Interface.Name)

    Node localhost
    {
        LocalConfigurationManager 
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }


	    WindowsFeature DNS 
        { 
            Ensure = "Present" 
            Name = "DNS"		
        }

	    WindowsFeature RSAT
	    {
	        Ensure = "Present"
            Name = "RSAT"
	    }

	    WindowsFeature DnsTools
	    {
	        Ensure = "Present"
            Name = "RSAT-DNS-Server"
	    }

        xDnsServerAddress DnsServerAddress 
        { 
            Address        = '127.0.0.1' 
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
	        DependsOn = "[WindowsFeature]DNS","[WindowsFeature]RSAT","[WindowsFeature]DnsTools"
        }

        xWaitforDisk Disk2
        {
             DiskNumber = 2
             RetryIntervalSec =$RetryIntervalSec
             RetryCount = $RetryCount
	 		 #Make sure all the modules are installed before proceeding - this may not be needed...
	 		 DependsOn = "[xDnsServerAddress]DnsServerAddress"
        }

        cDiskNoRestart ADDataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
			DependsOn="[xWaitforDisk]Disk2"
        }

        WindowsFeature ADDSInstall 
        { 
            Ensure = "Present" 
            Name = "AD-Domain-Services"
	        DependsOn="[cDiskNoRestart]ADDataDisk"
        } 
         
        xADDomain FirstDS 
        {
            DomainName = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath = "F:\NTDS"
            LogPath = "F:\NTDS"
            SysvolPath = "F:\SYSVOL"
	        DependsOn = "[WindowsFeature]ADDSInstall","[xDnsServerAddress]DnsServerAddress"
        }

        WindowsFeature ADCS-Cert-Authority
        {
               Ensure = 'Present'
               Name = 'ADCS-Cert-Authority'
               DependsOn = '[xADDomain]FirstDS'
        }

        xADCSCertificationAuthority ADCS
        {
            Ensure = 'Present'
            Credential = $DomainCreds
            CAType = 'EnterpriseRootCA'
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
        }
        WindowsFeature ADCS-Web-Enrollment
        {
            Ensure = 'Present'
            Name = 'ADCS-Web-Enrollment'
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority'
        }
        xADCSWebEnrollment CertSrv
        {
            Ensure = 'Present'
            IsSingleInstance = 'Yes'
            Credential = $DomainCreds
            DependsOn = '[WindowsFeature]ADCS-Web-Enrollment','[xADCSCertificationAuthority]ADCS'
        }

        Script Ensure_LDAPS_is_Active
        {
            DependsOn  = @("[xADCSWebEnrollment]CertSrv")
            GetScript  = { @{ Result = "Ensure_LDAPS_is_Active" } }

            TestScript = {
#                Test-Path -Path "C:\rebootmarker"
                $port=636
                $hostname = "localhost"
                Write-Host "Looking for LDAPS certificate for $hostname"
                try {
                    $tcpclient = new-object System.Net.Sockets.tcpclient
                    $tcpclient.Connect($hostname,$port)

                    #Authenticate with SSL - trusting all certificates
                    $sslstream = new-object System.Net.Security.SslStream -ArgumentList $tcpclient.GetStream(),$false,{$true}

                    $sslstream.AuthenticateAsClient($hostname)
                    $cert =  [System.Security.Cryptography.X509Certificates.X509Certificate2]($sslstream.remotecertificate)
                    if($cert) {
                        return $true
                    }
                    else {
                        # Didn't get a certificate somehow - usually because LDAPS isn't setup yet. Return $false.
                        return $false
                    }
                }
                catch {
                    return $false
                }
                finally {
                    #cleanup
                    if ($sslStream) {
                        $sslstream.close() | Out-Null
                    }
                    if ($tcpclient) {
                        $tcpclient.close() | Out-Null
                    }
                }
            }

            SetScript  = {

                function Test-LDAPS-Cert()
                {
                    $port=636
                    $hostname = "localhost"
                    Write-Host "Looking for LDAPS certificate for $hostname"
                    try {
                        $tcpclient = new-object System.Net.Sockets.tcpclient
                        $tcpclient.Connect($hostname,$port)
    
                        #Authenticate with SSL - trusting all certificates
                        $sslstream = new-object System.Net.Security.SslStream -ArgumentList $tcpclient.GetStream(),$false,{$true}
    
                        $sslstream.AuthenticateAsClient($hostname)
                        $cert =  [System.Security.Cryptography.X509Certificates.X509Certificate2]($sslstream.remotecertificate)
                        if($cert) {
                            return $true
                        }
                        else {
                            return $false
                        }
                    }
                    catch {
                        # Didn't get a certificate somehow - usually because LDAPS isn't setup yet. Return $false.
                        return $false
                    }
                    finally {
                        #cleanup
                        if ($sslStream) {
                            $sslstream.close() | Out-Null
                        }
                        if ($tcpclient) {
                            $tcpclient.close() | Out-Null
                        }
                    }
                }

                $retries = 30 # about 5 minutes
                while(-not (Test-LDAPS-Cert) ) {
                    Write-Host "LDAPS port not open. Retries remining: $retries"
                    if(($retries--) -eq 0) {
                        throw "LDAPS port did not open."
                    }
                    # Login as the domain admin, not the DSC user, for access rights.
                    $DCSession = New-PSSession localhost -Credential $using:DomainCreds
                    Invoke-Command {& "certutil" -pulse > $null} -Session $DCSession | Out-Null
                    Remove-PSSession $DCSession | Out-Null

                    Start-Sleep -seconds 10 #wait a few seconds for the certificate to show up
                }
			}
		}
	}
}
