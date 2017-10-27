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

        Script Reboot_DC
        {
            DependsOn  = @("[xADCSWebEnrollment]CertSrv")
            GetScript  = { @{ Result = "Reboot_DC" } }

            TestScript = {
                Test-Path -Path "C:\rebootmarker"
                }
            SetScript  = {
                $file = New-Item "C:\rebootmarker" -type File
                Set-Content -Path $file -Value "DSC reboot initiated"

                # Reboot machine - might help getting a certificate made???
				$global:DSCMachineStatus = 1
			}
		}
	}
}
