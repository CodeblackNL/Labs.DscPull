Configuration CommonServer {
    param (
        [string]$ShareHostName,
        [PSCredential]$ShareCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xNetworking'
    Import-DscResource -ModuleName 'xRemoteDesktopAdmin'
    Import-DscResource -ModuleName 'CredentialManagement'

    # Administrator password never expires
    User Administrator {
        Ensure                 = 'Present'
        UserName               = 'Administrator'
        PasswordChangeRequired = $false
        PasswordNeverExpires   = $true
    }

    foreach ($networkAdapter in $Node.NetworkAdapters) {
        $network = $networkAdapter.Network
        if ($networkAdapter.StaticIPAddress) {
            xDhcpClient "DisableDHCP_$($network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                State              = 'Disabled'
            }

            xIPAddress "Network_$($networkAdapter.Network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                IPAddress          = $networkAdapter.StaticIPAddress
                SubnetMask         = $network.PrefixLength
                DependsOn          = "[xDhcpClient]DisableDHCP_$($network.Name)"
            }

            if ($network.DnsServer -and $network.DnsServer.IPAddress) {
                xDnsServerAddress "DnsServerAddress_$($networkAdapter.Network.Name)" {
                    InterfaceAlias = $network.Name
                    AddressFamily  = $network.AddressFamily
                    Address        = $network.DnsServer.IPAddress
                    DependsOn      = "[xIPAddress]Network_$($network.Name)"
                }
            }
        }
        else {
            xDhcpClient "EnableDHCP_$($network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                State              = 'Enabled'
            }
        }
    }

    xRemoteDesktopAdmin RemoteDesktopSettings {
        Ensure                 = 'Present' 
        UserAuthentication     = 'Secure'
    }
    xFirewall AllowRDP {
        Ensure                 = 'Present'
        Name                   = 'RemoteDesktop-UserMode-In-TCP'
        Enabled                = 'True'
    }

    Registry DoNotOpenServerManagerAtLogon {
        Ensure                 = 'Present'
        Key                    = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
        ValueName              = 'DoNotOpenServerManagerAtLogon'
        ValueType              = 'Dword'
        ValueData              = 0x1
    }

	if ($ShareHostName -and $ShareCredential) {
        bManagedCredential ShareCredential {
            TargetName = $ShareHostName
            Ensure = 'Present'
            Credential = $ShareCredential
            CredentialType = 'DomainPassword'
            PersistanceScope ='LocalMachine'
        }
    }
}

Configuration DhcpServer {
    param (
        $DhcpServer,
        $DnsServerIPAddress
    )

    Import-DscResource –ModuleName 'xDhcpServer'
    Import-DscResource –ModuleName 'bDhcpServer'

    WindowsFeature Dhcp {
        Name               = 'DHCP'
    }
    bDhcpServerConfigurationCompletion DhcpCompletion {
        Ensure             = 'Present'
        DependsOn          = '[WindowsFeature]Dhcp'
    }
    WindowsFeature DhcpMgmtTools {
        Name               = 'RSAT-DHCP'
        DependsOn          = '[WindowsFeature]Dhcp'
    }

    # NOTE: Binding not needed (?), since only one interface
    #       Set-DhcpServerv4Binding -InterfaceAlias 'Management' -BindingState $true

    xDhcpServerScope DhcpScope {
        Ensure             = 'Present'
        Name               = $DhcpServer.ScopeName
        IPStartRange       = $DhcpServer.StartRange
        IPEndRange         = $DhcpServer.EndRange
        SubnetMask         = $DhcpServer.SubnetMask
        LeaseDuration      = $DhcpServer.LeaseDurationDays
        State              = 'Active'
        DependsOn          = '[bDhcpServerConfigurationCompletion]DhcpCompletion'
    }
    xDhcpServerOption DhcpOptions {
        Ensure             = 'Present'
        ScopeID            = $DhcpServer.ScopeId
        DnsServerIPAddress = $DnsServerIPAddress
        Router             = $DhcpServer.DefaultGateway
        DependsOn          = '[xDhcpServerScope]DhcpScope'
    }
}

Configuration DscPullServer {
    param (
        [string]$RegistrationKey
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    WindowsFeature DSCService {
        Name = 'DSC-Service'
        Ensure = 'Present'
    }

    $dscServicePath = Join-Path -Path $env:ProgramFiles -ChildPath '\WindowsPowerShell\DscService'
    File RegistrationKeyFile {
        DestinationPath = (Join-Path -Path $dscServicePath -ChildPath 'RegistrationKeys.txt')
        Type = 'File'
        Contents = $RegistrationKey
        Ensure = 'Present'
    }
    xDscWebService DSCPullServer {
        EndpointName = 'PSDSCPullServer'
        Port = 8080
        CertificateThumbPrint = 'AllowUnencryptedTraffic'
        Ensure = 'Present'
        PhysicalPath = "$($env:SystemDrive)\inetpub\PSDSCPullServer"
        ModulePath = (Join-Path -Path $dscServicePath -ChildPath 'Modules')
        ConfigurationPath = (Join-Path -Path $dscServicePath -ChildPath 'Configuration')
        RegistrationKeyPath = $dscServicePath
        State = 'Started'
        DependsOn = '[WindowsFeature]DSCService'
    }
}

Configuration FeedServer {
    param (
        [string]$SharePath,
        [PSCredential]$ShareCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource –ModuleName 'xWebAdministration'
    Import-DscResource -ModuleName 'xNetworking'

    $sitePort = 80
    $siteName = 'Packages'
	$webFolder = Join-Path -Path 'C:\inetpub' -ChildPath $siteName
	$appPoolName = "$($siteName)AppPool"
    $feedNames = @('Chocolatey', 'PowerShell')

    WindowsFeature WebServer {
        Name                   = 'Web-Server'
    }
    WindowsFeature AspNet45 {
        Name                   = 'Web-Asp-Net45'
        Ensure                 = 'Present'
        DependsOn              = '[WindowsFeature]WebServer'
    }
    # stop the default website, so port 80 is available
    xWebsite DefaultSite {
        Name                   = 'Default Web Site'
        State                  = 'Stopped'
        DependsOn              = '[WindowsFeature]WebServer'
    }
	xFirewall WebFirewall {
        Ensure                 = 'Present'
        Name                   = 'WWW'
        Direction              = 'InBound'
        LocalPort              = $sitePort
        Protocol               = 'TCP'
        Profile                = 'Any'
        Action                 = 'Allow'
        Enabled                = 'True'
	}

    File WebsiteFolder {
        DestinationPath    = $webFolder
        Ensure             = 'Present'
        Type               = 'Directory'
    }
    xWebAppPool WebsiteAppPool { 
        Name               = $appPoolName
        State              = 'Started'
        identityType       = 'LocalSystem'
    }
	xWebsite Website {
		Name               = $siteName
		Ensure             = 'Present'
		State              = 'Started'
		ApplicationPool    = $appPoolName
		PhysicalPath       = $webFolder
		BindingInfo        = MSFT_xWebBindingInformation { 
									Port = $sitePort
									Protocol = 'HTTP'
								} 
		DependsOn          = '[File]WebsiteFolder','[xWebAppPool]WebsiteAppPool'
	}

    foreach ($feedName in $feedNames) {
        $physicalPath = Join-Path -Path $webFolder -ChildPath $feedName
        $packagesPath = Join-Path -Path $physicalPath -ChildPath 'Packages'

        File "FeedFolder_$feedName" {
            DestinationPath    = $physicalPath
            Ensure             = 'Present'
            Type               = 'Directory'
            MatchSource        = $true
            Force              = $true
            Recurse            = $true
            SourcePath         = Join-Path -Path $SharePath -ChildPath 'install\NugetServer\'
            Credential         = $ShareCredential
        }
        File "PackagesFolder_$feedName" {
            DestinationPath    = $packagesPath
            Ensure             = 'Present'
            Type               = 'Directory'
            MatchSource        = $true
            Force              = $true
            Recurse            = $true
            SourcePath         = Join-Path -Path $SharePath -ChildPath "packages\$feedName\"
            Credential         = $ShareCredential
        }
        xWebApplication "WebApp_$feedName" {
            Name               = $feedName
            Ensure             = 'Present'
            Website            = $siteName
		    WebAppPool         = $appPoolName
            PhysicalPath       = $physicalPath
        }
    }
}

Configuration HyperVLabEnvironment {
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.NodeName {

        <# The following initialization is done in the setup-complete script
            + Initialize PowerShell environment (ExecutionPolicy:Unrestricted)
            + Enable PS-Remoting
            + Enable CredSSP
            + Format Extra-Disk (only if present and not yet formatted)
            + Change LCM:RebootNodeIfNeeded
            + Apply this configuration
        #>

        if ($Node.Environment.Host -and
            $Node.Environment.Host.Share -and
            $Node.Environment.Host.Share.UserName -and
            $Node.Environment.Host.Share.Password) {
            $sharePath = "\\$($Node.Environment.Host.Name)\$($Node.Environment.Host.Share.Name)"
            $shareCredential = New-Object -TypeName PSCredential -ArgumentList "$($Node.Environment.Host.Name)\$($Node.Environment.Host.Share.UserName)",$Node.Environment.Host.Share.Password
        }

        CommonServer CommonServer {
            ShareHostName = $Node.Environment.Host.Name
            ShareCredential = $shareCredential
        }

        foreach ($networkAdapter in $Node.NetworkAdapters) {
            $network = $networkAdapter.Network
            if ($networkAdapter.StaticIPAddress -and $network.DhcpServer -and $networkAdapter.StaticIPAddress -eq $network.DhcpServer.IPAddress) {
                DhcpServer DhcpServer {
                    DhcpServer = $network.DhcpServer
                    DnsServerIPAddress = $network.DnsServer.IPAddress
                    DependsOn = '[CommonServer]CommonServer'
                }
            }
        }

        if ($Node.Role -contains 'DscPullServer') {
            DscPullServer DscPullServer {
                RegistrationKey = $Node.AllProperties.DscPullServerRegistrationKey
                DependsOn = '[CommonServer]CommonServer'
            }
        }
        if ($Node.Role -contains 'FeedServer') {
            FeedServer FeedServer {
                SharePath = $sharePath
                ShareCredential = $shareCredential
                DependsOn = '[CommonServer]CommonServer'
            }
        }
    }
}
