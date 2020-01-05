# vCDEdgeSSL.psm1
#
# PS Module to allow management of NSX Edge SSL Certificates via the vCloud API
#
# Requires that you are already connected to the appropriate vCloud Director
# site(s) - powervcav will use the $Global:DefaultCIServers context to extract
# vCD session keys and use these to authenticate to vCD. VMware PowerCLI is
# required for this module to function.
#
# Copyright 2019 Jon Waite, All Rights Reserved
# Released under MIT License - see https://opensource.org/licenses/MIT
# Date:         6th January 2020
# Version:      0.1.6




# Internal function to  return the correct member of $global:DefaultCIServer if
# we are connected to multiple clouds and the -Server parameter has been
# provided or the current instance if only connected to one server.
Function Get-vCDServerRef{
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$false)][String]$Server
    )
    # If not connected generate error and exit
    if (-Not $Global:DefaultCIServers) {
        Write-Host -ForegroundColor Red ("Error: Not connected to any vCloud Director endpoints, use Connect-CIServer to connect prior to running commands.")
        Break
    }
    if ($Global:DefaultCIServers.Count -gt 1) { # If connected to multiple clouds
        if (-not $Server) { # and no -Server parameter provided, generate error and exit
            Write-Host -ForegroundColor Red ("Error: You are currently connected to more than one vCD API Endpoint, the -Server parameter must be used to specify which one to operate against. Connected vCD endpoints:")
            foreach ($vcdserver in $global:DefaultCIServers) {
                Write-Host -ForegroundColor Cyan ($vcdserver.Name)
            }
            Break
        } else { # -Server parameter has been specified
            ForEach ($ServerCon in $Global:DefaultCIServers) {
                if ($ServerCon.Name.ToLower() -eq $Server.ToLower()) { # Found a match
                    Write-Host 'Found Match'
                    return $ServerCon
                }
            }
            # No match found
            Write-Host -ForegroundColor Red ("Error: Could not match an API connection to server '$($Server)'. Connected vCD endpoints:")
            foreach ($vcdserver in $global:DefaultCIServers) {
                Write-Host -ForegroundColor Cyan ($vcdserver.Name)
            }
            Break
        }
    } else { # Only connected to 1 cloud
        if ($Server) {
            if ($Global:DefaultCIServers[0].Name.ToLower() -ne $Server.ToLower()) {
                Write-Host -ForegroundColor Red ("Error: Specified server name '$($Server)' does not match currently connected cloud name '$($Global:DefaultCIServers[0].Name)'.")
                Break
            } else { # Name matches
                return $Global:DefaultCIServers[0]
            }
        }
        return $Global:DefaultCIServers[0]
    }
}

# Internal function to return the highest supported vCD API version on the 
# specified endpoint (or connected endpoint if only 1).
Function Get-vCDAPIVersion{
    [cmdletbinding()]
    Param(
        [parameter(Mandatory=$False)][string]$Server    # Which API endpoint to use if connected to multiple
    )
    $serverRef = Get-vcdServerRef -Server $Server
    $uri = "https://$($serverRef.Name)/api/versions"
    $headers = @{'Accept'='application/*+xml'}
    Try {
        [xml]$r = Invoke-WebRequest -Method Get -Uri $uri -Headers $headers -ErrorAction Stop
    } Catch {
        Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
        Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
        Break
    }
    $apivers = (($r.SupportedVersions.VersionInfo | Where-Object { $_.deprecated -eq $False }) `
        | Measure-Object -Property Version -Maximum).Maximum.ToString() + ".0"
    return $apivers
}

Function Get-EdgeSSLCert{
    <#
    .SYNOPSIS
    Retrieves SSL Certificates on the specified NSX Edge Gateway for a vCloud Director
    tenant organization.
    .DESCRIPTION
    Get-EdgeSSLCert retrieves all (or optionally a single) object representing the SSL
    certificates installed on a vCloud Director edge gateway. The Id field in the
    returned object can be used for other cmdlets in this module
    (e.g Create-EdgeSSLCert and Update-EdgeSSLCert). Available Edge Gateways can be
    obtained from the VMware Get-EdgeGateway cmdlet.
    .PARAMETER Server
    Optional parameter specifying which vCloud Director API endpoint should be used
    if currently connected to multiple endpoints. If only connected to a single API
    endpoint this parameter is not required.
    .PARAMETER EdgeGW
    Parameter representing the NSX Edge Gateway to operate against. Either this
    parameter or the EdgeGWName parameter must be specified. An object returned by
    the Get-EdgeGateway cmdlet can be piped to Get-EdgeSSLCert.
    .PARAMETER EdgeGWName
    The name of the NSX Edge Gateway to operate against. Either this parameter or
    the EdgeGW parameter must be specified. If the name cannot be matched to an
    accessible Edge Gateway an error is returned.
    .PARAMETER CertName
    An optional parameter that attempts to match the certificate name provided and
    will only return a certificate whose name matches exactly.
    .PARAMETER CertId
    An optional parameter that attempts to match the certificate Id provided and
    will only return a certificate whose Id matches exactly.
    .OUTPUTS
    Any matching SSL Certificates are returned as a PSCustomObject containing the
    details of the certificate(s).
    .EXAMPLE
    Get-EdgeGateway | Get-EdgeSSLCert
    .EXAMPLE
    Get-EdgeGateway | Get-EdgeSSLCert -EdgeGWName 'MyEdge'
    .EXAMPLE
    Get-EdgeGateway | Get-EdgeSSLCert -CertName 'My Service Certificate'
    .NOTES
    Must be already connected to the vCloud Director API (Connect-CIServer) prior
    to running this command. Must have permissions in vCloud Director to allow
    access to the Edge Gateway configuration (typically Organization Administrator).
    #>
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$False)][string]$Server,
        [parameter(ValueFromPipeline=$True,Mandatory=$False)]$EdgeGW,
        [parameter(Mandatory=$False)][string]$EdgeGWName,
        [parameter(Mandatory=$False)][string]$CertName,
        [parameter(Mandatory=$False)][string]$CertId
    )

    Process{
        # Check we are connected and obtain environment details:
        $ServerRef = Get-vcdServerRef -Server $Server
        $apiVersion = Get-vCDAPIVersion -Server $Server
        $sessionId = $ServerRef.SessionId
        $Server = $ServerRef.Name

        # If EdgeGWName is supplied, attempt to locate an Edge Gateway with that name
        If ($EdgeGWName) {
            Try {
                $EdgeGW = Get-EdgeGateway -Server $Server -Name $EdgeGWName -ErrorAction Stop
            } Catch {
                Write-Host -ForegroundColor Yellow ("Could not find Edge Gateway with name: " + $EdgeGWName)
                break
            }
        } else {
            Try {
                $EdgeGW = Get-EdgeGateway -Server $Server -ErrorAction Stop
            } Catch {
                Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
                Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
                Break
            }
        } # If EdgeGWName is specified

        # If we have an Edge Gateway object, process it
        If (!$EdgeGW[0].Id) {
            Write-Host -ForegroundColor Yellow ("No Edge Gateway Found")
            break
        }

        $certs = @()

        Foreach ($edge in $EdgeGW) { # Process each edge gateway in turn if more than one

            $EdgeSvr = $edge.Href.SubString(0,$edge.Href.IndexOf('/api/admin'))
            $EdgeId = $edge.Id.Substring($edge.Id.LastIndexOf(':') +1)
    
            # Get certificates from the Edge GW:
            $CertURI = "$($EdgeSvr)/network/services/truststore/certificate/scope/$($EdgeId)/"
            $headers = @{'x-vcloud-authorization'=$sessionId;'Accept'='application/*+xml;version=' + $apiVersion}
            Try {
                [xml]$r = Invoke-WebRequest -Uri $CertURI -Headers $headers -Method Get
            } Catch {
                Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
                Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
                Break
            }

            if ($r.certificates.certificate.objectId) { # If certificates found in store
                ForEach ($cert in $r.Certificates.certificate) {

                    $certfile = $env:TMP + "cert-data"
                    Set-Content -Path $certfile -Value $cert.pemEncoding
                    $x509cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($certfile)
                    
                    $certObj = [PSCustomObject]@{
                        'EdgeGWName'        = [string]$edge.Name
                        'EdgeGWId'          = [string]$EdgeId
                        'CertName'          = [string]$cert.name
                        'CertId'            = [string]$cert.objectId
                        'CertRef'           = [string]$cert.objectId.Substring($cert.objectId.LastIndexOf(':') + 1)
                        'CertSerial'        = [string]$x509cert.GetSerialNumberString()
                        'CertIssuer'        = [string]$x509cert.GetIssuerName()
                        'CertSubject'       = [string]$x509cert.Subject
                        'CertDescription'   = [string]$cert.description
                        'CertNotBefore'     = Get-Date($x509cert.GetEffectiveDateString())
                        'CertNotAfter'      = Get-Date($x509cert.GetExpirationDateString())
                        'CertThumbprint'    = [String]$x509cert.GetCertHashString() -replace '(..(?!$))','$1:'
                        'CertDaysToExpiry'  = [Int]$cert.daysLeftToExpiry
                    }

                    $certs += $certObj
                } # For each certificate found
            } # if certificates found in store
        } # Each gateway processed

        if ($CertName -or $CertId) { # If we've asked to match on name or Id, find match and return it
            ForEach ($cert in $certs) {
                if ($CertName) { if ($cert.CertName.ToLower() -eq $CertName.ToLower()) { return $cert } }
                if ($CertId)   { if ($cert.CertId.ToLower()   -eq $CertId.ToLower())   { return $cert } }
            }
            if ($CertName) { Write-Host -ForegroundColor Yellow ("Could not find a matching certificate with name '$($CertName)'.") }
            if ($CertId) { Write-Host -ForegroundColor Yellow ("Could not find a matching certificate with Id '$($CertId)'.") }
            break
        }

        # Otherwise return collection of all found certificates:
        if ($certs.Count -gt 0) {
            return $certs
        } else {    
            Write-Host -ForegroundColor Yellow ("No SSL certificates found on Edge Gateway '$($EdgeGW.Name)' in OrgVDC '$($EdgeGW.OrgVdc)'.")
        }
    } # Process
} # Get-SSLEdge Function




Function Add-EdgeSSLCert{
    <#
    .SYNOPSIS
    Add a new SSL Certificate to the specified Edge Gateway
    .DESCRIPTION
    This cmdlet will add a new SSL certificate to the specified NSX Edge
    Gateway from the files specified in CertFile and CertKeyFile. You must
    specify the Server if currently connected to multiple vCloud Director API
    endpoints. You must also specify which Edge Gateway to add the certificate
    to (even if only one exists). Get-EdgeGateway can provide a list of
    accessible gateways.
    .PARAMETER Server
    Optional parameter specifying which vCloud Director API endpoint should be
    used if currently connected to multiple endpoints. If only connected to a
    single API endpoint this parameter is not required.
    .PARAMETER EdgeGW
    Parameter representing the NSX Edge Gateway to operate against. Either this
    parameter or the EdgeGWName parameter must be specified. An object returned
    by the Get-EdgeGateway cmdlet can be piped to Add-EdgeSSLCert.
    .PARAMETER EdgeGWName
    The name of the NSX Edge Gateway to operate against. Either this parameter
    or the EdgeGW parameter must be specified. If the name cannot be matched to
    an accessible Edge Gateway an error is returned.
    .PARAMETER CertFile
    A text file containing the public key (PEM format) of the certificate to be
    uploaded to the Edge Gateway.
    .PARAMETER CertKeyFile
    A text file containing the private key (PEM format) of the certificate to
    be uploaded to the Edge Gateway, cannot be encrypted or passphrase
    protected. If not specified the uploaded certificate can only be used as a
    reference (e.g. Issuer certificate) and not for a service endpoint.
    .PARAMETER CertDescription
    An optional description of the certificate which will be visible in the
    Edge Gateway view in vCloud Director
    .OUTPUTS
    An object containing the certificate details is returned on successful
    upload/creation of a certificate.
    .EXAMPLE
    Add-EdgeSSLCert -EdgeGWName 'MyEdge' -CertFile 'issuer.pem' -CertDescription 'Issuer Certificate'
    .EXAMPLE
    Add-EdgeSSLCert -EdgeGWName 'MyEdge' -CertFile 'cert.pem' -CertKeyFile 'cert.key' -CertDescription 'My Signed Certificate'
    .NOTES
    Must be already connected to the vCloud Director API (Connect-CIServer) prior
    to running this command. Must have permissions in vCloud Director to allow
    access to the Edge Gateway configuration (typically Organization Administrator).
    #>
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$False)][string]$Server,
        [parameter(ValueFromPipeline=$True,Mandatory=$False)][VMware.VimAutomation.Cloud.Types.V1.EdgeGateway]$EdgeGW,
        [parameter(Mandatory=$False)][string]$EdgeGWName,
        [parameter(Mandatory=$True)][string]$CertFile,
        [parameter(Mandatory=$False)][string]$CertKeyFile,
        [parameter(Mandatory=$False)][string]$CertDescription
    )

    Process{
        # Check we are connected and obtain environment details:
        $ServerRef = Get-vcdServerRef -Server $Server
        $apiVersion = Get-vCDAPIVersion -Server $Server
        $sessionId = $ServerRef.SessionId
        $Server = $ServerRef.Name

        # If EdgeGWName is supplied, attempt to locate an Edge Gateway with that name
        If (!$EdgeGWName) {
            if (!$EdgeGW) {
                Write-Host -ForegroundColor Yellow ("You must specify an EdgeGW or EdgeGWName to add an SSL Certificate.")
                break
            }      
        } else {
        
            Try {
                $EdgeGW = Get-EdgeGateway -Server $Server -Name $EdgeGWName -ErrorAction Stop
            } Catch {
                Write-Host -ForegroundColor Yellow ("Could not find Edge Gateway with name '$($EdgeGWName)'.")
                break
            }
        }

        $EdgeSvr = $EdgeGW.Href.SubString(0,$EdgeGW.Href.IndexOf('/api/admin'))
        $EdgeId = $EdgeGW.Id.Substring($EdgeGW.Id.LastIndexOf(':') +1)
 
        # Make a new XML TrustObject for the Certificate from files:
        Try {
            $pemcert = Get-Content $CertFile -Raw -ErrorAction Stop
            $prvcert = Get-Content $CertKeyFile -Raw -ErrorAction Stop
        } Catch {
            Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
            Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
            Break
        }

        # Build XML Body containing the new certificate
        [xml]$cert = New-Object System.Xml.XmlDocument
        $cert.AppendChild($cert.CreateXmlDeclaration("1.0","UTF-8",$null)) | Out-Null
        $root = $cert.CreateElement("trustObject")
        $cert.AppendChild($root) | Out-Null

        $pem = $root.AppendChild($cert.CreateElement("pemEncoding"))
        $pem.AppendChild($cert.CreateTextNode($pemcert)) | Out-Null
        $prv = $root.AppendChild($cert.CreateElement("privateKey"))
        $prv.AppendChild($cert.CreateTextNode($prvcert)) | Out-Null
        $desc = $root.AppendChild($cert.CreateElement("description"))
        $desc.AppendChild($cert.CreateTextNode($CertDescription)) | Out-Null

        # Try to upload the cert to vCD
        $CertURI = "$($EdgeSvr)/network/services/truststore/certificate/$($EdgeId)/"
        $headers = @{'x-vcloud-authorization'=$sessionId;'Accept'='application/*+xml;version=' + $apiVersion}
        Try {
            [xml]$r = Invoke-WebRequest -Uri $CertURI -Headers $headers -Method Post -ContentType 'application/xml' -Body $cert.InnerXml -ErrorAction Stop
            Write-Host -ForegroundColor Green ("Certificate '$($r.certificates.certificate.name)' added successfully.")


        } Catch {
            Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
            Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
            Break
        }

        # Build PSCustomObject of uploaded certificate and return:
        $NewCert = $r.certificates.certificate
        $tmpcertfile = $env:TMP + "cert-data"
        Set-Content -Path $tmpcertfile -Value $NewCert.pemEncoding
        $x509cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($certfile)
        
        $certObj = [PSCustomObject]@{
            'EdgeGWName'        = [string]$EdgeGW.Name
            'EdgeGWId'          = [string]$EdgeId
            'CertName'          = [string]$NewCert.name
            'CertId'            = [string]$NewCert.objectId
            'CertRef'           = [string]$NewCert.objectId.Substring($NewCert.objectId.LastIndexOf(':') + 1)
            'CertSerial'        = [string]$x509cert.GetSerialNumberString()
            'CertIssuer'        = [string]$x509cert.GetIssuerName()
            'CertSubject'       = [string]$x509cert.Subject
            'CertDescription'   = [string]$NewCert.description
            'CertNotBefore'     = Get-Date($x509cert.GetEffectiveDateString())
            'CertNotAfter'      = Get-Date($x509cert.GetExpirationDateString())
            'CertThumbprint'    = [String]$x509cert.GetCertHashString() -replace '(..(?!$))','$1:'
            'CertDaysToExpiry'  = [Int]$NewCert.daysLeftToExpiry
        }
        return $certObj

    } # Process
} # Add-EdgeSSLCert Function





Function Remove-EdgeSSLCert{
    <#
    .SYNOPSIS
    Delete an SSL Certificate from the specified Edge Gateway
    .DESCRIPTION
    This cmdlet will remove an existing SSL certificate from the specified NSX
    Edge Gateway. You must specify the Server if currently connected to
    multiple vCloud Director API endpoints. You must also specify which Edge
    Gateway to remove the certificate from (even if only one exists).
    Get-EdgeSSLCert can provide a list of certificates on gateways.
    .PARAMETER Server
    Optional parameter specifying which vCloud Director API endpoint should be
    used if currently connected to multiple endpoints. If only connected to a
    single API endpoint this parameter is not required.
    .PARAMETER EdgeGW
    Parameter representing the NSX Edge Gateway to operate against. Either this
    parameter or the EdgeGWName parameter must be specified. An object returned
    by the Get-EdgeGateway cmdlet can be piped to Add-EdgeSSLCert.
    .PARAMETER EdgeGWName
    The name of the NSX Edge Gateway to operate against. Either this parameter
    or the EdgeGW parameter must be specified. If the name cannot be matched to
    an accessible Edge Gateway an error is returned.
    .PARAMETER CertId
    The ID reference of the certificate to be removed from the Edge Gateway.
    This Id is a combination of the Edge Gateway and Certificate Ids as
    returned by the Get-EdgeSSLCert cmdlet.
    .OUTPUTS
    A message indicating whether the operation was successfully completed or
    not.
    .EXAMPLE
    Remove-EdgeSSLCert -EdgeGWName 'MyEdge' -CertId '610f4180-9316-4d60-9500-527708c9bfc1:certificate-18'
    .NOTES
    Must be already connected to the vCloud Director API (Connect-CIServer) prior
    to running this command. Must have permissions in vCloud Director to allow
    access to the Edge Gateway configuration (typically Organization Administrator).
    #>
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$False)][string]$Server,
        [parameter(ValueFromPipeline=$True,Mandatory=$False)][VMware.VimAutomation.Cloud.Types.V1.EdgeGateway]$EdgeGW,
        [parameter(Mandatory=$False)][string]$EdgeGWName,
        [parameter(Mandatory=$True)][string]$CertId
    )

    Process{
        # Check we are connected and obtain environment details:
        $ServerRef = Get-vcdServerRef -Server $Server
        $apiVersion = Get-vCDAPIVersion -Server $Server
        $sessionId = $ServerRef.SessionId
        $Server = $ServerRef.Name

        # If EdgeGWName is supplied, attempt to locate an Edge Gateway with that name
        If (!$EdgeGWName) {
            if (!$EdgeGW) {
                Write-Host -ForegroundColor Yellow ("You must specify an EdgeGW or EdgeGWName to add an SSL Certificate.")
                break
            }      
        } else {
        
            Try {
                $EdgeGW = Get-EdgeGateway -Server $Server -Name $EdgeGWName -ErrorAction Stop
            } Catch {
                Write-Host -ForegroundColor Yellow ("Could not find Edge Gateway with name '$($EdgeGWName)'.")
                break
            }
        }
        $EdgeSvr = $EdgeGW.Href.SubString(0,$EdgeGW.Href.IndexOf('/api/admin'))
 
        # Try to remove the cert from vCD
        $CertURI = "$($EdgeSvr)/network/services/truststore/certificate/$($CertId)"
        $headers = @{'x-vcloud-authorization'=$sessionId;'Accept'='application/*+xml;version=' + $apiVersion}
        Try {
            Invoke-WebRequest -Uri $CertURI -Headers $headers -Method Delete -ContentType 'application/xml' -ErrorAction Stop | Out-Null
            Write-Host -ForegroundColor Green ("Certificate '$($CertId)' removed from Edge Gateway '$($EdgeGW.Name)' successfully.")
        } Catch {
            Write-Host -ForegroundColor Red("Error: Error encountered attempting to remove certificate '$($CertId)' from Edge Gateway '$($EdgeGW.Name)'.")
            Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
            Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
            Break
        }
    } # Process
} # Remove-EdgeSSLCert Function




Function Get-EdgeAppProfile{
    <#
    .SYNOPSIS
    Returns all application profiles on the specified Edge gateway. 
    .DESCRIPTION
    Get-EdgeAppProfile returns a custom PSObject containing details of the
    application profiles on the specified Edge gateway. If the optional
    AppProfileName parameter is specified only returns the first application
    profile which matches this parameter.
    .PARAMETER Server
    Optional parameter specifying which vCloud Director API endpoint should be
    used if currently connected to multiple endpoints. If only connected to a
    single API endpoint this parameter is not required.
    .PARAMETER EdgeGW
    Parameter representing the NSX Edge Gateway to operate against. Either this
    parameter or the EdgeGWName parameter must be specified. An object returned
    by the Get-EdgeGateway cmdlet can be piped to Add-EdgeSSLCert.
    .PARAMETER EdgeGWName
    The name of the NSX Edge Gateway to operate against. Either this parameter
    or the EdgeGW parameter must be specified. If the name cannot be matched to
    an accessible Edge Gateway an error is returned.
    .PARAMETER AppProfileName
    An optional parameter to filter the returned results to a single
    application profile if a matching name is found on the specified edge
    gateway.
    .OUTPUTS
    A custom PSObject containing details of the application profiles on the
    specified Edge gateway.
    .EXAMPLE
    Get-EdgeAppProfile -EdgeGWName 'MyEdge'
    .NOTES
    Must be already connected to the vCloud Director API (Connect-CIServer) prior
    to running this command. Must have permissions in vCloud Director to allow
    access to the Edge Gateway configuration (typically Organization Administrator).
    #>
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$False)][string]$Server,
        [parameter(ValueFromPipeline=$True,Mandatory=$False)][VMware.VimAutomation.Cloud.Types.V1.EdgeGateway]$EdgeGW,
        [parameter(Mandatory=$False)][string]$EdgeGWName,
        [parameter(Mandatory=$False)][string]$AppProfileName
    )

    Process{
        # Check we are connected and obtain environment details:
        $ServerRef = Get-vcdServerRef -Server $Server
        $apiVersion = Get-vCDAPIVersion -Server $Server
        $sessionId = $ServerRef.SessionId
        $Server = $ServerRef.Name

        # If EdgeGWName is supplied, attempt to locate an Edge Gateway with that name
        If (!$EdgeGWName) {
            if (!$EdgeGW) {
                Write-Host -ForegroundColor Yellow ("You must specify an EdgeGW or EdgeGWName.")
                break
            }      
        } else {
        
            Try {
                $EdgeGW = Get-EdgeGateway -Server $Server -Name $EdgeGWName -ErrorAction Stop
            } Catch {
                Write-Host -ForegroundColor Yellow ("Could not find Edge Gateway with name '$($EdgeGWName)'.")
                break
            }
        }
        $EdgeSvr = $EdgeGW.Href.SubString(0,$EdgeGW.Href.IndexOf('/api/admin'))
        $EdgeId = $EdgeGW.Id.Substring($EdgeGW.Id.LastIndexOf(':') +1)
 
        # Attempt to retrieve a list of application profiles from the Edge Gateway
        $AppProfURI = "$($EdgeSvr)/network/edges/$($EdgeId)/loadbalancer/config/applicationprofiles"
        $headers = @{'x-vcloud-authorization'=$sessionId;'Accept'='application/*+xml;version=' + $apiVersion}
        Try {
            [xml]$r = Invoke-WebRequest -Uri $AppProfURI -Headers $headers -Method Get -ContentType 'application/xml' -ErrorAction Stop
        } Catch {
            Write-Host -ForegroundColor Red("Error: Error encountered attempting to retrieve application profiles from Edge Gateway '$($EdgeGW.Name)'.")
            Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
            Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
            Break
        }
        if ($r.loadBalancer.applicationProfile.applicationProfileId.Count -gt 0) { # Found 1 or more application profiles
            $appProfs = @()
            ForEach ($appProf in $r.loadBalancer.applicationProfile) {

                if ($appProf.clientSsl.serviceCertificate) {
                    $appProfCertRef = $EdgeId + ":" + $appProf.clientSsl.serviceCertificate
                } else {
                    $appProfCertRef = $null
                }

                $appProfObj = [PSCustomObject]@{
                    'Name'                 = [string]$appProf.name
                    'ProfileId'            = [string]$appProf.applicationProfileId
                    'CertId'               = [string]$appProfCertRef
                    'SSLEnabled'           = [boolean]$appProf.serverSslEnabled
                }
                $appProfs += $appProfObj
            }
            if ($AppProfileName) { # Match a particular application profile name
                ForEach ($appProf in $appProfs) {
                    if ($AppProfileName.ToLower() -eq $AppProf.Name.ToLower()) { # Match found
                        return $appProf
                    }
                }
                Write-Host -ForegroundColor Yellow ("No application profile matching name $($AppProfileName) found.")
                Break
            } else { # No AppProfileName specified - return all profiles:
                return $appProfs
            }

        } else {
            Write-Host -ForegroundColor Yellow ("Did not find any application profiles on '$($EdgeGW.Name)' Edge Gateway.")
        }
    } # Process
} # Get-EdgeAppProfiles Function




Function Set-EdgeAppProfileCert{
    <#
    .SYNOPSIS
    Updates the certificate used by the specified application profile on the
    Edge gateway to the specified certificate.
    .DESCRIPTION
    Set-EdgeAppProfileCert updates the application profile on the Edge
    Gateway to the provided certificate reference. Available certificate
    Ids can be retrieved using the Get-EdgeSSLCert cmdlet, available
    application profiles can be retrieved using the Get-EdgeAppProfiles
    cmdlet.
    .PARAMETER Server
    Optional parameter specifying which vCloud Director API endpoint should be
    used if currently connected to multiple endpoints. If only connected to a
    single API endpoint this parameter is not required.
    .PARAMETER EdgeGW
    Parameter representing the NSX Edge Gateway to operate against. Either this
    parameter or the EdgeGWName parameter must be specified. An object returned
    by the Get-EdgeGateway cmdlet can be piped to Add-EdgeSSLCert.
    .PARAMETER EdgeGWName
    The name of the NSX Edge Gateway to operate against. Either this parameter
    or the EdgeGW parameter must be specified. If the name cannot be matched to
    an accessible Edge Gateway an error is returned.
    .PARAMETER AppProfileName
    The name of the application profile whose certificate is to be updated as
    returned by the Get-EdgeAppProfiles cmdlet.
    .PARAMETER CertId
    The certificate Id to be configured for the specified application profile
    as returned by the Get-EdgeSSLCert. Note that a full certificate Id is
    required which includes the Edge Gateway Id and the certificate reference
    e.g. 'b1b92ec7-4263-4d81-af2a-c9ab5bae08ca:certificate-21'
    .OUTPUTS
    A message indicating whether the application certificate was successfully
    updated or not.
    .EXAMPLE
    Set-EdgeAppProfileCert -EdgeGWName 'MyEdge' -AppProfileName 'MyWebServer' -CertId 'b1b92ec7-4263-4d81-af2a-c9ab5bae08ca:certificate-21'
    .NOTES
    Must be already connected to the vCloud Director API (Connect-CIServer) prior
    to running this command. Must have permissions in vCloud Director to allow
    access to the Edge Gateway configuration (typically Organization Administrator).
    #>
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$False)][string]$Server,
        [parameter(ValueFromPipeline=$True,Mandatory=$False)][VMware.VimAutomation.Cloud.Types.V1.EdgeGateway]$EdgeGW,
        [parameter(Mandatory=$False)][string]$EdgeGWName,
        [parameter(Mandatory=$True)][string]$AppProfileName,
        [parameter(Mandatory=$True)][String]$CertId
    )


    Process{
        # Check we are connected and obtain environment details:
        $ServerRef = Get-vcdServerRef -Server $Server
        $apiVersion = Get-vCDAPIVersion -Server $Server
        $sessionId = $ServerRef.SessionId
        $Server = $ServerRef.Name

        # If EdgeGWName is supplied, attempt to locate an Edge Gateway with that name
        If (!$EdgeGWName) {
            if (!$EdgeGW) {
                Write-Host -ForegroundColor Yellow ("You must specify an EdgeGW or EdgeGWName.")
                break
            }      
        } else {
        
            Try {
                $EdgeGW = Get-EdgeGateway -Server $Server -Name $EdgeGWName -ErrorAction Stop
            } Catch {
                Write-Host -ForegroundColor Yellow ("Could not find Edge Gateway with name '$($EdgeGWName)'.")
                break
            }
        }
        $EdgeSvr = $EdgeGW.Href.SubString(0,$EdgeGW.Href.IndexOf('/api/admin'))
        $EdgeId = $EdgeGW.Id.Substring($EdgeGW.Id.LastIndexOf(':') +1)

        # Check both objects exist (the application profile and certificate):
        $AppProf = Get-EdgeAppProfile -Server $Server -EdgeGW $EdgeGW -AppProfileName $AppProfileName
        $Cert = Get-EdgeSSLCert -Server $Server -EdgeGW $EdgeGW -CertId $CertId

        $AppProfURI = "$($EdgeSvr)/network/edges/$($EdgeId)/loadbalancer/config/applicationprofiles/$($AppProf.ProfileId)"
        $headers = @{'x-vcloud-authorization'=$sessionId;'Accept'='application/*+xml;version=' + $apiVersion}

        Try { # Get current XML definition of application profile
            [xml]$r = Invoke-WebRequest -Uri $AppProfURI -Method Get -Headers $Headers -ErrorAction Stop
        } Catch {
            Write-Host -ForegroundColor Red("Error: Error encountered attempting to read application profile '$($AppProf.Name)' from Edge Gateway '$($EdgeGW.Name)'.")
            Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
            Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
            Break
        }

        # Update to new certificate:
        $r.applicationProfile.clientSsl.serviceCertificate = $cert.CertRef

        Try {
            Invoke-WebRequest -Uri $AppProfURI -Method Put -Headers $headers -Body $r.OuterXml -ContentType 'application/xml' -ErrorAction Stop | Out-Null
        } Catch {
            Write-Host -ForegroundColor Red("Error: Error encountered attempting to update application profile '$($AppProf.Name)' on Edge Gateway '$($EdgeGW.Name)'.")
            Write-Host -ForegroundColor Red ("Error: $($_.Exception.Message)")
            Write-Host -ForegroundColor Red ("Item: $($_.Exception.ItemName)")
            Break
        }
        Write-Host -ForegroundColor Green ("Application profile '$($AppProf.Name)' updated successfully.")
    } # Process
} # Set-EdgeAppProfileCert




Function Update-EdgeAppProfileCert{
    <#
    .SYNOPSIS
    Updates the specified Edge Gateway application profile to use the supplied
    certificate and (optionally) removes the old/existing certificate from the
    certificate store.
    .DESCRIPTION
    Update-EdgeAppProfileCert allows an 'all in one' replacement of the SSL
    certificate assigned to a Load Balancer application profile on an Edge
    Gateway and can also remove the previous certificate if required.
    .PARAMETER Server
    Optional parameter specifying which vCloud Director API endpoint should be
    used if currently connected to multiple endpoints. If only connected to a
    single API endpoint this parameter is not required.
    .PARAMETER EdgeGW
    Parameter representing the NSX Edge Gateway to operate against. Either this
    parameter or the EdgeGWName parameter must be specified. An object returned
    by the Get-EdgeGateway cmdlet can be piped to Add-EdgeSSLCert.
    .PARAMETER EdgeGWName
    The name of the NSX Edge Gateway to operate against. Either this parameter
    or the EdgeGW parameter must be specified. If the name cannot be matched to
    an accessible Edge Gateway an error is returned.
    .PARAMETER AppProfileName
    The name of the application profile whose certificate is to be updated as
    returned by the Get-EdgeAppProfiles cmdlet.
    .PARAMETER CertFile
    A text file containing the public key (PEM format) of the certificate to be
    uploaded to the Edge Gateway.
    .PARAMETER CertKeyFile
    A text file containing the private key (PEM format) of the certificate to
    be uploaded to the Edge Gateway, cannot be encrypted or passphrase
    protected.
    .PARAMETER CertDescription
    An optional description of the certificate which will be visible in the
    Edge Gateway view in vCloud Director
    .PARAMETER RemoveOldCert
    An optional boolean parameter (defaults to 'False') which specifies
    whether the 'old' certificate previously assigned to the application
    profile should be removed from the Edge Gateway if the certificate
    update is successful.
    .OUTPUTS
    A message indicating whether the application certificate was successfully
    updated or not.
    .EXAMPLE
    Update-EdgeAppProfileCert -EdgeGWName 'MyEdge' -AppProfileName 'MyWebServer' -CertFile website.cer -CertKeyFile website.key -CertDescription 'My Web Server' -RemoveOldCert $true
    .NOTES
    Must be already connected to the vCloud Director API (Connect-CIServer) prior
    to running this command. Must have permissions in vCloud Director to allow
    access to the Edge Gateway configuration (typically Organization Administrator).
    #>
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$False)][string]$Server,
        [parameter(ValueFromPipeline=$True,Mandatory=$False)][VMware.VimAutomation.Cloud.Types.V1.EdgeGateway]$EdgeGW,
        [parameter(Mandatory=$False)][string]$EdgeGWName,
        [parameter(Mandatory=$True)][string]$AppProfileName,
        [parameter(Mandatory=$True)][String]$CertFile,
        [parameter(Mandatory=$True)][String]$CertKeyFile,
        [parameter(Mandatory=$False)][String]$CertDescription,
        [parameter(Mandatory=$False)][Boolean]$RemoveOldCert = $False
    )
    Process{
        # Check we are connected and obtain environment details:
        $ServerRef = Get-vcdServerRef -Server $Server
        $Server = $ServerRef.Name

        # If EdgeGWName is supplied, attempt to locate an Edge Gateway with that name
        If (!$EdgeGWName) {
            if (!$EdgeGW) {
                Write-Host -ForegroundColor Yellow ("You must specify an EdgeGW or EdgeGWName.")
                break
            }      
        } else {
        
            Try {
                $EdgeGW = Get-EdgeGateway -Server $Server -Name $EdgeGWName -ErrorAction Stop
            } Catch {
                Write-Host -ForegroundColor Yellow ("Could not find Edge Gateway with name '$($EdgeGWName)'.")
                break
            }
        }

        # Check the specified application profile exists and get it's current certificate Id:
        $AppProf = Get-EdgeAppProfile -Server $Server -EdgeGW $EdgeGW -AppProfileName $AppProfileName
        $OldCertId = $AppProf.CertId

        # Upload the new certificate to this Edge GW:
        $NewCert = Add-EdgeSSLCert -Server $Server -EdgeGW $EdgeGW -CertFile $CertFile -CertKeyFile $CertKeyFile -CertDescription $CertDescription

        # Change the application profile to use this new certificate:
        Set-EdgeAppProfileCert -Server $Server -EdgeGW $EdgeGW -AppProfileName $AppProfileName -CertId $NewCert.CertId

        # Optionally remove the 'old' certificate:
        if ($RemoveOldCert) {
            Remove-EdgeSSLCert -Server $Server -EdgeGW $EdgeGW -CertId $OldCertId
        }
    } # Process
} # Update-EdgeAppProfileCert

# Export the public functions from this module to the environment:
Export-ModuleMember -Function Get-EdgeSSLCert
Export-ModuleMember -Function Add-EdgeSSLCert
Export-ModuleMember -Function Remove-EdgeSSLCert
Export-ModuleMember -Function Get-EdgeAppProfile
Export-ModuleMember -Function Set-EdgeAppProfileCert
Export-ModuleMember -Function Update-EdgeAppProfileCert