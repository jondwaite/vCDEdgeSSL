# vCloud Director NSX Edge SSL Certificate Management

## Introduction

This PowerShell module provides cmdlets to make it easier to view and manipulate
the SSL certificates assigned to an NSX Edge Gateway when deployed as part of a
VMware vCloud Director environment. Typically tenants in such an environment
will not have direct access to the NSX API, but fortunately VMware provide a
proxy-service via the vCloud Director API which allows tenant users to manipulate
any NSX Edge Gateways deployed to their environment. It is this vCloud Director
proxy service which this module uses.

An obvious use-case for these is to automate updating/replacing the SSL
certificates on services published via NSX-V load balancers when certificates
expire or need to be regenrated (e.g. using Let's Encrypt 90-day certificates).

The modules will detect and use the highest-available API version for the vCloud
Director platform to which the session is connected automatically. They will also
attempt to intelligently guess the name of the vCloud Director API endpoint to
use (if only connected to a single environment with Connect-CIServer this will be
used automatically, if multiple environments are connected the -Server parameter
must be provided to specify which service endpoint should be used).

## Supported Versions

These cmdlets should work on any version of vCloud Director with NSX-V, although
I have only tested on v9.5, v9.7 and v10.0. I would appreciate any feedback on
other versions and if possible will update the module to work with earlier
versions. The cmdlets will  only work against NSX Edge Gateways configured in
'Advanced' mode, but since the Load Balancer functionality is not enabled in
'Basic' mode this shouldn't be an issue.

Update for 0.1.6: This module should now work correctly on PowerShell Core
as well as PowerShell for Windows, I've tested functionality from core on
OSX and everything appears to work correctly.

## Disclaimer

I am not a professional developer and write these modules in my spare time to
help our internal IT teams and customers interact with vCloud Director platforms
which ours (and other) companies provide. There are probably many things that
could be improved in this module. If you have problems, please feel free to
contact me via Issues in Github and I will see what I can do to assist (no
guarantees though) or feel free to fix yourself and submit a PR against this
repository.

## References

The inspiration for this module came from two great blog posts written by Tom
Fojta, and from a long-standing desire to make it easier to automate the
updates to SSL certficates on NSX Edge Gateways:

[Automate Let's Encrypt Certificate for NSX Edge Load Balancer](https://fojta.wordpress.com/2016/07/16/automate-lets-encrypt-certificate-for-nsx-edge-load-balancer/)

[Automate Let's Encrypt Certificates - Part 2](https://fojta.wordpress.com/2019/12/21/automate-lets-encrypt-certificates-part-2/)

I definitely recommand checking out Tom's blog for other awesomely useful content.

## Cmdlet Summary

A summary of the cmdlets provided by the module are shown in the table below,
the sections below have full documentation for each individual cmdlet (linked
from the table).

| cmdlet Name | Description |
| ----------- | ----------- |
| [`Get-EdgeSSLCert`](#Get-EdgeSSLCert) | Retrieves one or more SSL certificates from one or more NSX Edge Gateways |
| [`Add-EdgeSSLCert`](#Add-EdgeSSLCert) | Adds an SSL certificate to the specified NSX Edge Gateway |
| [`Remove-EdgeSSLCert`](#Remove-EdgeSSLCert) | Removes an SSL certificate from the specified Edge Gateway |
| [`Get-EdgeAppProfile`](#Get-EdgeAppProfile) | Retrieves one or more Load Balancer application profiles from the NSX Edge Gateway |
| [`Set-EdgeAppProfileCert`](#Set-EdgeAppProfileCert) | Sets a Load Balancer application profile to use the specified SSL Certificate |
| [`Update-EdgeAppProfileCert`](#Update-EdgeAppProfileCert) | Provides a simpler method to update an application profile to use a new SSL certificate (and remove the old one) in a single operation |

## Installation

The module is published to PSGalley and can be installed for the current user
using:

`Install-Module vCDEdgeSSL -Scope CurrentUser`

or globally using:

`Install-Module vCDEdgeSSL`

You can also download the module from this repository and install it using:

`Import-Module <Download location>\vCDEdgeSSL.psm1`

## cmdlet Details

Each of the cmdlets in this module is shown in a section below together with its
parameters, outputs and examples.

### Get-EdgeSSLCert

Gets details of SSL certificates installed on Edge Gateways (or all from a
specific Edge Gateway if specified). Can also be filtered to return a single certificate.

Parameters

| Parameter | Type | Mandatory | Pipeline Input | Description |
| --------- | ---- | --------- | -------------- | ----------- |
| `Server`    | String | False* | False | Which vCloud endpoint to use for the command. *Required if connected to multiple vCloud Director endpoints |
| `EdgeGW`    | VMware.VimAutomation.Cloud.Types.V1.EdgeGateway | False | True | Which Edge Gateway to return the certificates from, suitable object can be obtained from the PowerCLI `Get-EdgeGateway` cmdlet |
| `EdgeGWName` | String | False | False | Name of the Edge Gateway to return the certificates from. Either this or the `-EdgeGW` parameter can be used to restrict which Edge Gateways are considered |
| `CertName`  | String | False | False | Name of a specific certificate to match, only the first certificate matching this name will be returned |
| `CertId`    | String | False | False | Id of a specific certificate to match, only the first certificate matching this Id will be returned |

#### Output

One or more certificates will be returned in a PSCustom Object with the
following properties:

| Property | Type | Description |
| -------- | ---- | ----------- |
| `EdgeGWName` | String | The name of the Edge Gateway where this certificate exists |
| `EdgeGWId`   | String | The Id (GUID) of the Edge Gateway where this certificate exists |
| `CertName`   | String | The name of the certificate |
| `CertId`     | String | The Id of the certificate consisting of the EdgeGWId and the Certificate reference |
| `CertRef`    | String | The certificate reference (everything after the ':' in the CertId) |
| `CertSerial` | String | The certificate serial |
| `CertIssuer` | String | The certificate issuing authority |
| `CertSubject` | String | The certificate Subject |
| `CertDescription` | String | The certificate description (if any) provided when the certificate was uploaded to vCD |
| `CertNotBefore` | DateTime | The start (valid from) date for the certificate |
| `CertNotAfter`  | DateTime | The expiry (valid to) date for the certificate |
| `CertThumbprint` | String | The certificate thumbprint |
| `CertDaysToExpiry` | Int | The number of days until the certificate expires |

#### Example

```PowerShell
PS C:\> Get-EdgeSSLCert

EdgeGWName       : Tenant Edge
EdgeGWId         : 6d64dd55-c623-47c3-8a3a-c38f85ee6216
CertName         : myserver.com
CertId           : 6d64dd55-c623-47c3-8a3a-c38f85ee6216:certificate-11
CertRef          : certificate-11
CertSerial       : 167CD77E36DD1824D50E62BCA0594430CE4E
CertIssuer       : C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
CertSubject      : CN=myserver.com
CertDescription  :
CertNotBefore    : 5/12/2019 11:09:46 PM
CertNotAfter     : 4/03/2020 11:09:46 PM
CertThumbprint   : FE:72:4F:0E:77:AB:6A:2A:95:13:B5:21:5E:C7:F4:FC:BA:3C:79:23
CertDaysToExpiry : 71
```

#### Notes

If either EdgeGW or EdgeGWName are provided and multiple Edge Gateways exist only
certificates from the matching Edge will be returned. If CertName or CertId are
specified only the first certificate matching either parameter will be returned.

### Add-EdgeSSLCert

Adds an SSL certificate to the specified Edge Gateway. The certificate files
should be in plain text/.PEM format and encrypted private keys cannot be used.

#### Parameters

| Parameter | Type | Mandatory | Pipeline Input | Description |
| --------- | ---- | --------- | -------------- | ----------- |
| `Server`    | String | False* | False | Which vCloud endpoint to use for the command. *Required if connected to multiple vCloud Director endpoints |
| `EdgeGW`   | VMware.VimAutomation.Cloud.Types.V1.EdgeGateway | False** | True | Which Edge Gateway to create the certificate on, suitable object can be obtained from the PowerCLI `Get-EdgeGateway` cmdlet |
| `EdgeGWName` | String | False** | False | Name of the Edge Gateway to create the certificate on. **Either this or the EdgeGW parameter must be used to identify the Edge Gateway where the certificate is to be created |
| `CertFile`  | String | True | False | The filename of the certificate public-key in .PEM format |
| `CertKeyFile` | String | False | False | The filename of the certificate private-key in .PEM format (see Notes) |
| `CertDescription` | String | False | False | Optional description text for the certificate which will be shown in the vCloud Director UI and by the [Get-EdgeSSLCert](Get-EdgeSSLCert) cmdlet output |

#### Output

A PSCustomObject is returned with the details of the newly added certificate
(in the same format as objects returned by the Get-EdgeSSLCert cmdlet).

#### Example

```PowerShell
PS C:\> Add-EdgeSSLCert -EdgeGWName 'Tenant Edge' -CertFile 'mycert.cer' -CertKeyFile 'mycert.key' -CertDescription 'My Website'

Certificate 'mywebserver.co.nz' added successfully.

EdgeGWName       : Tenant Edge
EdgeGWId         : b1b92ec7-4261-4d87-af1a-c9ab5bfe08ca
CertName         : mywebserver.co.nz
CertId           : b1b92ec7-4261-4d87-af1a-c9ab5bfe08ca:certificate-73
CertRef          : certificate-73
CertSerial       : 03CED77E36DD1824D50E62BCA0594430CE4E
CertIssuer       : C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3
CertSubject      : CN=mywebserver.co.nz
CertDescription  : My Website
CertNotBefore    : 5/12/2019 11:09:46 PM
CertNotAfter     : 4/03/2020 11:09:46 PM
CertThumbprint   : FE:82:4F:0E:77:AB:70:2A:95:13:B5:23:5E:C7:F4:EE:BA:3C:79:23
CertDaysToExpiry : 68
```

#### Notes

If the CertKeyFile is not provided then only the certificate's public key will
be in the created certificate which can then only be used for issuer/referrer
chains and not for hosting services from the Edge Load Balancer.

### Remove-EdgeSSLCert

Removes (deletes) an SSL certificate from the specified Edge Gateway. Note that
the certificate cannot be in use by any Edge Gateway services or the removal
will fail.

#### Parameters

| Parameter | Type | Mandatory | Pipeline Input | Description |
| --------- | ---- | --------- | -------------- | ----------- |
| `Server`    | String | False* | False | Which vCloud endpoint to use for the command. *Required if connected to multiple vCloud Director endpoints |
| `EdgeGW`    | VMware.VimAutomation.Cloud.Types.V1.EdgeGateway | False** | True | Which Edge Gateway to remove the certificate from, suitable object can be obtained from the PowerCLI `Get-EdgeGateway` cmdlet |
| `EdgeGWName` | String | False** | False | Name of the Edge Gateway to remove the certificate from. **Either this or the `-EdgeGW` parameter must be used to identify the Edge Gateway where the certificate is to be removed from |
| `CertId` | String | True | False | The Id of the certificate to be removed. Certificate Ids can be obtained from the [Get-EdgeSSLCert](Get-EdgeSSLCert) cmdlet |

#### Output

A message indicates whether or not the certificate was successfully removed
from the Edge Gateway.

#### Example

```PowerShell
PS C:\> Remove-EdgeSSLCert -EdgeGWName 'Tenant Edge' -CertId 'b1b92ec7-4261-4d87-af1a-c9ab5bfe08ca:certificate-6'
Certificate 'b1b92ec7-4261-4d87-af1a-c9ab5bfe08ca:certificate-6' removed from Edge Gateway 'Tenant Edge' successfully.
```

#### Notes

If the certificate is assigned to any services on the Edge Gateway it will not
be possible to remove it until all of these references are changed to use a
different certificate or the referencing service is removed.

### Get-EdgeAppProfile

Retrieves any defined Load Balancer application profiles from the specified
Edge Gateway.

#### Parameters

| Parameter | Type | Mandatory | Pipeline Input | Description |
| --------- | ---- | --------- | -------------- | ----------- |
| `Server`    | String | False* | False | Which vCloud endpoint to use for the command. *Required if connected to multiple vCloud Director endpoints |
| `EdgeGW`    | VMware.VimAutomation.Cloud.Types.V1.EdgeGateway | False** | True | Which Edge Gateway to retrieve application profiles from, suitable object can be obtained from the PowerCLI `Get-EdgeGateway` cmdlet |
| `EdgeGWName` | String | False** | False | Name of the Edge Gateway to retrieve application profiles from. **Either this or the `-EdgeGW` parameter must be used |
| `AppProfileName` | String | False | False | The name of an existing application profile, if matched only this application profile will be returned, if this parameter is provided and not matched a message will be generated and no application profiles will be returned |

#### Output

One or more application profiles will be returned in a PSCustom Object with the
following properties:

| Property | Type | Description |
| -------- | ---- | ----------- |
| `Name` | String | Application Profile Name |
| `ProfileId` | String | A unique identifier for this application profile |
| `CertId` | String | The certificate Id of the SSL certificate assigned to this application profile (if any) |
| `SSLEnabled` | Boolean | A flag showing whether SSL is enabled or not for this application profile |

If no application profiles are found a message will be returned stating this.
If the `-AppProfileName` parameter is provided and a matching application
profile cannot be matched to this name a message will be generated
indicating this too. In both cases no application profiles will be returned.

#### Example

```PowerShell
PS C:\> Get-EdgeAppProfile -EdgeGWName 'Tenant Edge'

Name   ProfileId            CertId                                              SSLEnabled
----   ---------            ------                                              ----------
Test02 applicationProfile-3 b1b92ec7-4261-4d87-af1a-c9ab5bfe08ca:certificate-7        True
Test01 applicationProfile-2 6d64dd55-c623-47c3-8a3a-c38f85ee6216:certificate-5        True
```

#### Notes

This cmdlet is primarily provided to obtain application profile names which
can be used with the [Set-EdgeAppProfile](Set-EdgeAppProfile) cmdlet.

### Set-EdgeAppProfile

This cmdlet can be used to point an existing application profile to use a new
SSL certificate (e.g. one provided by the [Add-SSLEdgeCert](Add-SSLEdgeCert)
cmdlet) in order to change a Load Balancer service to use a new/updated
certificate.

#### Parameters

| Parameter | Type | Mandatory | Pipeline Input | Description |
| --------- | ---- | --------- | -------------- | ----------- |
| `Server`    | String | False* | False | Which vCloud endpoint to use for the command. *Required if connected to multiple vCloud Director endpoints |
| `EdgeGW`    | VMware.VimAutomation.Cloud.Types.V1.EdgeGateway | False** | True | Which Edge Gateway to update the application profile on, suitable object can be obtained from the PowerCLI `Get-EdgeGateway` cmdlet |
| `EdgeGWName` | String | False** | False | Name of the Edge Gateway to update the application profile on. **Either this or the `-EdgeGW` parameter must be used |
| `AppProfileName` | String | True | False | The name of the application profile to be updated. A list of application profiles can be obtained from the [Get-EdgeAppProfile](Get-EdgeAppProfile) cmdlet. |
| CertId | String | True | False | The certificate Id of the new certificate to be used in the specified application profile. Certificate Ids can be obtained from the [Get-EdgeSSLCert](Get-EdgeSSLCert) cmdlet. |

#### Output

A message is returned indicating whether the application profile was updated
to the specified certificate successfully or not.

#### Example

```PowerShell
PS C:\> Set-EdgeAppProfileCert -EdgeGWName 'Tenant Edge' -AppProfileName 'MyWebServer' -CertId '6d64dd55-c623-47c3-8a3a-c38f85ee6216:certificate-5'
Application profile 'MyWebServer' updated successfully.
```

#### Notes

No check is made to see whether the specified certificate is the same (or
different) to the certificate currently used by the specified application
profile. If the same certificate is specified a 'success' message will still be
returned.

### Update-EdgeAppProfileCert

This cmdlet combines the functions in [Add-EdgeSSLCert](Add-EdgeSSLCert),
[Set-EdgeAppProfileCert](Set-EdgeAppProfileCert) and [Remove-EdgeSSLCert](Remove-EdgeSSLCert)
to provide an easier method to replace the certificate on an existing application
profile (as is commonly required when using short-lifetime certificates such as
those from Let's Encrypt). The cmdlet uploads the new certificate, changes the
application profile to use the new certificate and then removes the 'old'
certificate from the Edge Gateway. This should only be used when a certificate
is used by a single application profile, if multiple application profiles share
the same SSL certificate then use the individual cmdlets to manipulate the
application profiles.

#### Parameters

| Parameter | Type | Mandatory | Pipeline Input | Description |
| --------- | ---- | --------- | -------------- | ----------- |
| `Server`    | String | False* | False | Which vCloud endpoint to use for the command. *Required if connected to multiple vCloud Director endpoints |
| `EdgeGW`    | VMware.VimAutomation.Cloud.Types.V1.EdgeGateway | False** | True | Which Edge Gateway to update the application profile on, a suitable object can be obtained from the PowerCLI `Get-EdgeGateway` cmdlet |
| `EdgeGWName` | String | False** | False | Name of the Edge Gateway to update the application profile on. **Either this or the `-EdgeGW` parameter must be used |
| `AppProfileName` | String | True | False | The name of the application profile to be updated. A list of application profiles can be obtained from the [Get-EdgeAppProfile](Get-EdgeAppProfile) cmdlet
| `CertFile`  | String | True | False | The filename of the certificate public-key in .PEM format |
| `CertKeyFile` | String | True | False | The filename of the certificate private-key in .PEM format (see Notes) |
| `CertDescription` | String | False | False | Optional description text for the certificate which will be shown in the vCloud Director UI and by the [Get-EdgeSSLCert](Get-EdgeSSLCert) cmdlet output |
| `RemoveOldCert` | Boolean | False | False | A flag to specify whether the previous certificate assigned to this application profile should be removed from the Edge Gateway once the steps to update the profile to the new certificate have completed. If not specified this defaults to $false (do not remove).

#### Output

Messages indicate each step of the operation and whether it has completed each
successfully or not.

#### Example

```PowerShell
PS C:\> Update-EdgeAppProfileCert -EdgeGWName 'Tenant Edge' -AppProfileName 'MyWebServer' -CertFile 'webserver.cer' -CertKeyFile 'webserver.key' -CertDescription 'My Web Server' -RemoveOldCert $true
Certificate 'website.co.nz' added successfully.
Application profile 'MyWebServer' updated successfully.
Certificate '6d64dd55-c623-47c3-8a3a-c38f85ee6216:certificate-8' removed from Edge Gateway 'Tenant Edge' successfully.
```

#### Notes

Unlike the [Add-EdgeSSLCert](Add-EdgeSSLCert) cmdlet, the certificate key file
(`-CertKeyFile` parameter must be provided). Removal of the 'old' certificate
will fail if it is used by any other Edge Gateway services, in this case it
can be tidied up using the [Remove-EdgeSSLCert](Remove-EdgeSSLCert) cmdlet once
the other services have been changed to use other certificates.

## License

This module is Copyright 2019 Jon Waite

This module is made available under the [MIT License](https://opensource.org/licenses/MIT)
