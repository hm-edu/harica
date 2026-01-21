<#
.SYNOPSIS
  Name: harica.ps1
  Request SMIME certificates using the Harica CA API.

.DESCRIPTION
  This script enables NoSpamProxy customers to fully automate the S/MIME certificate enrollment using the Harica CA. The Harica CA is utilized by the DFN PKI and GÉANT TCS. To request certificates, the script uses an open-source client: https://github.com/hm-edu/harica.

.PARAMETER AdGroupId
  Specify an Active Directory security group GUID to gather the users who should receive an S/MIME certificate.
  Mandatory.

.PARAMETER CertPassword
  Specify a custom password to request all certificates and save each PFX bundle. If not specified, a random password will be generated and saved next to the requested certificate in the <WorkingDirPath>.

.PARAMETER CertificateProfile
  Define the certificate profile to be used when requesting S/MIME certificates.
  Possible values: "email_only", "natural_legal_lcp"

.PARAMETER GracePeriod
  Define the number of days before an S/MIME certificate expires to request a new certificate.

.PARAMETER HaricaConfigPath
  Define the file path for the 'cert-generator.yaml' configuration file.
  Default: <WorkingDirpath>\cert-generator.yaml

.PARAMETER IgnoreIssuers
  Specify a list of distinguished names for certificate issuers to be ignored while checking for already existing certificates for a user.

.PARAMETER IntranetRoleAddress
  Define the address for the NoSpamProxy Intranet Role Web App.
  Mandatory.

.PARAMETER MailFilter
  Define a list of email addresses for which an S/MIME certificate should be requested. All other users will be skipped.

.PARAMETER NspApiKey
  Provide a NoSpamProxy API key for authentication.

.PARAMETER Port
  Define the port of the NoSpamProxy Intranet Role Web App. Default: 6061

.PARAMETER WorkingDirPath
  Specify a file path where output files such as CSR, PEM certificate, PFX, and password file will be saved.
  Mandatory.

.PARAMETER RSA
  Choose to enroll RSA certificates.

.PARAMETER ECDSA
  Choose to enroll ECDSA certificates.

.PARAMETER KeySize
  Define the RSA key size. Default: 2048 Possible values: 2048, 3072, 4096

.PARAMETER Curve
  Define the ECC curve. Default: P256 Possible values: P256, P384

.OUTPUTS
  The script will write the CSR, PEM certificate, and PFX file to a sub folder named by the current date of the defined <WorkingDirPath> folder. If no <CertPassword> is defined, an additional TXT file containing the PFX password will also be saved.
  
.NOTES
  Version:        0.9.11
  Author:         Jan Jaeschke
  Creation Date:  2026-01-20
  Purpose/Change: added certificate typ implementation
  
.LINK
  Hompage:
    https://www.nospamproxy.de
  Help requests:
    https://forum.nospamproxy.de
    https://github.com/noSpamProxy
  Related dependencies:  
    https://harica.gr
    https://github.com/hm-edu/harica

.EXAMPLE
  Create and extend NoSpamProxy API Key:
    New-NspApiKey -Name Harica -Permissions @("read:users","read:certificates","manage:certificates")
    Reset-NspApiKeyLifetime -Id 3

.EXAMPLE
  .\harica.ps1 -IntranetRoleAddress intranetrole.example.test -RSA -WorkingDirPath "C:\harica" -AdGroupId "awdawd-98awdfaw87d-adg67awrd"

.EXAMPLE
  Only the users provided will get a certificate. The group membership is still required.
  .\harica.ps1 -IntranetRoleAddress intranetrole.example.test -MailFilter "user@example.test", "user2@example.test" -RSA -WorkingDirPath "C:\harica" -AdGroupId "awdawd-98awdfaw87d-adg67awrd"

.EXAMPLE
  Define a custom harica config path, useful to use the script for multiple organizations but the same NoSpamProxy.
  .\harica.ps1 -IntranetRoleAddress intranetrole.example.test -RSA -WorkingDirPath "C:\harica" -AdGroupId "awdawd-98awdfaw87d-adg67awrd" -HaricaConfigPath "C:\harica\custom-conf.yaml"

.EXAMPLE
  Provide a NSP API Key to use the NoSpamProxy Identity Service without NTLM. Highly recommended for automation.
  .\harica.ps1 -IntranetRoleAddress intranetrole.example.test -MailFilter user@example.test -RSA -WorkingDirPath "C:\harica" -AdGroupId "awdawd-98awdfaw87d-adg67awrd" -NspApiKey "vjawzdfajwtzr6u532uefjz3e6523u"

.EXAMPLE
  Ignore specific issuers so that users who has already a certifiate will get a new one too.
  .\harica.ps1 -IntranetRoleAddress intranetrole.example.test -MailFilter user@example.test -RSA -WorkingDirPath "C:\harica" -AdGroupId "awdawd-98awdfaw87d-adg67awrd" -IgnoreIssuers "CN = Example CA1, O = Issuer Org, C = DE","CN = ExampleCA1,O=Issuer Org2, DE=UK"

#>

param (
  # Global parameters (available for both RSA and ECDSA)
  [Parameter(Mandatory = $true)]
  [string]$AdGroupId,

  [Parameter(Mandatory = $false)]
  [string]$CertPassword,
  
  [Parameter(Mandatory = $false)]
  [ValidateSet('email_only','natural_legal_lcp', IgnoreCase = $true)]
  [string] $CertificateProfile = "email_only",

  [Parameter(Mandatory = $true)]
  [string]$WorkingDirPath,

  [Parameter(Mandatory = $false)]
  [int]$GracePeriod = 15,

  [Parameter(Mandatory = $false)]
  [string]$HaricaConfigPath = "$WorkingDirPath\cert-generator.yaml",

  [Parameter(Mandatory = $false)]
  [array]$IgnoreIssuers,

  [Parameter(Mandatory = $true)]
  [string]$IntranetRoleAddress,

  [Parameter(Mandatory = $false)]
  [array]$MailFilter,
  
  [Parameter(Mandatory = $false)]
  [string]$NspApiKey,
  
  [Parameter(Mandatory = $false)]
  [int]$Port = 6061,
  
  # RSA or ECDSA selection directly affecting the parameter set
  [Parameter(Mandatory = $true, ParameterSetName = 'RSA')]
  [switch]$RSA,

  [Parameter(Mandatory = $true, ParameterSetName = 'ECDSA')]
  [switch]$ECDSA,

  # RSA specific parameters
  [Parameter(ParameterSetName = 'RSA')]
  [ValidateSet(2048, 3072, 4096)]
  [int]$KeySize = 2048,

  # ECDSA specific parameters
  [Parameter(ParameterSetName = 'ECDSA')]
  [ValidateSet('P256', 'P384')]  # 521 not supported by harica
  [string]$Curve = 'P256'
)

# Load the required .NET assemblies
Add-Type -AssemblyName System.Security

if ($PSVersionTable.PSVersion -le [version]"7.0.0.0") {
  add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  $oldPowerShell = $true
}
else {
  $oldPowerShell = $false
}

$executionDate = Get-Date #).addDays($GracePeriod).ToString("yyyy-MM-dd")
$executionFolder = "$($WorkingDirPath)\$($executionDate.ToString("yyyy-MM-dd"))"
$executionLog = "$WorkingDirPath\$($executionDate.ToString("yyyy-MM-dd-hhmmss"))_harica.txt"
if (!(Test-Path $executionFolder)) {
  try {
    New-Item -ItemType Directory -Path $executionFolder | Out-Null
  }
  catch {
    $e = $_
    Write-Host "An error occured while creating a new folder in your working directory, please check the error message for further information: $e"
    "An error occured while creating a new folder in your working directory, please check the error message for further information: $e" | Out-File -FilePath $executionLog -Append
    exit
  }
}

function Remove-Diacritics {
    param ([String]$src = [String]::Empty)
    $normalized = $src.Normalize( [Text.NormalizationForm]::FormKD )
    $sb = new-object Text.StringBuilder
    $normalized.ToCharArray() | % {
        if ( [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$sb.Append($_)
        }
    }
    $sb.ToString()
}

function Remove-Umlaut {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )
    $String -creplace 'Ü', 'Ue' -creplace 'Ö', 'Oe' -creplace 'Ä', 'Ae' -creplace 'ü', 'ue' -creplace 'ö', 'oe' -creplace 'ä', 'ae' -replace 'ß','ss'
}

function New-CertificateSigningRequest {
  param (
    [string]$SubjectName, # e.g., "CN=user@example.com"
    [string[]]$SubjectAlternativeNames, # e.g., @("user@example.com", "example.com")
    [string]$OutputCsrFilePath, # Path to save the CSR file
    [ValidateSet("RSA", "ECDSA")]  # Allow only RSA or ECDSA
    [string]$Algorithm = "RSA", # Default to RSA
    [int]$KeySize = 2048, # RSA key size (default: 2048)
    [ValidateSet("P256", "P384", "P521")] # ECDSA curve options
    [string]$CurveName = "P256"    # Default ECDSA curve
  )

  # Create the key pair based on the selected algorithm
  if ($Algorithm -eq "RSA") {
    # Create an RSA key pair
    $key = [System.Security.Cryptography.RSA]::Create($KeySize)
  }
  else {
    # Create an ECDSA key pair
    $curve = switch ($CurveName) {
      "P256" { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256 }
      "P384" { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP384 }
      #"P521" { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP521 } # currently not supported by harica
    }
    $key = [System.Security.Cryptography.ECDsa]::Create($curve)
  }

  # $string = $key.ToXmlString($true)
  # Define the subject name
  $subjectDN = New-Object -TypeName System.Security.Cryptography.X509Certificates.X500DistinguishedName -ArgumentList $SubjectName

  # Create the CertificateRequest object
  if ($Algorithm -eq "RSA") {
    $certRequest = New-Object -TypeName System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList @(
      $subjectDN,
      $key,
      [System.Security.Cryptography.HashAlgorithmName]::SHA256,
      [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
  }
  else {
    $certRequest = New-Object -TypeName System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList @(
      $subjectDN,
      $key,
      [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
  }

  # Add Subject Alternative Name (SAN) extension
  if ($SubjectAlternativeNames) {
    $sanBuilder = New-Object -TypeName System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
    foreach ($san in $SubjectAlternativeNames) {
      if ($san -match "@") {
        # Assume it's an email address
        $sanBuilder.AddEmailAddress($san)
      } 
    }
    $sanExtension = $sanBuilder.Build()
    $certRequest.CertificateExtensions.Add($sanExtension)
  }

  # Generate the CSR
  $csr = $certRequest.CreateSigningRequest()

  # Export the CSR in PEM format
  $pemCsr = @"
-----BEGIN CERTIFICATE REQUEST-----
$([Convert]::ToBase64String($csr, [System.Base64FormattingOptions]::InsertLineBreaks))
-----END CERTIFICATE REQUEST-----
"@

  # Save the CSR to a file
  $pemCsr | Out-File -FilePath $OutputCsrFilePath -Encoding ASCII

  Write-Host "CSR saved to $OutputCsrFilePath"
  return New-Object PsObject -Property @{privateKey = $key ; csr = $pemCsr }
}

function Invoke-HaricaCertificateRequest {
  param (
    [string]$requestTime,
    [string]$csr,
    [string]$emailAddress,
    [string]$givenName,
    [string]$surName,
    [string]$friendlyName
  )
  # harica has issues with special characters/umlauts in gn/sn, therefore we sanatize them
  $sanatizedGivenName = Remove-Diacritics -src (Remove-Umlaut -String $givenName)
  $sanatizedSurName = Remove-Diacritics -src (Remove-Umlaut -String $surName)
  #run Harica client
  $appPath = "$PSScriptRoot\harica.exe"
  try {
    if ($CertificateProfile -eq "natural_legal_lcp") {
      $certificate = & $appPath gen-cert smime --config $HaricaConfigPath --email $emailAddress --given-name $sanatizedGivenName --sur-name $sanatizedSurName --friendly-name $friendlyName --cert-type `"natural_legal_lcp`" --csr `"$csr`"
    }
    else {
      $certificate = & $appPath gen-cert smime --config $HaricaConfigPath --email $emailAddress --given-name $sanatizedGivenName --sur-name $sanatizedSurName --friendly-name $friendlyName --csr `"$csr`"
    }
    if ($null -eq $certificate -OR $certificate -eq "") {
      throw "No certificate returned by harica - this can be caused by anything, run manually for debugging."
    }
  }
  catch {
    $e = $_
    Write-Host "An error occured while requesting the certificate, please check the error message for further information: $e"
    "An error occured while requesting the certificate, please check the error message for further information: $e" | Out-File -FilePath $executionLog -Append
  }

  #save public key
  $publicCertFile = "$($executionFolder)\$($_.Username)_pub_$requestTime.pem"
  $certificate | Out-File -FilePath $publicCertFile -Encoding utf8
  return $certificate
}

function Build-Pfx {
  param (
    [string]$publicCert, 
    [System.Security.Cryptography.RSA]$privateKey
  )
  # import public key
  #$certContent = Get-Content -Raw -Path $publicCert
  $certBase64 = $publicCert -replace '-----BEGIN CERTIFICATE-----', '' -replace '-----END CERTIFICATE-----', '' -replace '\s+', ''
  $certPem = [System.Convert]::FromBase64String($certBase64)
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $certPem)

  # genereate PFX
  $certWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($cert, $privateKey)
  $pfx = $certWithKey.Export("PFX", $pfxPassword)
  Write-Host "imported pub"
  return $pfx
}

#function Import-PrivateKey {
#    #$key2 = [System.Security.Cryptography.RSA]::Create()
#    #$key2.FromXmlString($string)
#}

# ntlm auth - replace by NSP API Key + setup
$headers = @{}
$headers.Add("Content-Type", "application/json")
$headers.Add("Authorization", "Bearer $NspApiKey")
try {
  if ($NspApiKey) {
    $url = "https://$($IntranetRoleAddress):$($Port)/api/identity-service/account/login/pat"
    if ($oldPowerShell -eq $true) {
      $response = Invoke-WebRequest -Uri $url -Method GET -Headers $headers -ContentType 'application/json'
    }
    else {
      $response = Invoke-WebRequest -Uri $url -SkipCertificateCheck -Method GET -Headers $headers -ContentType 'application/json'
    }
  }
  else {
    $url = "https://$($IntranetRoleAddress):$($Port)/api/identity-service/account/login"
    if ($oldPowerShell -eq $true) {
      $response = Invoke-WebRequest -Uri $url -Method POST -Headers $headers -ContentType 'application/json' -Credential $(Get-Credential)
    }
    else {
      $response = Invoke-WebRequest -Uri $url -SkipCertificateCheck -Method POST -Headers $headers -ContentType 'application/json' -Credential $(Get-Credential)
    }

  }
}
catch {
  $e = $_
  Write-Host "An error occured while logging in, please check the error message for further information> $e"
  "An error occured while logging in, please check the error message for further information> $e" | Out-File -FilePath $executionLog -Append
  exit
}
$jwt = ($response.Content | ConvertFrom-Json).token

# call request
$headers = @{}
$headers.Add("authorization", "BEARER $jwt")
$url = ("https://$($IntranetRoleAddress):$($Port)/odata/v4/Users?" + '$select=Username,IsEnabledInMailGateway,DisplayName,Title,GivenName,Surname,StateOrProvince,Locality,OrganizationName,OrganizationalUnitName&$expand=MailAddresses($expand=Domain($select=Name);$select=localPart;$filter=IsDefaultAddress%20eq%20true)&$filter=Groups/any(g:g/Name%20eq%20%27' + "$($AdGroupId)" + '%27 and IsEnabledInMailGateway eq true)&$orderby=id')
try {

  if ($oldPowerShell -eq $true) {
    do {
      $response = Invoke-WebRequest -Uri $url -Method GET -Headers $headers
      $groupMembers += ($response.Content | ConvertFrom-Json).Value
      $url = ($response.Content | ConvertFrom-Json).'@odata.nextLink'
    } until (!($response.Content | ConvertFrom-Json).'@odata.nextLink')
  }
  else {
    do {
      $response = Invoke-WebRequest -Uri $url -SkipCertificateCheck -Method GET -Headers $headers
      $groupMembers += ($response.Content | ConvertFrom-Json).Value
      $url = ($response.Content | ConvertFrom-Json).'@odata.nextLink'
    } until (!($response.Content | ConvertFrom-Json).'@odata.nextLink')
  }
}
catch {
  $e = $_
  Write-Host "An error occured while gathering user data, please check the error message for further information> $e"
  "An error occured while gathering user data, please check the error message for further information> $e" | Out-File -FilePath $executionLog -Append
  exit
}
# get nsp certificates
$filterDate = (Get-date).addDays($GracePeriod).ToString("yyyy-MM-dd")
$headers = @{}
$headers.Add("authorization", "BEARER $jwt")
if ($IgnoreIssuers) {
  $issuerFilter = "'$($IgnoreIssuers -join "','")'"
  $url = ("https://$($IntranetRoleAddress):$($Port)/odata/v4/CertificateConfigurations?" + '$filter=NotAfter%20gt%20' + $filterDate + 'T00:00:00Z%20and%20StoreId%20eq%20%27My%27and%20KeyType%20eq%20%27X509Certificate%27%20and%20not%20(Issuer%20in%20(' + $issuerFilter + '))&$orderby=id')
}
else {
  $url = ("https://$($IntranetRoleAddress):$($Port)/odata/v4/CertificateConfigurations?" + '$filter=NotAfter%20gt%20' + $filterDate + 'T00:00:00Z%20and%20StoreId%20eq%20%27My%27and%20KeyType%20eq%20%27X509Certificate%27&$orderby=id')
}
try {
  if ($oldPowerShell -eq $true) {
    do {
      $response = Invoke-WebRequest -Uri $url -Method GET -Headers $headers
      $existingCertificates += ($response.Content | ConvertFrom-Json).Value.Subject
      $url = ($response.Content | ConvertFrom-Json).'@odata.nextLink'
    } until (!($response.Content | ConvertFrom-Json).'@odata.nextLink')
  }
  else {
    do {
      $response = Invoke-WebRequest -Uri $url -SkipCertificateCheck -Method GET -Headers $headers
      $existingCertificates += ($response.Content | ConvertFrom-Json).Value.Subject
      $url = ($response.Content | ConvertFrom-Json).'@odata.nextLink'
    } until (!($response.Content | ConvertFrom-Json).'@odata.nextLink')
  }
}
catch {
  $e = $_
  Write-Host "An error occured while receiving existing certificate information, please check the error message for further information: $e"
  "An error occured while receiving existing certificate information, please check the error message for further information: $e" | Out-File -FilePath $executionLog -Append
  exit
}

$groupMembers | ForEach-Object {
  $_.DisplayName
  # build Mail address
  $emailAddress = ($_.MailAddresses).LocalPart + '@' + ($_.MailAddresses).Domain.Name
  Write-Host "Executing $emailAddress"
  "Executing $emailAddress" | Out-File -FilePath $executionLog -Append
  if ($MailFilter -AND !$MailFilter.Contains($emailAddress)) {
    Write-Host "Skipping address."
    "Skipping address." | Out-File -FilePath $executionLog -Append
  }
  else {
    if ($existingCertificates -match $emailAddress) {
      Write-Host "Certificate already existing."
      "Certificate already existing." | Out-File -FilePath $executionLog -Append
    }
    else {
      $requestTimestamp = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
      if ($CertPassword) {
        $pfxPassword = $CertPassword
        Write-Host "Using provided password."
      }
      else {
        Write-Host "Generating password..."
        # generate a random password: 28 characters, a-z, A-Z, 0-9, +-_=?
        $pfxPassword = -join ((65..90) + (97..122) + (48..57) + (43, 45, 61, 63, 95) | Get-Random -Count 28 | ForEach-Object { [char]$_ })
        $pfxPassword | Out-File "$($executionFolder)\$($_.Username)_pass_$requestTimestamp.txt" -Encoding utf8
      }
      Write-Host "Generating CSR..."
      "Generating CSR..." | Out-File -FilePath $executionLog -Append
      if ($RSA) {
        $certRequest = New-CertificateSigningRequest -SubjectName "E=$($emailAddress)" -SubjectAlternativeNames @("$emailAddress") -OutputCsrFilePath "$($executionFolder)\$($_.Username)_RSA_$requestTimestamp.csr" -Algorithm RSA -KeySize $KeySize
      }
      elseif ($ECDSA) {
        $certRequest = New-CertificateSigningRequest -SubjectName "CN=`"$($_.DisplayName)`"" -SubjectAlternativeNames @("$emailAddress") -OutputCsrFilePath "$($executionFolder)\$($_.Username)_ECDSA_$requestTimestamp.csr" -Algorithm ECDSA -CurveName $Curve
      }
      #REMOVE
      pause
      Write-Host "Invoke harica process..."
      "Invoke harica process..." | Out-File -FilePath $executionLog -Append
      $publicCert = Invoke-HaricaCertificateRequest -requestTime $requestTimestamp -csr $($certRequest.csr -replace "`r?`n", "\n") -email $emailAddress -givenName "$($_.GivenName)" -surName "$($_.Surname)" -friendlyName "$($_.DisplayName)" -username "$($_.Username)"
      Write-Host "Building PFX..."
      "Building PFX..." | Out-File -FilePath $executionLog -Append
      $pfx = Build-Pfx $publicCert $certRequest.privateKey
      [System.IO.File]::WriteAllBytes("$($executionFolder)\$($_.Username)_$requestTimeStamp.pfx", $pfx)
      # import pfx to NoSpamProxy
      $headers = @{}
      $headers.Add("authorization", "BEARER $jwt")
      $request = @{
        "Certificate" = [System.Convert]::ToBase64String($pfx);
        "Password"    = "$($pfxPassword)"
      }
      $body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $request))
      $url = "https://$($IntranetRoleAddress):$($Port)/odata/v4/CertificateConfigurations/UploadCertificate()"
      Write-Host "Import certificate to NoSpamProxy..."
      "Import certificate to NoSpamProxy..." | Out-File -FilePath $executionLog -Append
      try {
        if ($oldPowerShell -eq $true) {
          $response = Invoke-WebRequest -Uri $url -Method POST -Headers $headers -Body $body -ContentType "application/json"
        }
        else {
          $response = Invoke-WebRequest -Uri $url -SkipCertificateCheck -Method POST -Headers $headers -Body $body -ContentType "application/json"
        }
      }
      catch {
        $e = $_
        Write-Host "An error occured while uploading a certificate, please check the error message for further information: $e"
        "An error occured while uploading a certificate, please check the error message for further information: $e" | Out-File -FilePath $executionLog -Append
      }
    }
  }
}
Write-Host "Script execution finished."
"Script execution finished." | Out-File -FilePath $executionLog -Append
