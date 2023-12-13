[CmdletBinding()]
param (
    [Parameter(ParameterSetName = 'CertificateFile')]
    [Switch]
    $UseCertificateFile,

    [Parameter(ParameterSetName = 'Thumbprint')]
    [Switch]
    $UseThumbprint,

    [Parameter(ParameterSetName = 'Password')]
    [Switch]
    $UsePassword,

    [Parameter(ParameterSetName = 'FederatedToken')]
    [Switch]
    $UseFederatedToken,

    [Parameter(ParameterSetName = 'Thumbprint', Mandatory = $true)]
    [Parameter(ParameterSetName = 'CertificateFile', Mandatory = $true)]
    [string]
    $Path,

    [Parameter(ParameterSetName = 'Thumbprint', Mandatory = $true)]
    [Parameter(ParameterSetName = 'CertificateFile', Mandatory = $true)]
    [string]
    $PfxFileName,

    [Parameter(ParameterSetName = 'FederatedToken', Mandatory = $true)]
    [string]
    $FederatedToken
)

$password = 'pa88w0rd!'
$tenantId = '54826b22-38d6-4fb2-bad9-b7b93a3e9c5a'
$keyVaultName = 'LiveTestKeyVault'

$servicePrincipalName = 'Azure PowerShell AzAccounts Test'
$secretName = 'Azure PowerShell AzAccounts Test'
$certificateName = 'ServicePrincipalCertificate'

Import-Module "$PSScriptRoot/CertificateUtility.psm1"
Set-AzContext -TenantId $tenantId

$paramsCertificate = @{
    KeyVaultName    = $keyVaultName;
    CertificateName = $certificateName;
    CertPassword    = $password;
    Path            = $Path
    PfxFileName     = $PfxFileName
}

$pfxFile = Get-CertificateFromKeyVault @paramsCertificate

$appId = (Get-AzADServicePrincipal -DisplayName $servicePrincipalName).AppId
$params = @{
    TenantId      = $tenantId;
    ApplicationId = appId;
}
if ($PSCmdlet.ParameterSetName -eq 'CertificateFile') {
    $params['CertificatePath'] = $pfxFile
    $params['CertificatePassword'] = $password
    Connect-AzAccount -ServicePrincipal @params
}
elseif ($PSCmdlet.ParameterSetName -eq 'Thumbprint') {
    $paramsImport = @{
        FilePath          = $pfxFile
        CertStoreLocation = 'Cert:\LocalMachine\My'
        Password          = $password
    }
    Import-PfxCertificate @paramsImport

    $pfxCert = New-Object `
        -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 `
        -ArgumentList @($pfxFile, $password)
    $thumbprint = $pfxCert.Thumbprint
    $params['CertificateThumbprint'] = $thumbprint
    Connect-AzAccount -ServicePrincipal @params
}
elseif ($PSCmdlet.ParameterSetName -eq 'Password') {
    $secret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $appId, $secret.SecretValue
    Connect-AzAccount -ServicePrincipal -TenantId $tenantId -Credential $credential
}
elseif ($PSCmdlet.ParameterSetName -eq 'FederatedToken')
{
    Connect-AzAccount -ServicePrincipal -Tenant $tenantId -ApplicationId $appId -FederatedToken $FederatedToken
}
