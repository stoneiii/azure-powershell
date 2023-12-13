
[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $true)]
    [string]
    $Path,

    [Parameter(Mandatory = $true)]
    [string]
    $PfxFileName
)

$subscriptionId = '0b1f6471-1bf0-4dda-aec3-cb9272f09590'
$keyVaultName = 'LiveTestKeyVault'
$servicePrincipalName = 'Azure PowerShell AzAccounts Test'
$roleName = "Contributor"
$password = 'pa88w0rd!'
$certficateName = 'ServicePrincipalCertificate'
$secretName = 'Azure PowerShell AzAccounts Test'
$subject = 'CN=TestAzAccounts'

Import-Module "$PSScriptRoot/CertificateUtility.psm1"

Set-AzContext -TenantId '54826b22-38d6-4fb2-bad9-b7b93a3e9c5a' -SubscriptionId $subscriptionId
New-CertificateFromKeyVault -KeyVaultName $keyVaultName -CertificateName $certficateName -SubjectName $subject

$params = {
    KeyVaultName = $keyVaultName;
    CertificateName = $certficateName;
    CertPlainPassword = $password;
    Path = $Path;
    PfxFileName = $PfxFileName;
}
$pfxFile = Get-CertificateFromKeyVault @params

$sp = New-AzADServicePrincipal -DisplayName $servicePrincipalName

$scope = "/subscriptions/$subscriptionId"
try {
    $spRoleAssg = Get-AzRoleAssignment -ObjectId $sp.Id -Scope $scope -RoleDefinitionName $roleName -ErrorAction 'Stop'
    if ($null -eq $spRoleAssg) {
        New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop
    }
}
catch {
    throw "Exception occurred when retrieving the role assignment for service principal with error message $($_.Exception.Message)."
}

$pfxCert = Convert-CertFileToObject -CertFile $pfxFile -CertPlainPassword $CertPlainPassword
$keyValue = [System.Convert]::ToBase64String($pfxCert.RawData)
New-AzADSpCredential -ObjectId $sp.Id -CertValue $keyValue -StartDate $pfxCert.NotBefore -EndDate $pfxCert.NotAfter
$spInfo = @{
    Id             = $sp.Id;
    AppId          = $sp.AppId;
    AppDisplayName = $sp.AppDisplayName;
    Password       = $testSp.PasswordCredentials.SecretText;
}

#New-AzADAppFederatedCredential -ApplicationObjectId $appObjectId -Audience api://AzureADTokenExchange -Issuer https://login.microsoftonline.com/3d1e2be9-a10a-4a0c-8380-7ce190f98ed9/v2.0 -name 'test-cred' -Subject 'subject'

$secretParams = {
    VaultName = $keyVaultName;
    Name = $secretName;
    SecretValue = $testSp.PasswordCredentials.SecretText;
    NotBefore = $testSp.PasswordCredentials.StartDateTime;
    Expires = $testSp.PasswordCredentials.EndDateTime;
}
Set-AzKeyVaultSecret @secretParams

Write-Ouput $spInfo