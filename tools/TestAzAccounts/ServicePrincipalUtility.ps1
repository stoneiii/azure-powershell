function Deploy-ServicePincipal {
    param(
    
        [Parameter(Mandatory = $true)]
        [string]
        $ServicePrincipalName,

        [Parameter(Mandatory = $false)]
        [string]
        $SubscriptionId,

        [Parameter()]
        [string]
        $RoleName,

        [Parameter(Mandatory)]
        [String]
        $CertFile,
   
        [Parameter(Mandatory)]
        [String]
        $CertPlainPassword
    )

    $spInfo = @{
    }

    $sp = New-AzADServicePrincipal -DisplayName $ServicePrincipalName

    $spInfo['Id'] = $sp.Id
    $spInfo['AppId'] = $sp.AppId
    $spInfo['AppDisplayName'] = $sp.AppDisplayName
    $spInfo['Password'] = $testSp.PasswordCredentials.SecretText

    $scope = "/subscriptions/$SubscriptionId"
    if ($RoleName -eq $null) {
        $RoleName = "Contributor"
    }
    try {
        $spRoleAssg = Get-AzRoleAssignment -ObjectId $sp.Id -Scope $scope -RoleDefinitionName $roleName -ErrorAction Stop
        if ($null -eq $spRoleAssg) {
            New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop
        }
    }
    catch {
        throw "Exception occurred when retrieving the role assignment for service principal with error message $($_.Exception.Message)."
    }

    $pfxCert = Convert-CertFileToObject -CertFile $CertFile -CertPlainPassword $CertPlainPassword
    $keyValue = [System.Convert]::ToBase64String($pfxCert.RawData)
    New-AzADSpCredential -ObjectId $sp.Id -CertValue $keyValue -StartDate $pfxCert.NotBefore -EndDate $pfxCert.NotAfter
    Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $
    Write-Ouput $spInfo
}