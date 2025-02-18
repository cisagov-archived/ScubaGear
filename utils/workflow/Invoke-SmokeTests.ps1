function Invoke-SmokeTests {
    <#
        .SYNOPSIS
            Runs the smoke tests for ScubaGear
        .PARAMETER TestTenants
            Tenant info
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]
        $TestTenants
    )

    Write-Warning "Invoking smoke tests..."
    Write-Warning "Identified $($TestTenants.Count) test tenants..."

    # Access certificate functions
    . Testing/Functional/SmokeTest/SmokeTestUtils.ps1
    # Install-SmokeTestExternalDependencies
    # Note this is dupe code with this:
    . utils/workflow/Install-SeleniumForTesting.ps1
    Install-SeleniumForTesting
    # Install ScubaGear modules
    Import-Module -Name .\PowerShell\ScubaGear\ScubaGear.psd1
    Initialize-SCuBA

    # Workaround for Selenium. Loading psm1 instead of psd1
    # Import-Module -Name (Get-Module -Name Selenium -ListAvailable).Path -Force

    # ScubaGear currently requires the provisioning of a certificate for using a ServicePrinicpal, rather than
    # using Workload Identity Federation, which would ordinarily be preferred for calling Microsoft APIs from
    # GitHub actions.
    $TestContainers = @()
    ForEach ($TestTenantObj in $TestTenants){
        $Properties = Get-Member -InputObject $TestTenantObj -MemberType NoteProperty
        $TestTenant = $TestTenantObj | Select-Object -ExpandProperty $Properties.Name
        $OrgName = $TestTenant.DisplayName
        Write-Warning "The org name is $OrgName"
        $DomainName = $TestTenant.DomainName
        $AppId = $TestTenant.AppId
        $PlainTextPassword = $TestTenant.CertificatePassword
        $CertPwd = ConvertTo-SecureString -String $PlainTextPassword -Force -AsPlainText
        $M365Env = $TestTenant.M365Env
        try {
            $Result = New-ServicePrincipalCertificate `
                -EncodedCertificate $TestTenant.CertificateB64 `
                -CertificatePassword $CertPwd
            $Thumbprint = $Result[-1]
            $TestContainers += New-PesterContainer `
                -Path "Testing/Functional/SmokeTest/SmokeTest001.Tests.ps1" `
                -Data @{ Thumbprint = $Thumbprint; Organization = $DomainName; AppId = $AppId; M365Environment = $M365Env }
            $TestContainers += New-PesterContainer `
                -Path "Testing/Functional/SmokeTest/SmokeTest002.Tests.ps1" `
                -Data @{ OrganizationDomain = $DomainName; OrganizationName = $OrgName }
            Invoke-Pester -Container $TestContainers -Output Detailed
        }
        catch {
            Write-Warning "Failed to install certificate for $OrgName"
            Write-Warning $_
        }

        # $TestContainers += New-PesterContainer `
        #     -Path "Testing/Functional/SmokeTest/SmokeTest001.Tests.ps1" `
        #     -Data @{ Thumbprint = $Thumbprint; Organization = $DomainName; AppId = $AppId; M365Environment = $M365Env }
        # $TestContainers += New-PesterContainer `
        #     -Path "Testing/Functional/SmokeTest/SmokeTest002.Tests.ps1" `
        #     -Data @{ OrganizationDomain = $DomainName; OrganizationName = $OrgName }
    }

    # Invoke-Pester -Container $TestContainers -Output Detailed

    Remove-MyCertificates
}