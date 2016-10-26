
#######################################
# Update LocalConfigurationManager
#######################################
Write-Log "INFO" "Updating LocalConfigurationManager with RebootNodeIfNeeded"
configuration LCM_RebootNodeIfNeeded {
    node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }
    }
}

LCM_RebootNodeIfNeeded -OutputPath "$setupFolder\LCM_RebootNodeIfNeeded" | Out-Null
Set-DscLocalConfigurationManager -Path "$setupFolder\LCM_RebootNodeIfNeeded" -Verbose -ComputerName localhost
Write-Log "INFO" "Finished updating LocalConfigurationManager with RebootNodeIfNeeded"

#######################################
# Apply configuration
#######################################
$dscFilePath = Join-Path -Path $setupFolder -ChildPath 'HyperVLabEnvironment.ps1'
if (Test-Path -Path $dscFilePath) {
    Write-Log "INFO" "Start applying configuration"
    Write-Log "INFO" "Preparing configuration for DSC"
    $configuration `
        | Add-Member -MemberType NoteProperty -Name NodeName -Value 'localhost' -PassThru `
        | Add-Member -MemberType NoteProperty -Name PSDscAllowPlainTextPassword -Value $true `
        | Add-Member -MemberType NoteProperty -Name PSDscAllowDomainUser -Value $true

    $configurationData = @{
        AllNodes = @(
            (Convert-PSObjectToHashtable $configuration)
        )
    }

    Write-Log "INFO" "Loading configuration"
    . $dscFilePath
    Write-Log "INFO" "Generating configuration"
    $outputPath = Join-Path -Path $PSScriptRoot -ChildPath "$([System.IO.Path]::GetFileNameWithoutExtension($dscFilePath))_DSC"
    HyperVLabEnvironment -ConfigurationData $configurationData -OutputPath $outputPath | Out-Null
    Write-Log "INFO" "Starting configuration"
    Start-DscConfiguration –Path $outputPath –Wait -Force –Verbose | Out-Null
    Write-Log "INFO" "Finished applying configuration"
}
else {
    Write-Log "INFO" "Skipping configuration"
}
