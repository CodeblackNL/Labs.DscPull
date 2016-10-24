
#######################################
# Load configuration
#######################################
Write-Log "INFO" "Loading configuration"
$configuration = Get-content -Path "$setupFolder\configuration.json" -Raw | ConvertFrom-Json
Write-Log "INFO" "Finished loading configuration"

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
# Install modules
#######################################
$modulesPath = Join-Path -Path $setupFolder -ChildPath 'Modules'
if (Test-Path -Path $modulesPath -PathType Container) {
    $destination = Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsPowerShell\Modules'
    Write-Log "INFO" "installing modules from '$modulesPath' to '$destination'"
    Get-ChildItem -Path "$modulesPath\*" -include '*.nupkg','*.zip' |% {
        if ($_.BaseName -match '(?<name>\D*)\.(?<version>\d*.\d*(.\d*(.\d*)?)?)') {
            Write-Log "INFO" "Installing module '$($_.BaseName)'"
            if ([System.IO.Path]::GetExtension($_.FullName) -ne '.zip') {
                $zipFilePath = Join-Path -Path $_.Directory -ChildPath "$($_.BaseName).zip"
                Rename-Item -Path $_.FullName -NewName $zipFilePath
            }
            else {
                $zipFilePath = $_.FullName
            }

            $destinationPath = Join-Path -Path $destination -ChildPath "$($Matches.name)\$($Matches.version)"
            New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
            Expand-Archive -Path $zipFilePath -DestinationPath $destinationPath -Force

            get-childitem -path $destinationPath |? { $_.BaseName -in 'package', '_rels','[Content_Types]' } | Remove-Item -Recurse -Force

            if ($zipFilePath -ne $_.FullName) {
                Rename-Item -Path $zipFilePath -NewName $_.FullName
            }
        }
    }
}
else {
    Write-Log "INFO" "Modules path '$modulesPath' not found"
}


#######################################
# Apply configuration
#######################################
$configurationFilePath = Join-Path -Path $setupFolder -ChildPath 'HyperVLabEnvironment.ps1'
$configurationData = @{}
if (Test-Path -Path $configurationFilePath) {
    Write-Log "INFO" "Start applying configuration"
    Write-Log "INFO" "Preparing configuration for DSC"
    $configuration `
        | Add-Member -MemberType NoteProperty -Name NodeName -Value 'localhost' -PassThru `
        | Add-Member -MemberType NoteProperty -Name PSDscAllowPlainTextPassword -Value $true `
        | Add-Member -MemberType NoteProperty -Name PSDscAllowDomainUser -Value $true

    $configurationData.AllNodes = @((Convert-PSObjectToHashtable $configuration))

    Write-Log "INFO" "Loading configuration"
    . $configurationFilePath
    Write-Log "INFO" "Generating configuration"
    $outputPath = Join-Path -Path $setupFolder -ChildPath 'HyperVLabEnvironment'
    HyperVLabEnvironment -ConfigurationData $configurationData -OutputPath $outputPath | Out-Null
    Write-Log "INFO" "Starting configuration"
    Start-DscConfiguration –Path $outputPath –Wait -Force –Verbose | Out-Null
    Write-Log "INFO" "Finished applying configuration"
}
else {
    Write-Log "INFO" "Skipping configuration"
}
