Import-Module .\variables.ps1

# Construct the command
$command = "$installScriptPath -CodeScoopDir '$codeScoopDir' -CodeScoopGlobalDir '$codeScoopGlobalDir'"

if ($noProxy) {
    $command += " -NoProxy"
}

if ($runAsAdmin) {
    $command += " -RunAsAdmin"
}

# Execute the command
Invoke-Expression $command
