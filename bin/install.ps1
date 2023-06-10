#Requires -Version 5

$installScriptPath = '..\codescoop-install.ps1'
$installScriptContent = Get-Content $installScriptPath -Raw
Invoke-Expression $installScriptContent
