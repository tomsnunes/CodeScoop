#Requires -Version 5

$installScriptPath = '..\codescoop.ps1'
$installScriptContent = Get-Content $installScriptPath -Raw
Invoke-Expression $installScriptContent
