# Usage: codescoop import <path/url to scoopfile.json>
# Summary: Imports apps, buckets and configs from a Scoopfile in JSON format
# Help: To replicate a Scoop installation from a file stored on Desktop, run
#      codescoop import Desktop\codescoopfile.json

param(
    [Parameter(Mandatory)]
    [String]
    $scoopfile
)

. "$PSScriptRoot\..\lib\manifest.ps1"

$import = $null
$bucket_names = @()
$def_arch = Get-DefaultArchitecture

if (Test-Path $scoopfile) {
    $import = parse_json $scoopfile
} elseif ($scoopfile -match '^(ht|f)tps?://|\\\\') {
    $import = url_manifest $scoopfile
}

if (!$import) { abort 'Input file not a valid JSON.' }

foreach ($item in $import.config.PSObject.Properties) {
    set_config $item.Name $item.Value | Out-Null
    Write-Host "'$($item.Name)' has been set to '$($item.Value)'"
}

foreach ($item in $import.buckets) {
    add_bucket $item.Name $item.Source | Out-Null
    $bucket_names += $item.Name
}

foreach ($item in $import.apps) {
    $info = $item.Info -Split ', '
    $global = if ('Global install' -in $info) {
        ' --global'
    } else {
        ''
    }
    $arch = if ('64bit' -in $info -and '64bit' -ne $def_arch) {
        ' --arch 64bit'
    } elseif ('32bit' -in $info -and '32bit' -ne $def_arch) {
        ' --arch 32bit'
    } elseif ('arm64' -in $info -and 'arm64' -ne $def_arch) {
        ' --arch arm64'
    } else {
        ''
    }

    $app = if ($item.Source -in $bucket_names) {
        "$($item.Source)/$($item.Name)"
    } elseif ($item.Source -eq '<auto-generated>') {
        "$($item.Name)@$($item.Version)"
    } else {
        $item.Source
    }

    & "$PSScriptRoot\codescoop-install.ps1" $app$global$arch

    if ('Held package' -in $info) {
        & "$PSScriptRoot\codescoop-hold.ps1" $($item.Name)$global
    }
}
