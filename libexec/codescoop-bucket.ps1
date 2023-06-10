# Usage: codescoop bucket add|list|known|rm [<args>]
# Summary: Manage Scoop buckets
# Help: Add, list or remove buckets.
#
# Buckets are repositories of apps available to install. Scoop comes with
# a default bucket, but you can also add buckets that you or others have
# published.
#
# To add a bucket:
#     codescoop bucket add <name> [<repo>]
#
# e.g.:
#     codescoop bucket add extras https://github.com/ScoopInstaller/Extras.git
#
# Since the 'extras' bucket is known to Scoop, this can be shortened to:
#     codescoop bucket add extras
#
# To list all known buckets, use:
#     codescoop bucket known
param($cmd, $name, $repo)

$usage_add = 'usage: codescoop bucket add <name> [<repo>]'
$usage_rm = 'usage: codescoop bucket rm <name>'

switch ($cmd) {
    'add' {
        if (!$name) {
            '<name> missing'
            $usage_add
            exit 1
        }
        if (!$repo) {
            $repo = known_bucket_repo $name
            if (!$repo) {
                "Unknown bucket '$name'. Try specifying <repo>."
                $usage_add
                exit 1
            }
        }
        $status = add_bucket $name $repo
        exit $status
    }
    'rm' {
        if (!$name) {
            '<name> missing'
            $usage_rm
            exit 1
        }
        $status = rm_bucket $name
        exit $status
    }
    'list' {
        $buckets = list_buckets
        if (!$buckets.Length) {
            warn "No bucket found. Please run 'codescoop bucket add main' to add the default 'main' bucket."
            exit 2
        } else {
            $buckets
            exit 0
        }
    }
    'known' {
        known_buckets
        exit 0
    }
    default {
        "codescoop bucket: cmd '$cmd' not supported"
        my_usage
        exit 1
    }
}
