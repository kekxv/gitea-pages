#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

workflow=.github/workflows/security.yml
security_doc=docs/security.md

require_file() {
    test -f "$1" || { printf 'missing required file: %s\n' "$1" >&2; exit 1; }
}

require_text() {
    local file=$1
    local text=$2
    grep -Fq -- "$text" "$file" || { printf 'missing %q in %s\n' "$text" "$file" >&2; exit 1; }
}

require_file "$workflow"
require_file "$security_doc"
if test -e tests/integration_test.go; then
    printf 'historical non-module Go test harness must not remain in tests/\n' >&2
    exit 1
fi

# Third-party actions must use immutable commit references, not mutable tags.
if grep -E '^ *uses: [^@]+@v?[0-9]+(\.[0-9]+)*([[:space:]]*(#.*)?)$' "$workflow"; then
    printf 'workflow contains a mutable action reference\n' >&2
    exit 1
fi
grep -Eq '^ *uses: [^@]+@[0-9a-f]{40}( +#.*)?$' "$workflow" || {
    printf 'workflow contains no commit-pinned action reference\n' >&2
    exit 1
}

require_text "$workflow" 'GOVULNCHECK_VERSION:'
require_text "$workflow" 'TRIVY_VERSION:'
require_text "$workflow" 'working-directory: deployer'
require_text "$workflow" 'go test -race -coverprofile=coverage.out ./...'
require_text "$workflow" 'govulncheck ./...'
require_text "$workflow" 'docker compose --env-file .env.example config --quiet'
require_text "$workflow" 'bash tests/compose_security_test.sh'
require_text "$workflow" 'bash tests/nginx_test.sh'
require_text "$workflow" 'trivy config --exit-code 1 --severity HIGH,CRITICAL .'
require_text "$workflow" 'trivy image --exit-code 1 --severity CRITICAL gitea-pages-deployer:${GITHUB_SHA}'
require_text "$workflow" 'trivy image --exit-code 1 --severity CRITICAL gitea-pages-nginx:${GITHUB_SHA}'
if grep -Fq 'cd tests' "$workflow"; then
    printf 'workflow invokes the historical non-module tests directory\n' >&2
    exit 1
fi

for text in \
    'hook key is an identifier' \
    'hook secret authenticates one scope' \
    'OAuth tokens never come from payload identity' \
    'Gitea API metadata is canonical' \
    'Static repository content is untrusted' \
    'no Docker socket or SSH key' \
    'Secret rotation' \
    'Suspected token compromise' \
    'Forged-hook response' \
    'Disk-exhaustion response' \
    'Rollback procedure'; do
    require_text "$security_doc" "$text"
done

require_text README.md 'offline migration'
require_text README.md 'ENABLE_ORGANIZATION_HOOKS=true'
require_text README.md 'administrator token pool'
require_text AI.md 'offline migration'
require_text AI.md 'ENABLE_ORGANIZATION_HOOKS=true'
require_text AI.md 'administrator token pool'
user_facing_paths=(README.md AI.md docs/security.md .env.example examples)
if rg -n -i \
    -e 'write:admin' \
    -e 'GITEA_ACCESS_TOKEN' \
    -e 'WEBHOOK_SECRET[=[:space:]]' \
    -e 'OAUTH_CLIENT_SECRET=' \
    -e 'WEBHOOK_PUBLIC_URL=http://deployer:8080' \
    -e 'https?://[^[:space:]]*deployer[^[:space:]]*:8080' \
    -e 'https?://(localhost|[^[:space:]]*deployer[^[:space:]]*):8080/(oauth|webhook)' \
    -e '\./test\.sh' \
    -e '\./cleanup\.sh' \
    -e 'system[- ]wide[^[:cntrl:]]*hook' \
    -e '所有仓库' \
    -e 'SSH private-key mount' \
    "${user_facing_paths[@]}"; then
    printf 'user-facing documentation or examples still contain a retired credential or public Deployer route\n' >&2
    exit 1
fi
