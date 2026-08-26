#!/usr/bin/env bash
# Fail closed unless the public FRP fork resolves to the reviewed release commit.
#
# The reviewed COMMIT is the only hand-maintained constant. Version and module
# hashes are read from go.mod/go.sum, then checked against what the public proxy
# independently serves; the proxy's reported origin commit must equal the value
# below. Repinning to any other release therefore fails here regardless of what
# the pin is called, so the anchor cannot be moved by editing go.mod alone.
#
# Cutting a new fork release means updating exactly one line: `commit`.
set -euo pipefail

readonly module='github.com/layervai/frp'
readonly repository='https://github.com/layervai/frp.git'

# Reviewed release commit on layerv/main. See FORK.md in the fork repository.
readonly commit='ecb28a1dece90985dfc20f829f75ccbc7406adba'

replace_line="$(grep -E "^replace github\.com/fatedier/frp => ${module} v" go.mod || true)"
if [ -z "${replace_line}" ]; then
  echo "FRP replace directive for ${module} not found in go.mod" >&2
  exit 1
fi
version="${replace_line##* }"
readonly version
if [ -z "${version}" ]; then
  echo "could not read pinned FRP version from go.mod" >&2
  exit 1
fi

read_sum() { # <go.sum key suffix>
  local key="$1" line
  line="$(grep -E "^${module} ${version}${key} h1:" go.sum || true)"
  if [ -z "${line}" ]; then
    echo "FRP checksum pin missing from go.sum: ${module} ${version}${key}" >&2
    exit 1
  fi
  echo "${line##* }"
}
sum="$(read_sum '')"
mod_sum="$(read_sum '/go.mod')"
readonly sum mod_sum

# Use an isolated cache so this check cannot succeed from a developer's warm
# module cache. GONOPROXY=none also proves a public consumer can resolve the
# dependency without repository credentials.
provenance_modcache="$(mktemp -d)"
readonly provenance_modcache
cleanup_provenance_modcache() {
  chmod -R u+w "${provenance_modcache}" 2>/dev/null || true
  rm -rf -- "${provenance_modcache}"
}
trap cleanup_provenance_modcache EXIT
metadata="$(
  GOENV=off \
  GOMODCACHE="${provenance_modcache}" \
  GOPROXY=https://proxy.golang.org \
  GONOPROXY=none \
  GOPRIVATE='' \
  GONOSUMDB='' \
    go mod download -json "${module}@${version}"
)"
for field in \
  "\"Path\": \"${module}\"" \
  "\"Version\": \"${version}\"" \
  "\"Sum\": \"${sum}\"" \
  "\"GoModSum\": \"${mod_sum}\"" \
  "\"URL\": \"https://github.com/layervai/frp\"" \
  "\"Hash\": \"${commit}\"" \
  "\"Ref\": \"refs/tags/${version}\""; do
  if ! grep -Fq "$field" <<<"${metadata}"; then
    echo "FRP proxy provenance mismatch: missing ${field}" >&2
    exit 1
  fi
done

remote_refs="$(git ls-remote "${repository}" "refs/tags/${version}" "refs/tags/${version}^{}")"
remote_commit="$(awk '$2 ~ /\^\{\}$/ { print $1 }' <<<"${remote_refs}")"
if [ -z "${remote_commit}" ]; then
  remote_commit="$(awk '$2 !~ /\^\{\}$/ { print $1 }' <<<"${remote_refs}")"
fi
if [ "${remote_commit}" != "${commit}" ]; then
  echo "FRP release tag mismatch: ${version} resolves to ${remote_commit:-missing}, want ${commit}" >&2
  exit 1
fi

echo "FRP provenance verified through the public proxy: ${version} -> ${commit}"
