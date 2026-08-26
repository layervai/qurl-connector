#!/usr/bin/env bash
# Fail closed unless the public FRP fork resolves to the reviewed release.
# go.sum binds the module archives, the public proxy supplies independently
# cached module metadata, and the live tag lookup detects a moved release tag.
set -euo pipefail

readonly module='github.com/layervai/frp'
readonly repository='https://github.com/layervai/frp.git'
readonly version='v0.70.0-layerv.5'
readonly commit='2a637b92c133c23e228bb32bd94ac4550067156b'
readonly sum='h1:8Txo5ZdscoJbIiC9avmrXBMSS0ms/U/cEKhOAxPvKbY='
readonly mod_sum='h1:h6UP/0bhnurYzBPORBgbP+aZByDMpzWOErJNNoFdoJo='

if ! grep -Fqx "replace github.com/fatedier/frp => ${module} ${version}" go.mod; then
  echo "FRP replace is not pinned to ${module} ${version}" >&2
  exit 1
fi
for line in "${module} ${version} ${sum}" "${module} ${version}/go.mod ${mod_sum}"; do
  if ! grep -Fqx "$line" go.sum; then
    echo "FRP checksum pin missing: $line" >&2
    exit 1
  fi
done

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
