#!/usr/bin/env bash
# Fail closed unless the public FRP fork resolves to the reviewed release commit.
#
# The reviewed dependency and release commits are the only hand-maintained
# constants. Version and module hashes come from go.mod/go.sum, then the public
# proxy and release tag must resolve to these exact commits.
#
# Cutting a new fork release means updating these two commit constants.
set -euo pipefail

readonly module='github.com/layervai/frp'
readonly repository='https://github.com/layervai/frp.git'

# Reviewed dependency head and signed release merge on layerv/main. They have
# the same tree; the pseudo-version avoids the generic new-release quarantine.
readonly dependency_commit='9a0e4ee61964140e58f9cedd482c8f32b19acbd9'
readonly release_commit='03712d9a51a9e72b1d0263ce3a116b4f7f1d294c'

module_re="${module//./\\.}"
replace_line="$(grep -E "^replace github\\.com/fatedier/frp => ${module_re} v" go.mod || true)"
if [ -z "${replace_line}" ]; then
  echo "FRP replace directive for ${module} not found in go.mod" >&2
  exit 1
fi
# Field 5, not the last token: a trailing comment on the replace directive would
# make ${replace_line##* } grab the comment and surface later as a confusing
# "checksum pin missing" instead of a parse failure here.
version="$(awk '{print $5}' <<<"${replace_line}")"
readonly version
if [[ ! "${version}" =~ ^v[0-9] ]]; then
  printf 'could not read a pinned FRP version from go.mod; got %s\n' "${version}" >&2
  exit 1
fi
version_re="${version//./\\.}"
readonly version_re

release_version="${version}"
pseudo_commit_prefix=''
if [[ "${version}" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+)-0\.[0-9]{14}-([0-9a-f]{12})$ ]]; then
  release_version="${BASH_REMATCH[1]}"
  pseudo_commit_prefix="${BASH_REMATCH[2]}"
fi
readonly release_version pseudo_commit_prefix

read_sum() { # <go.sum key suffix>
  local key="$1" line
  line="$(grep -E "^${module_re} ${version_re}${key} h1:" go.sum || true)"
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
provenance_git=''
cleanup_provenance() {
  chmod -R u+w "${provenance_modcache}" 2>/dev/null || true
  rm -rf -- "${provenance_modcache}"
  if [ -n "${provenance_git}" ]; then
    chmod -R u+w "${provenance_git}" 2>/dev/null || true
    rm -rf -- "${provenance_git}"
  fi
}
trap cleanup_provenance EXIT
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
  "\"URL\": \"https://github.com/layervai/frp\""; do
  if ! grep -Fq "$field" <<<"${metadata}"; then
    echo "FRP proxy provenance mismatch: missing ${field}" >&2
    exit 1
  fi
done

origin_commit="$(awk -F '"' '$2 == "Hash" { print $4; exit }' <<<"${metadata}")"
readonly origin_commit
if [[ ! "${origin_commit}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "FRP proxy provenance mismatch: invalid origin commit ${origin_commit:-missing}" >&2
  exit 1
fi
if [ "${origin_commit}" != "${dependency_commit}" ]; then
  echo "FRP dependency resolves to ${origin_commit}, want ${dependency_commit}" >&2
  exit 1
fi
if [ -n "${pseudo_commit_prefix}" ]; then
  if [[ "${dependency_commit}" != "${pseudo_commit_prefix}"* ]]; then
    echo "FRP pseudo-version names ${pseudo_commit_prefix}, want ${dependency_commit}" >&2
    exit 1
  fi
elif [ "${dependency_commit}" != "${release_commit}" ] \
  || ! grep -Fq "\"Ref\": \"refs/tags/${version}\"" <<<"${metadata}"; then
  echo "FRP release proxy provenance mismatch for ${version}" >&2
  exit 1
fi

remote_refs="$(git ls-remote "${repository}" "refs/tags/${release_version}" "refs/tags/${release_version}^{}")"
remote_commit="$(awk '$2 ~ /\^\{\}$/ { print $1 }' <<<"${remote_refs}")"
if [ -z "${remote_commit}" ]; then
  remote_commit="$(awk '$2 !~ /\^\{\}$/ { print $1 }' <<<"${remote_refs}")"
fi
if [ "${remote_commit}" != "${release_commit}" ]; then
  echo "FRP release tag mismatch: ${release_version} resolves to ${remote_commit:-missing}, want ${release_commit}" >&2
  exit 1
fi

if [ -n "${pseudo_commit_prefix}" ]; then
  provenance_git="$(mktemp -d)"
  if ! git -C "${provenance_git}" init -q \
    || ! git -C "${provenance_git}" fetch -q --depth=2 "${repository}" "refs/tags/${release_version}" \
    || ! git -C "${provenance_git}" merge-base --is-ancestor "${dependency_commit}" "${release_commit}" \
    || [ "$(git -C "${provenance_git}" rev-parse "${dependency_commit}^{tree}")" != "$(git -C "${provenance_git}" rev-parse "${release_commit}^{tree}")" ]; then
    echo "FRP pseudo-version commit is not contained by signed release ${release_version}" >&2
    exit 1
  fi
fi

echo "FRP provenance verified through the public proxy: ${version} -> ${dependency_commit} (release ${release_version} -> ${release_commit})"
