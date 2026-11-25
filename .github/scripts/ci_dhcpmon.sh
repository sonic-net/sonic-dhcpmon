#!/usr/bin/env bash
# Run from the source checkout on a native Debian Trixie runner.
set -euo pipefail
out=${1:?pass an artifact directory outside the checkout}
mkdir -p "$out"
arch=$(dpkg --print-architecture)
case "$arch:$(uname -m)" in
  amd64:x86_64) platform=@sonic_build_infra//platforms:x86_64_trixie ;;
  arm64:aarch64) platform=@sonic_build_infra//platforms:aarch64_trixie ;;
  *) echo "Unsupported native host: $arch / $(uname -m)" >&2; exit 1 ;;
esac
test "$(bazel --version)" = "bazel $(cat .bazelversion)"
test ! -e MODULE.bazel.lock
git check-ignore -q MODULE.bazel.lock

# These public mirrors keep the original source and Debian package checksums.
mirrors="$out/source_mirrors.cfg"
tools_dir=$(mktemp -d)
fetch_ci_input() {
  curl --disable --fail --silent --show-error --retry 3 --max-time 60 \
    "https://raw.githubusercontent.com/sonic-net/sonic-bazel-registry/main/ci/$1" -o "$3"
  printf '%s  %s\n' "$2" "$3" | sha256sum -c -
}
fetch_ci_input source_mirrors.cfg c28e6882aa9ebed84fd32586112e5fbfe9684af4e4aaa9942170919a3cbd308e "$mirrors"
# The declared test launcher needs Cosmos tools. Use the same upstream release
# and member digests as SWSS CI without requiring the cosmo.zip endpoint.
fetch_ci_input github_sources.py 06836c38c56aa0e77e1f7adac68b6463f8f1e920e0beb000061cec5b7f5ec1f2 "$tools_dir/github_sources.py"
fetch_ci_input github_sources/cosmos-4.0.2.json 1579ad34288945a28a2d77f96f4764b8910dd3d856d688971e46e63e58119af5 "$tools_dir/cosmos.json"
python3 "$tools_dir/github_sources.py" --manifest "$tools_dir/cosmos.json" --distdir "$tools_dir/dist" \
  --cache-dir "$tools_dir/cache" --receipt "$out/github-sources.json"

download_flags=(--downloader_config="$mirrors" --distdir="$tools_dir/dist")
flags=(--lockfile_mode=update --host_platform="$platform" --platforms="$platform" "${download_flags[@]}")
archives=(//:runtime //:runtime.debug_symbols)
bazel build "${flags[@]}" --jobs=4 "${archives[@]}" //:monitor_metadata
bazel test "${flags[@]}" --jobs=4 --nocache_test_results --test_output=errors //:util_behavior_test

for target in "${archives[@]}"; do
  file=$(bazel cquery "${flags[@]}" --output=files "$target")
  test -f "$file"
  cp "$file" "$out/${target#//:}.tar"
done
python3 .github/scripts/check_dhcpmon_artifacts.py --arch "$arch" "$out/runtime.tar" "$out/runtime.debug_symbols.tar" > "$out/debug-pair.json"
metadata=$(bazel cquery "${flags[@]}" --output=files //:monitor_metadata)
cp "$metadata" "$out/monitor_metadata.json"
# Inspect the target package trees declared by runtime_packages, never the runner's dpkg database.
bazel cquery "${flags[@]}" //:monitor_metadata --output=starlark \
  --starlark:expr='"\n".join([f.path for k, p in providers(target).items() if k.endswith("%RuntimePackagesInfo") for f in p.trees.to_list()])' \
  > "$tools_dir/package-trees"
python3 .github/scripts/check_dhcpmon_metadata.py "$arch" "$out/runtime.tar" "$out/monitor_metadata.json" \
  "$tools_dir/package-trees" > "$out/metadata-verification.json"
# Record the actual published inputs so both jobs can be compared with infra.
# External cquery paths are relative to the execution root, which owns bazel-out.
execroot=$(dirname "$(realpath bazel-out)")
for name in apt.lock requests sources; do
  label="@sonic_build_infra//apt:$name.json"
  file=$(bazel cquery "${flags[@]}" --output=files "$label")
  checksum=$(sha256sum "$execroot/$file")
  printf '%s  %s\n' "${checksum%% *}" "$label"
done > "$out/infra-apt-inputs.txt"
cp bazel-testlogs/util_behavior_test/test.{log,xml} "$out/"
grep -Fx 'Monitor-production-utility-PASS 10 groups' "$out/test.log"
bazel aquery "${flags[@]}" 'mnemonic("CppCompile", //:dhcpmon)' --output=text > "$out/daemon-compile-actions.txt"
bazel aquery "${flags[@]}" 'mnemonic("DebAssemble", deps(set(//:runtime //:runtime.debug_symbols //:monitor_metadata //:util_behavior_test)))' \
  --output=jsonproto | python3 -c 'import json, sys; sys.exit("unexpected DEB assembly action") if json.load(sys.stdin).get("actions") else None'
bazel mod graph --lockfile_mode=update "${download_flags[@]}" > "$out/module-graph.txt"
cp MODULE.bazel.lock "$out/"
git diff --exit-code HEAD --
printf 'source=%s\ncheckout=%s\nuserspace=%s\nhost_and_target=%s\n' \
  "$SOURCE_SHA" "$(git rev-parse HEAD)" "$(dpkg --print-architecture)" "$platform" > "$out/build.txt"
bazel --version >> "$out/build.txt"
(cd "$out" && sha256sum *.tar *.json *.lock *.txt *.log *.xml *.cfg > SHA256SUMS)
