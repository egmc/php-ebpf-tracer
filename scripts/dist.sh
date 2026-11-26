#!/bin/sh
# Packages a static release build (make STATIC=1 dist) into
#
#   dist/php-ebpf-tracer-<version>-linux-<arch>.tar.gz
#       the binary, this project's licenses, and THIRD_PARTY_LICENSES/ with
#       the license of everything linked into the binary;
#   dist/sources/
#       the source of libelf, which is linked in under the LGPL-3.0: the
#       upstream elfutils release and the Alpine packaging (patches) it was
#       built with.
#
# Meant to run in docker/release.Dockerfile (Alpine). It downloads the license
# texts and sources that the build image does not ship.
set -eu

version=$1
bin=$2

arch=$(go env GOARCH)
name=php-ebpf-tracer-$version-linux-$arch
root=dist/$name
lic=$root/THIRD_PARTY_LICENSES
src=dist/sources

# fetch OUT URL... downloads the first URL that works. Some upstream sites
# turn away requests from CI networks, so mirrors come first.
fetch() {
	out=$1
	shift
	for url; do
		if curl -fsSL --retry 3 -o "$out" "$url"; then
			return 0
		fi
		echo "dist.sh: could not fetch $url" >&2
	done
	rm -f "$out"
	return 1
}

rm -rf "$root" "$root.tar.gz"
mkdir -p "$lic" "$src"

cp "$bin" README.md LICENSE "$root/"
cp -R LICENSES "$root/"

summary=$lic/README.txt
cat >"$summary" <<TXT
Third-party components linked into php-ebpf-tracer $version (linux/$arch).
Each directory holds the license texts of one component.

TXT

# --- Go: the standard library and every module linked into the binary -------

mkdir -p "$lic/go/std"
cp "$(go env GOROOT)/LICENSE" "$lic/go/std/"
echo "go/std            Go standard library $(go env GOVERSION)   BSD-3-Clause" >>"$summary"

go list -deps -tags netgo,osusergo \
	-f '{{with .Module}}{{.Path}} {{.Version}} {{.Dir}}{{end}}' ./cmd/php-ebpf-tracer |
	sort -u |
	while read -r path ver dir; do
		[ "$path" = github.com/egmc/php-ebpf-tracer ] && continue
		dest=$lic/go/$path
		mkdir -p "$dest"
		n=0
		for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
			[ -f "$f" ] || continue
			cp "$f" "$dest/"
			n=$((n + 1))
		done
		if [ "$n" -eq 0 ]; then
			echo "dist.sh: no license file in $path $ver" >&2
			exit 1
		fi
		echo "go/$path $ver" >>"$summary"
	done

# --- C libraries --------------------------------------------------------------

echo >>"$summary"

# libbpf: LGPL-2.1 OR BSD-2-Clause, used under BSD-2-Clause.
mkdir -p "$lic/libbpf"
cp libbpf/LICENSE libbpf/LICENSE.BSD-2-Clause "$lic/libbpf/"
v=$(awk '/define LIBBPF_MAJOR_VERSION/ {ma = $3} /define LIBBPF_MINOR_VERSION/ {mi = $3} END {print ma "." mi}' libbpf/src/libbpf_version.h)
echo "libbpf            $v (git submodule)   BSD-2-Clause (of LGPL-2.1 OR BSD-2-Clause)" >>"$summary"

# libelf (elfutils): LGPL-3.0-or-later OR GPL-2.0-or-later, used under the
# LGPL-3.0-or-later. Its source goes into dist/sources.
v=$(pkg-config --modversion libelf)
tarball=elfutils-$v.tar.bz2
alpine=
[ -f /etc/alpine-release ] && alpine=$(cut -d. -f1,2 /etc/alpine-release)
[ -f "$src/$tarball" ] || fetch "$src/$tarball" \
	${alpine:+"https://distfiles.alpinelinux.org/distfiles/v$alpine/$tarball"} \
	"https://sourceware.org/elfutils/ftp/$v/$tarball"
tmp=$(mktemp -d)
tar -xjf "$src/$tarball" -C "$tmp" "elfutils-$v/COPYING" "elfutils-$v/COPYING-LGPLV3" "elfutils-$v/COPYING-GPLV2"
mkdir -p "$lic/elfutils"
cp "$tmp/elfutils-$v"/COPYING* "$lic/elfutils/"
rm -rf "$tmp"
if [ -n "$alpine" ]; then
	# The Alpine packaging libelf was built from: APKBUILD and its patches,
	# from the GitHub mirror of aports.
	branch=$alpine-stable
	aports=alpine-aports-$branch-main-elfutils.tar.gz
	if [ ! -f "$src/$aports" ]; then
		tmp=$(mktemp -d)
		dir=$tmp/aports-$branch-main-elfutils
		base=https://raw.githubusercontent.com/alpinelinux/aports/$branch/main/elfutils
		mkdir -p "$dir"
		fetch "$dir/APKBUILD" "$base/APKBUILD"
		# Local files are the source= entries that are not URLs.
		for f in $(sed -n '/^source="/,/"/p' "$dir/APKBUILD" | sed 's/^source=//' | tr -d '"' |
			tr ' \t' '\n\n' | grep -v -e '://' -e '^$'); do
			fetch "$dir/$f" "$base/$f"
		done
		tar -czf "$src/$aports" -C "$tmp" "aports-$branch-main-elfutils"
		rm -rf "$tmp"
	fi
fi
echo "elfutils (libelf) $v   LGPL-3.0-or-later (of LGPL-3.0-or-later OR GPL-2.0-or-later); source in sources/ of the release" >>"$summary"

# zlib: the license is the comment at the top of zlib.h.
v=$(pkg-config --modversion zlib)
mkdir -p "$lic/zlib"
sed -n '1,/\*\//p' "$(pkg-config --variable=includedir zlib)/zlib.h" >"$lic/zlib/LICENSE"
echo "zlib              $v   Zlib" >>"$summary"

# zstd: BSD-3-Clause OR GPL-2.0-only, used under BSD-3-Clause. Only linked
# when libelf was built with it.
if pkg-config --static --libs libelf | grep -q -- -lzstd; then
	v=$(pkg-config --modversion libzstd)
	mkdir -p "$lic/zstd"
	fetch "$lic/zstd/LICENSE" "https://raw.githubusercontent.com/facebook/zstd/v$v/LICENSE"
	echo "zstd              $v   BSD-3-Clause (of BSD-3-Clause OR GPL-2.0-only)" >>"$summary"
fi

# musl: MIT.
if v=$(apk list -I musl 2>/dev/null | sed -n 's/^musl-\([0-9.]*\)-r.*/\1/p') && [ -n "$v" ]; then
	mkdir -p "$lic/musl"
	tmp=$(mktemp -d)
	fetch "$tmp/musl.tar.gz" \
		${alpine:+"https://distfiles.alpinelinux.org/distfiles/v$alpine/musl-$v.tar.gz"} \
		"https://musl.libc.org/releases/musl-$v.tar.gz"
	tar -xzf "$tmp/musl.tar.gz" -C "$tmp" "musl-$v/COPYRIGHT"
	cp "$tmp/musl-$v/COPYRIGHT" "$lic/musl/"
	rm -rf "$tmp"
	echo "musl              $v   MIT" >>"$summary"
fi

cat >>"$summary" <<TXT

libgcc, also linked in, is covered by the GCC Runtime Library Exception and
needs no notice. The BPF program embedded in the binary is part of this
project and licensed GPL-2.0-only OR BSD-2-Clause (see LICENSES/).
TXT

tar -czf "$root.tar.gz" -C dist "$name"
rm -rf "$root"
echo "dist.sh: wrote $root.tar.gz"
ls -l "$src"
