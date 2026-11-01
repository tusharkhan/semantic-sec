#!/bin/sh
# Builds build/semantic-sec.phar with a pinned, checksum-verified Box; --verify also runs it under php:8.2-cli and php:8.4-cli.
set -eu

BOX_VERSION=4.7.0
BOX_SHA256=3d390eeaec33288098fe83f8a54c60cc575cb6be295f38ff4482b4b4f26f8d52
BOX_URL="https://github.com/box-project/box/releases/download/${BOX_VERSION}/box.phar"

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/build"
verify=0
for arg in "$@"; do
    case "$arg" in
        --verify) verify=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

fail() { echo "build-phar: $*" >&2; exit 1; }

sha256_check() {
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$1  $2" | sha256sum -c - >/dev/null
    else
        echo "$1  $2" | shasum -a 256 -c - >/dev/null
    fi
}

sha256_write() {
    (cd "$(dirname "$1")" && if command -v sha256sum >/dev/null 2>&1; then sha256sum "$(basename "$1")"; else shasum -a 256 "$(basename "$1")"; fi) > "$1.sha256"
}

build() {
    command -v composer >/dev/null 2>&1 || fail "composer is not on PATH"
    mkdir -p "$out"
    box="$out/box-$BOX_VERSION.phar"
    if [ ! -f "$box" ]; then
        php -r 'copy($argv[1], $argv[2]) || exit(1);' "$BOX_URL" "$box.part" || fail "could not download $BOX_URL"
        mv "$box.part" "$box"
    fi
    sha256_check "$BOX_SHA256" "$box" || { rm -f "$box"; fail "box.phar checksum mismatch (expected $BOX_SHA256)"; }

    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    mkdir "$work/bin"
    cp "$root/bin/semantic-sec" "$work/bin/"
    cp -R "$root/src" "$root/config" "$work/"
    cp "$root/composer.json" "$root/composer.lock" "$root/box.json" "$root/LICENSE" "$work/"

    # Advisory blocking stays on: a vulnerable locked dependency fails the build.
    (cd "$work" && composer install --no-dev --classmap-authoritative --no-interaction --no-progress --prefer-dist)
    php -d phar.readonly=0 "$box" compile --working-dir="$work" --no-interaction

    rm -f "$out/semantic-sec.phar"
    mv "$work/semantic-sec.phar" "$out/semantic-sec.phar"
    sha256_write "$out/semantic-sec.phar"
    cat "$out/semantic-sec.phar.sha256"
}

run_verify() {
    command -v docker >/dev/null 2>&1 || fail "--verify needs docker"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    cp -R "$root/benchmark/laravel11-app" "$tmp/app"
    user="$(id -u):$(id -g)"
    docker run --rm -u "$user" -v "$root:/src:ro" -v "$tmp:/work" -w /tmp semantic-sec:dev \
        php /src/bin/semantic-sec map --format=json --project-root=/work/app > "$tmp/ref.json"
    for v in 8.2 8.4; do
        img="php:$v-cli"
        echo "== $img"
        docker run --rm -u "$user" -v "$out:/phar:ro" -v "$tmp:/work" -w /tmp "$img" php /phar/semantic-sec.phar --version
        docker run --rm -u "$user" -v "$out:/phar:ro" -v "$tmp:/work" -w /tmp "$img" \
            php /phar/semantic-sec.phar map --format=json --project-root=/work/app > "$tmp/map-$v.json"
        cmp "$tmp/ref.json" "$tmp/map-$v.json" || fail "$img: PHAR map output differs from bin/semantic-sec"
        echo "map: byte-identical to bin/semantic-sec ($(wc -c < "$tmp/ref.json") bytes)"
        rm -rf "$tmp/app/.semantic-sec"
        docker run --rm -u "$user" -v "$out:/phar:ro" -v "$tmp:/work" -w /tmp "$img" \
            php /phar/semantic-sec.phar analyze --dry-run --format=json --project-root=/work/app > "$tmp/dry-$v.json"
        n=$(find "$tmp/app/.semantic-sec/dry-run" -name '*.txt' | wc -l)
        [ "$n" -gt 1 ] || fail "$img: analyze --dry-run wrote no payloads"
        echo "analyze --dry-run: $n files written"
    done
}

if command -v php >/dev/null 2>&1; then
    build
elif command -v docker >/dev/null 2>&1; then
    # No host PHP: build inside the repo's php image (PHP 8.2 by default).
    (cd "$root" && docker compose run --rm -T php sh tools/build-phar.sh)
else
    fail "needs php and composer, or docker"
fi

if [ "$verify" = 1 ]; then
    run_verify
fi
