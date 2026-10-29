#!/bin/sh
# Usage: build.sh <laravel11-app|laravel10-app> <absolute-target-dir>
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
APP=${1:-}
TARGET=${2:-}

case "$APP" in
    laravel11-app | laravel10-app) ;;
    *) echo "usage: build.sh <laravel11-app|laravel10-app> <target>" >&2; exit 2 ;;
esac
[ -n "$TARGET" ] || { echo "usage: build.sh <app> <target>" >&2; exit 2; }
case "$TARGET" in
    /*) ;;
    *) echo "target must be an absolute path" >&2; exit 2 ;;
esac

TARGET=$(printf '%s' "$TARGET" | sed 's#/*$##')
case "$TARGET/" in
    "$ROOT"/*) echo "target must be outside the repository" >&2; exit 2 ;;
esac

SRC="$ROOT/benchmark/$APP"
VERIFY="$ROOT/benchmark/verify/$APP"

rm -rf "$TARGET"
mkdir -p "$(dirname "$TARGET")"

if ! composer create-project laravel/laravel:^12.0 "$TARGET" --no-interaction --prefer-dist; then
    echo "create-project failed — if this is a security-advisory block, the Laravel 12 line may now be flagged; do NOT disable blocking, raise the skeleton version instead" >&2
    exit 1
fi

if [ "$APP" = "laravel11-app" ]; then
    rm -rf "$TARGET/app/Http/Controllers" "$TARGET/app/Models" "$TARGET/app/Providers"
    cp -R "$SRC/app/." "$TARGET/app/"
    cp -R "$SRC/routes/." "$TARGET/routes/"
    cp "$SRC/bootstrap/app.php" "$SRC/bootstrap/providers.php" "$TARGET/bootstrap/"
else
    for d in app routes database; do
        if [ -d "$SRC/$d" ]; then
            mkdir -p "$TARGET/$d"
            cp -R "$SRC/$d/." "$TARGET/$d/"
        fi
    done
fi

rm -f "$TARGET/tests/Feature/ExampleTest.php" "$TARGET/tests/Unit/ExampleTest.php"

if [ -d "$VERIFY" ]; then
    cp -R "$VERIFY/." "$TARGET/"
fi

cd "$TARGET"
if grep -q 'auth:sanctum' routes/api.php 2>/dev/null; then
    composer require laravel/sanctum --no-interaction
fi
composer dump-autoload --no-interaction

echo "built $APP at $TARGET"
