#!/bin/sh
# Usage: build.sh <laravel12-app|laravel11-app|laravel10-app> <absolute-target-dir>
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
APP=${1:-}
TARGET=${2:-}

case "$APP" in
    laravel12-app | laravel11-app | laravel10-app) ;;
    *) echo "usage: build.sh <laravel12-app|laravel11-app|laravel10-app> <target>" >&2; exit 2 ;;
esac
[ -n "$TARGET" ] || { echo "usage: build.sh <app> <target>" >&2; exit 2; }
case "$TARGET" in
    /*) ;;
    *) echo "target must be an absolute path" >&2; exit 2 ;;
esac

TARGET=$(printf '%s' "$TARGET" | sed 's#/*$##')
[ -n "$TARGET" ] || { echo "refusing: target is /" >&2; exit 2; }
case "/$TARGET/" in
    */../*) echo "refusing: target contains a .. segment" >&2; exit 2 ;;
esac
PARENT=$(dirname "$TARGET")
[ -d "$PARENT" ] || { echo "refusing: parent directory $PARENT does not exist" >&2; exit 2; }
CANON="$(cd "$PARENT" && pwd -P)/$(basename "$TARGET")"
CANON=$(printf '%s' "$CANON" | sed 's#^//*#/#')
case "$CANON/" in
    "$ROOT"/* | /) echo "refusing: target is inside the repository or is /" >&2; exit 2 ;;
esac
case "$ROOT/" in
    "$CANON"/*) echo "refusing: target is the repository or an ancestor of it" >&2; exit 2 ;;
esac
TARGET=$CANON

SRC="$ROOT/benchmark/$APP"
VERIFY="$ROOT/benchmark/verify/$APP"

if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    if [ -d "$TARGET" ] && [ ! -L "$TARGET" ] && { [ -z "$(ls -A "$TARGET")" ] || [ -f "$TARGET/.semantic-sec-verify" ]; }; then
        rm -rf "$TARGET"
    else
        echo "target exists and is not a previous verification build" >&2
        exit 2
    fi
fi
mkdir -p "$(dirname "$TARGET")"

if ! composer create-project laravel/laravel:^12.0 "$TARGET" --no-interaction --prefer-dist; then
    echo "create-project failed — if this is a security-advisory block, the Laravel 12 line may now be flagged; do NOT disable blocking, raise the skeleton version instead" >&2
    exit 1
fi

if [ "$APP" = "laravel11-app" ] || [ "$APP" = "laravel12-app" ]; then
    rm -rf "$TARGET/app/Http/Controllers" "$TARGET/app/Models" "$TARGET/app/Providers"
    cp -R "$SRC/app/." "$TARGET/app/"
    cp -R "$SRC/routes/." "$TARGET/routes/"
    cp "$SRC/bootstrap/app.php" "$SRC/bootstrap/providers.php" "$TARGET/bootstrap/"
else
    rm -rf "$TARGET/app/Http/Controllers" "$TARGET/app/Models" "$TARGET/app/Providers" "$TARGET/routes/web.php"
    cp -R "$SRC/app/." "$TARGET/app/"
    cp "$SRC"/routes/*.php "$TARGET/routes/"
fi

rm -f "$TARGET/tests/Feature/ExampleTest.php" "$TARGET/tests/Unit/ExampleTest.php"

if [ -d "$VERIFY" ]; then
    cp -R "$VERIFY/." "$TARGET/"
fi

cd "$TARGET"
if [ "$APP" = "laravel10-app" ]; then
    php "$ROOT/benchmark/verify/lib/register-legacy-providers.php" "$TARGET"
fi
if grep -q 'auth:sanctum' routes/api.php 2>/dev/null; then
    if ! composer require laravel/sanctum --no-interaction; then
        echo "composer require laravel/sanctum failed — if this is a security-advisory block, do NOT disable blocking; report it" >&2
        exit 1
    fi
fi
composer dump-autoload --no-interaction

touch "$TARGET/.semantic-sec-verify"
echo "built $APP at $TARGET"
