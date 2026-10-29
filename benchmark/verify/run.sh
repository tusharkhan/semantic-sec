#!/bin/sh
# Usage: run.sh <laravel11-app|laravel10-app>
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
APP=${1:?usage: run.sh <laravel11-app|laravel10-app>}
TARGET=$(mktemp -d)
trap 'rm -rf "$TARGET"' EXIT

sh "$HERE/build.sh" "$APP" "$TARGET/project"
cd "$TARGET/project"
status=0
php artisan test || status=$?
php artisan route:list --json > "$TARGET/routes.json" || status=$?
php "$HERE/lib/check-routes.php" "$HERE/../expected.yaml" "$APP" "$TARGET/routes.json" || status=$?
exit "$status"
