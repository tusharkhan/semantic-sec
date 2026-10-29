#!/bin/sh
# Usage: run.sh <laravel11-app|laravel10-app>
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
APP=${1:?usage: run.sh <laravel11-app|laravel10-app>}
TARGET=$(mktemp -d)

sh "$HERE/build.sh" "$APP" "$TARGET/project"
cd "$TARGET/project"
php artisan test
