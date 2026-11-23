#!/usr/bin/env bash
# Build the static site and publish apps/web/out to the gh-pages branch.
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build -w shieldtrail-web
node apps/web/e2e/smoke.mjs
out=apps/web/out
touch "$out/.nojekyll" # otherwise GitHub Pages' Jekyll drops the _next/ folder
rev=$(git rev-parse --short HEAD)
tmp=$(mktemp -d)
cp -r "$out/." "$tmp/"
git -C "$tmp" init -q -b gh-pages
git -C "$tmp" add -A
git -C "$tmp" -c user.name="$(git config user.name)" -c user.email="$(git config user.email)" commit -qm "deploy site from $rev"
git -C "$tmp" push -qf "$(git remote get-url origin)" gh-pages
rm -rf "$tmp"
echo "published $rev → https://sergemiro.github.io/ShieldTrail/"
