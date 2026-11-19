#!/usr/bin/env bash
# 本地构建 capri-hub 发布产物，并可选上传到 GitHub Release。
#
# 用法：
#   scripts/release-local.sh v0.5.1 --build-only
#   scripts/release-local.sh v0.5.1 --notes-file /tmp/notes.md
#
# 产物写到 dist/release/<tag>/（已在 .gitignore 中）。默认会创建或更新 GitHub
# Release；--build-only 只出包。要求当前 checkout 在 tag 对应提交上，工作区
# 干净；确实要带未提交改动时加 --allow-dirty。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TAG=""
NOTES_FILE=""
BUILD_ONLY=0
ALLOW_DIRTY=0

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  echo "error: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-only)
      BUILD_ONLY=1
      shift
      ;;
    --notes-file)
      [[ $# -ge 2 ]] || die "--notes-file 缺少路径"
      NOTES_FILE="$2"
      shift 2
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      die "未知选项 $1"
      ;;
    *)
      [[ -z "$TAG" ]] || die "只接受一个 tag"
      TAG="$1"
      shift
      ;;
  esac
done

[[ -n "$TAG" ]] || {
  usage
  exit 1
}
printf '%s' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' ||
  die "tag 必须形如 vX.Y.Z，收到 $TAG"
command -v go >/dev/null || die "找不到 go"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null ||
  die "本地没有 tag $TAG"

if [[ -n "$(git status --porcelain)" ]]; then
  if [[ "$ALLOW_DIRTY" -eq 1 ]]; then
    echo "warn: 工作区有未提交改动，继续构建（--allow-dirty）" >&2
  else
    die "工作区有未提交改动；提交后再发，或加 --allow-dirty"
  fi
fi

if [[ "$(git rev-parse HEAD^{commit})" != "$(git rev-parse "$TAG^{commit}")" ]]; then
  if [[ "$ALLOW_DIRTY" -eq 1 ]]; then
    echo "warn: HEAD 不在 $TAG 对应提交上，继续构建（--allow-dirty）" >&2
  else
    die "HEAD 不在 $TAG 对应提交上；先 git checkout $TAG，或加 --allow-dirty"
  fi
fi

if [[ "$BUILD_ONLY" -eq 0 ]]; then
  command -v gh >/dev/null || die "找不到 gh"
  git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1 ||
    die "远端还没有 tag $TAG；先 git push origin $TAG"
fi

OUT="$ROOT/dist/release/$TAG"
rm -rf "$OUT"
mkdir -p "$OUT"

for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  ext=""
  [[ "$GOOS" == "windows" ]] && ext=".exe"
  name="capri-hub-${TAG}-${GOOS}-${GOARCH}${ext}"
  echo "build  $name"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath \
    -ldflags "-s -w -X main.version=${TAG}" \
    -o "$OUT/$name" ./cmd/capri-hub
done

echo "built  $OUT"

if [[ "$BUILD_ONLY" -eq 1 ]]; then
  echo "skip   GitHub Release (--build-only)"
  exit 0
fi

if gh release view "$TAG" >/dev/null 2>&1; then
  gh release upload "$TAG" "$OUT"/* --clobber
  if [[ -n "$NOTES_FILE" ]]; then
    gh release edit "$TAG" --notes-file "$NOTES_FILE"
  fi
  echo "updated https://github.com/AgentsHarness/capri-hub/releases/tag/$TAG"
else
  ARGS=(release create "$TAG" --title "capri-hub $TAG" --verify-tag)
  if [[ -n "$NOTES_FILE" ]]; then
    ARGS+=(--notes-file "$NOTES_FILE")
  else
    ARGS+=(--generate-notes)
  fi
  gh "${ARGS[@]}" "$OUT"/*
  echo "created https://github.com/AgentsHarness/capri-hub/releases/tag/$TAG"
fi
