#!/usr/bin/env bash
# Build the four images and make them available to k3s.
#
# k3s runs containerd, not Docker, and it does not see your local Docker
# images. Two ways to bridge that, and this script does whichever applies:
#
#   no registry   images are exported to a tarball and imported straight into
#                 the node's containerd with `k3s ctr images import`. Works on
#                 a single-node k3s, which is the common case.
#   --registry R  images are tagged R/<name> and pushed. Use this for more
#                 than one node, and remember to point the manifests at R with
#                 `kustomize edit set image` or by editing kustomization.yaml.
#
# Run it ON the k3s node for the import path; it needs `k3s ctr`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$ROOT"

REGISTRY=""
TAG="latest"
while [ $# -gt 0 ]; do
  case "$1" in
    --registry) REGISTRY="${2:-}"; shift ;;
    --tag)      TAG="${2:-}"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '[k3s] %s\n' "$*"; }

command -v docker >/dev/null 2>&1 || { echo "docker is needed to BUILD the images" >&2; exit 1; }

build() {
  local name="$1" context="$2" target="${3:-}"
  local tag="${REGISTRY:+${REGISTRY}/}${name}:${TAG}"
  log "building ${tag}"
  if [ -n "$target" ]; then
    docker build --target "$target" -t "$tag" "$context"
  else
    docker build -t "$tag" "$context"
  fi
  echo "$tag"
}

IMAGES=()
IMAGES+=("$(build syphax-backend ./backend app)")
IMAGES+=("$(build syphax-proxy ./backend proxy)")
IMAGES+=("$(build syphax-frontend ./frontend)")
IMAGES+=("$(build syphax-sandbox-runner ./sandbox-runner)")

if [ -n "$REGISTRY" ]; then
  for image in "${IMAGES[@]}"; do
    log "pushing ${image}"
    docker push "$image"
  done
  log "done. Point kustomization.yaml at ${REGISTRY}."
  exit 0
fi

command -v k3s >/dev/null 2>&1 || {
  echo "k3s not found. Run this on the k3s node, or use --registry." >&2
  exit 1
}

tar="$(mktemp -t syphax-images-XXXXXX.tar)"
trap 'rm -f "$tar"' EXIT
log "exporting ${#IMAGES[@]} images"
docker save "${IMAGES[@]}" -o "$tar"
log "importing into containerd (needs root)"
sudo k3s ctr images import "$tar"
log "done. The manifests use imagePullPolicy: IfNotPresent, so they will find them."
