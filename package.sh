#!/bin/bash
set -euo pipefail

if [[ -n ${DOCKER+x} ]]; then
    docker="$DOCKER"
elif hash podman 2>/dev/null; then
    docker=podman
else
    docker=docker
fi

package() {
    baseimage=$1
    image=$2
    tag=$3

    base_dockerfile="Dockerfile.$baseimage"
    build_target="rust-u2f-build-$image:$tag"
    dist_path="dist/$image/$tag/"
    dist_dockerfile="${dist_path}Dockerfile"

    mkdir -p "$dist_path"
    sed -e "s/$baseimage:latest/$image:$tag/" < "$base_dockerfile" > "$dist_dockerfile"
    $docker build -f "$dist_dockerfile" -t "$build_target" .

    id=$($docker create "$build_target")
    $docker cp "$id":/app/linux/dist/. "$dist_path"
    $docker rm -v $id
}

[[ -d dist/ ]] && rm -r dist/

if [[ $# -eq 3 ]]; then
    package "$1" "$2" "$3"
else
    package fedora fedora 30
    package fedora fedora 29
    package fedora fedora 28
    package debian debian bullseye
    package debian debian buster
    package debian debian stretch
    package debian debian jessie
    package debian ubuntu eoan
    package debian ubuntu disco
    package debian ubuntu bionic
    package debian ubuntu xenial
fi
