#!/bin/bash
set -euxo pipefail

if hash podman 2>/dev/null; then
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
    cat "$base_dockerfile" | sed -e "s/$baseimage:latest/$image:$tag/" > "$dist_dockerfile"
    $docker build -f "$dist_dockerfile" -t "$build_target" .

    id=$($docker create "$build_target")
    $docker cp "$id":/app/linux/dist/. "$dist_path"
    $docker rm -v $id
}

[[ -d dist/ ]] && rm -r dist/

package fedora fedora 29
package fedora fedora 28

package debian debian buster
package debian debian stretch

package debian ubuntu bionic
package debian ubuntu cosmic
package debian ubuntu disco
package debian ubuntu xenial

