#!/bin/bash
set -euxo pipefail

package_with_docker() {
    baseimage=$1
    image=$2
    tag=$3

    base_dockerfile="Dockerfile.$baseimage"
    build_target="rust-u2f-build-$image:$tag"
    dist_path="dist/$image/$tag/"
    dist_dockerfile="$dist_path/Dockerfile"

    mkdir -p "$dist_path"
    cat "$base_dockerfile" | sed -e "s/$baseimage:latest/$image:$tag/" > "$dist_dockerfile"
    docker build . -f "$dist_dockerfile" -t "$build_target"

    id=$(docker create "$build_target")
    docker cp "$id":/app/linux/dist/. "$dist_path"
    docker rm -v $id
}

[[ -d dist/ ]] && rm -r dist/

package_with_docker debian debian latest
package_with_docker debian debian stretch

package_with_docker debian ubuntu bionic
package_with_docker debian ubuntu cosmic
package_with_docker debian ubuntu disco
package_with_docker debian ubuntu xenial

package_with_docker fedora fedora 29
package_with_docker fedora fedora 28
