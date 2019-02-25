FROM debian:latest

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y \
      build-essential \
      clang \
      curl \
      debhelper \
      libdbus-1-dev \
      libssl-dev \
      libsystemd-dev \
      libudev-dev \
      systemd \
      unzip

ARG protoc_version=3.6.1

RUN set -eux; \
    url="https://github.com/google/protobuf/releases/download/v${protoc_version}/protoc-${protoc_version}-linux-x86_64.zip"; \
    curl -sSfOL "$url"; \
    unzip "protoc-${protoc_version}-linux-x86_64.zip" -d protoc3; \
    mv protoc3/bin/* /usr/local/bin/; \
    mv protoc3/include/* /usr/local/include/;

RUN set -eux; \
    url="https://sh.rustup.rs"; \
    curl -sSf -o rustup-init "$url"; \
    sha256sum rustup-init; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain stable; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version;

RUN cargo install cargo-deb

COPY . /app
WORKDIR /app/linux

RUN cargo test

RUN mkdir -p dist/

RUN cd system-daemon && cargo deb
RUN mv target/debian/*.deb dist/

RUN cd user-daemon && cargo deb
RUN mv target/debian/*.deb dist/

RUN cd meta-package && dpkg-buildpackage -us -uc
RUN mv *.deb dist/

RUN cd u2f-hidraw-policy && dpkg-buildpackage -b
RUN mv *.deb dist/

CMD ["/bin/bash"]
