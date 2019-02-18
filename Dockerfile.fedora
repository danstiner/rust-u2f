FROM fedora:latest

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN yum -y groupinstall 'Development Tools' && \
    yum -y install \
      clang \
      dbus-devel \
      libselinux-devel \
      openssl-devel \
      pkg-config \
      protobuf-compiler \
      selinux-policy-devel \
      systemd-devel \
      rpm-build && \
    yum clean all

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

COPY . /app
WORKDIR /app/linux

RUN cargo test

RUN make rpm

RUN mkdir -p dist/ && cp -r target/fedora/* dist/

CMD ["/bin/bash"]
