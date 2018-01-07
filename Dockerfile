FROM rust:latest

RUN apt-get update && apt-get install -y clang-3.9 libdbus-1-dev libssl-dev libsystemd-dev protobuf-compiler

WORKDIR /app
COPY . .

RUN cargo build

