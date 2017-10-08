FROM rust:latest

RUN apt-get update && apt-get install -y llvm-3.9-dev libclang-3.9-dev clang-3.9

WORKDIR /app
COPY . .

RUN cd uhid-linux-tokio/example && cargo install

CMD ["example"]
