FROM rust:latest

RUN apt-get update && apt-get install -y llvm-3.9-dev libclang-3.9-dev clang-3.9

WORKDIR /app
COPY . .

RUN cargo build --all

RUN cd ./softu2f-bin && cargo install

CMD ["softu2f-bin"]
