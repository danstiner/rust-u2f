FROM rust:latest

RUN apt-get update && apt-get install -y clang-3.9 libssl-dev

WORKDIR /app
COPY . .

RUN cargo build --all

RUN cd ./softu2f-bin && cargo install

CMD ["softu2f-bin"]
