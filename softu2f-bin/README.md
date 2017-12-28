```sh
sudo apt install clang-3.9 curl git libssl-dev libdub-1-dev
curl https://sh.rustup.rs -sSf | sh
git clone https://github.com/danstiner/softu2f-linux.git
cd softu2f-linux/softu2f-bin
cargo install


sudo apt install libudev-dev
cd
git clone https://github.com/amluto/u2f-hidraw-policy.git
cd u2f-hidraw-policy
make
sudo make install

sudo ../target/release/softu2f-bin
```

```
sudo apt install liblzma-dev
cd softu2f-linux/softu2f-bin
cargo deb
```
