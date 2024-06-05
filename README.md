# powdr-revme

## Setup 

Edit `~/.cargo/config` and add:  

```
[target.mips-unknown-linux-musl]
linker = "/mnt/data/angell/mips-linux-muslsf-cross/bin/mips-linux-muslsf-gcc"
rustflags = ["-C", "target-feature=+crt-static", "-C", "link-arg=-g", "-C", "link-args=-lc"]
```

## Compile
```
cargo build -Z build-std=core,alloc --target mips-unknown-linux-musl
```
