# PSO2 RSA Injector

A "simple" RSA key swapper for PSO2 (tested only on global). This project is based on [cyberkitsune's "PSO2KeyTools"](https://github.com/cyberkitsune/PSO2Proxy/tree/5355aea6edb5342a439642c892369443246c4644/tools).

## Building

You will need to install [rust compiler](https://www.rust-lang.org/tools/install).

From Windows:
```
cargo build
```

From Linux:
```
rustup target add x86_64-pc-windows-gnu # run if the windows toolchain is not installed
cargo build --target x86_64-pc-windows-gnu
```

## Usage

1) Generate a [key pair](https://github.com/cyberkitsune/PSO2Proxy#your-private--public-keypair).
2) Copy your `publickey.blob` to `pso2_bin` and game root folders.
3) Run `injector.exe`.
4) Launch the game.

## Notes

 - Code is generally lacking in comments.