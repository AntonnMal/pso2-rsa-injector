# WARNING! Read before downloading
On 1/11/2023 (6/11/2023 for Steam) Sega will incorporate/have incorporated a new anticheat: Xigncode3 ([source](https://pso2.com/players/news/i_Wellbia_20231026/)). This means that this injector will most likely not work and could get you banned. While they say that you can use GG, this won't last forever.

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
2) Copy your `publickey.blob` to `pso2_bin`.
3) (Optional) Copy `config.toml` to `pso2_bin` and edit it.
4) Run `injector.exe`.
5) Launch the game.

## Notes

 - Code is generally lacking in comments.
