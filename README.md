# WARNING! Read before downloading

While this version should work, you might get banned for using it, so **_use at your own risk!_**

# PSO2 RSA Injector

A "simple" RSA key swapper for PSO2 (tested only on global). This project is based on [cyberkitsune's "PSO2KeyTools"](https://github.com/cyberkitsune/PSO2Proxy/tree/5355aea6edb5342a439642c892369443246c4644/tools).

## Building

You will need to install [rust compiler](https://www.rust-lang.org/tools/install).

From Windows:
```
cargo build
```

From Linux (only for injector and rsa replacer):
```
rustup target add x86_64-pc-windows-gnu # run if the windows toolchain is not installed
cargo build --target x86_64-pc-windows-gnu
```

## Usage

### For gameguard
1) Generate a [key pair](https://github.com/cyberkitsune/PSO2Proxy#your-private--public-keypair).
2) (If the server doesn't support auto key negotiation) Copy your `publickey.blob` to `pso2_bin`.
3) (Optional) Copy `config.toml` to `pso2_bin` and edit it.
4) Run `injector.exe`.
5) Launch the game.

### For xigncode3
1) Generate a [key pair](https://github.com/cyberkitsune/PSO2Proxy#your-private--public-keypair).
2) (If the server doesn't support auto key negotiation) Copy your `publickey.blob` to `pso2_bin\sub`.
3) (Optional) Copy `config.toml` to `pso2_bin\sub` and edit it.
4) Copy `rsa_inject.dll` and `dllhijack.dll` to `pso2_bin\sub`
5) Rename `dllhijack.dll` to `ddraw.dll`.
6) Launch the game.

## Notes

 - Code is generally lacking in comments.
