# PSO2 RSA Injector

A "simple" POC RSA key swapper for PSO2 (tested only on global). This project is a heavily modified version of [cyberkitsune's "PSO2KeyTools"](https://github.com/cyberkitsune/PSO2Proxy/tree/5355aea6edb5342a439642c892369443246c4644/tools).

## Building

Using MSVC toolchain:
```
cl /LD /O2 /DEBUG:NONE dllmain.c /LD User32.lib /Fecryptbase.dll
cl /LD /O2 /DEBUG:NONE detour.c
```

Using mingw:
```
x86_64-w64-mingw32-gcc -shared -O2 -s -o cryptbase.dll dllmain.c
x86_64-w64-mingw32-gcc -shared -O2 -s -o detour.dll detour.c
```

## Usage

1) Copy `cryptbase.dll` and `detour.dll` to `pso2_bin` folder.
2) Generate a [key pair](https://github.com/cyberkitsune/PSO2Proxy#your-private--public-keypair).
3) Copy your `publickey.blob` to `pso2_bin` and game root folders.

## Notes

 - `dllmain`'s code uses functions that are considered dangerous to call from within `dllmain` (e.g., calling `LoadLibrary`, using `memcpy`).
 - Code is generally lacking in comments.