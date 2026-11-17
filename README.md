# interactor-mixer-auth-guest

The player's side of the Mixer relay's door, as one sandbox guest ELF: make a P-256 key, take its thumbprint, sign the
relay's nonce. Godot, Blender and the browser load the same ELF, so no client has its own signing code.

`src/mixer_auth.c` is plain C over mbedTLS with no I/O. `tests/native_test.c` checks it against RFC 6979 known answers.

## Build

```
PATH=/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:$PATH \
cmake -S . -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE=<repository-riscv64-sysroot>/toolchain.cmake \
      -DSANDBOX_API=<contract-guest-runtime>/vendor/sandbox-api/cmake
cmake --build build        # writes mixer_auth.elf
```

mbedTLS 3.6.4 is fetched by hash at configure time. The host calls `auth_init`, `auth_keygen`, `auth_thumbprint` and
`auth_sign` by name through `Sandbox.vmcall`; the host keeps the private key.

## Checked

`tests/native_test.c` (19 checks, RFC 6979 known answers) passes against mbedTLS 3.6. The ELF runs in the Godot
sandbox and its signature verifies with Python's `cryptography` for the signed room and fails for another room or a
flipped byte.

## Licence

MIT. See [LICENSE](LICENSE).
