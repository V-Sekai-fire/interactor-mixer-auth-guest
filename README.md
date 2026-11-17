# interactor-mixer-auth-guest

The player's side of the Mixer relay's door, as one sandbox guest ELF: make a P-256 key, take its thumbprint, sign the
relay's nonce. Godot, Blender and the browser load the same ELF, so no client has its own signing code.

`src/mixer_auth.c` is plain C over mbedTLS with no I/O. `tests/native_test.c` checks it against RFC 6979 known answers.

## Licence

MIT. See [LICENSE](LICENSE).
