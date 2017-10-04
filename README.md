# OCaml bindings to C stubs for Poly1305

This exposes the Poly1305 one-time MAC algorithm.

The C code was lifted from WireGuard and adopted by my inexperienced hands, using [abeaumont's salsa20 bindings](https://github.com/abeaumont/salsa20-core) as a template.

## You don't want to use this

There's no error handling, no input validation, and the C code is probably not very portable either. Don't use this is in production.

## Installation

```
opam pin add poly1305 --dev -k git https://github.com/cfcs/ocaml-poly1305
```

## License

I do not have a law degree, so I do not know anything about licensing.
The main body of code in this repository comes from WireGuard, and the licensing from there applies.
