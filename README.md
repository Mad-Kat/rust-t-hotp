# rust-t-hotp

First rust project to learn some rust and to implement a small utility library.

This implements totp described by [RFC-6238](https://tools.ietf.org/html/rfc6238) and
 htop described by [RFC-4226](https://tools.ietf.org/html/rfc4226).

## Building

To build the wasm execute the following:

```shell
wasm-pack build --target bundler
```

## Testing

To test the wasm execute the following:

```shell
wasm-pack test --node
```
