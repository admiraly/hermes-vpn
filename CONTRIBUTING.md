# Contributing to Hermes

Thanks for your interest! Bug reports, test results from real networks
(see [TEST-RUN.md](TEST-RUN.md)) and pull requests are all welcome.

## Licensing of contributions

Hermes is published under the
[PolyForm Noncommercial License 1.0.0](LICENSE.md), and its copyright
holder (admiraly) also offers it under separate commercial licenses. For
that to stay possible, every contribution has to be licensable both ways.

By submitting a contribution (a pull request, patch, or any other code,
documentation or asset) you agree that:

1. You wrote it yourself, or otherwise have the right to submit it under
   these terms.
2. You grant admiraly a perpetual, worldwide, non-exclusive, royalty-free,
   irrevocable license to use, modify, sublicense and distribute your
   contribution under any terms, including the PolyForm Noncommercial
   License and commercial licenses.
3. You keep the copyright in your contribution, and you're free to use it
   elsewhere however you like.

If you can't agree to this (for example, your employer owns your work),
please open an issue to discuss before sending code.

## Development

See [BUILDING.md](BUILDING.md). Before sending a pull request:

```sh
cargo fmt --all
RUSTFLAGS="-D warnings" cargo test --workspace --exclude hermes-ui
(cd hermes-ui && npm run build)
sudo scripts/netns-smoke.sh relayed   # Linux; also p2p, fallback, restart
```
