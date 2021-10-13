# b2-client - Backend-agnostic Backblaze B2 API Client

b2-client provides a Rust API to B2 services, backed by any HTTP client (though
see [Known Issues](#known-issues).

Support for [Hyper](https://crates.io/crates/hyper),
[Isahc](https://crates.io/crates/isahc) (soon), and
[Surf](https://crates.io/crates/surf) are implemented out of the box.

The official repository for b2-client is on SourceHut at
[https://git.sr.ht/~rjframe/b2-client](https://git.sr.ht/~rjframe/b2-client),
with a mirror at Github on
[https://github.com/rjframe/b2-client](https://github.com/rjframe/b2-client).
Patches/pull requests from both are accepted; all other activity takes place at
SourceHut.

* Issues:
  [https://todo.sr.ht/~rjframe/b2-client](https://todo.sr.ht/~rjframe/b2-client)
* Discussions:
  [https://lists.sr.ht/~rjframe/public](https://lists.sr.ht/~rjframe/public)


## Table of Contents

* [Introduction](#introduction)
    * [License](#license)
* [Getting Started](#getting-started)
    * [Install](#installation)
    * [Testing](#testing)
    * [Known Issues](#known-issues)
* [Contributing](#contributing)
* [Contact](#contact)
* [Related Projects](#related-projects)


## Introduction

I wanted a type-safe, backend-agnostic interface to the B2 API; I don't want to
potentially end up with two HTTP clients linked into my applications, and I
don't want the B2 library I need to be determined by the HTTP client (or async
runtime) I happen to be using.

I intend to support the full API.


## License

All source code is licensed under the terms of the
[MPL 2.0 license](LICENSE.txt).


## Getting Started

### Installation

I will not be registering b2-client on crates.io until I've implemented enough
to be useful. To use this library now, you'll need to clone the git repository
and add it as a path-based dependency.

```toml
[dependencies]
b2-client = { path = "../b2-client" }
```

If using a pre-packaged HTTP client, choose the backend via the `with_*name*`
feature. Supported features are

* `with_surf`
* `with_hyper`
* `with_isahc` (soon)

For alternative backends, once supported, implement the `HttpClient` trait.


### Testing

Tests currently only work with surf:

```
cargo test --features=with_surf
```


### Known Issues

* Error types are currently tied to the error types of the implemented HTTP
  clients, so arbitrary HTTP clients are not yet supported.


## Contributing

Patches and pull requests are welcome. For major features or breaking changes,
please open a ticket or start a discussion first so we can discuss what you
would like to do.

See [CONTRIBUTING.md](CONTRIBUTING.md) for pointers on getting set up. If you'd
like guidance on anything feel free to ask in a discussion or ticket, or submit
a draft PR.


## Contact

- Email: code@ryanjframe.com
- Website: [www.ryanjframe.com](https://www.ryanjframe.com)
- diaspora*: rjframe@diasp.org


## Related Projects

* [backblaze-b2](https://crates.io/crates/backblaze-b2): Built on Hyper
* [raze](https://crates.io/crates/raze): Built on reqwest
