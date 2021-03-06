# B2-client - Backend-agnostic Backblaze B2 API Client

B2-client provides a Rust API to Backblaze B2 cloud storage service, backed by
any async HTTP client utilizing any async runtime.

Support for [Hyper](https://crates.io/crates/hyper),
[Isahc](https://crates.io/crates/isahc), and
[Surf](https://crates.io/crates/surf) are implemented out of the box.

The official repository for B2-client is on SourceHut at
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

B2-client is an async runtime-agnostic, HTTP client-agnostic interface to the
Backblaze B2 API. The full B2 API is supported.

Note that most of these functions can incur charges to your account.


## License

All library source code is licensed under the terms of the
[MPL 2.0 license](LICENSE.txt).

The source code of examples is licensed under the terms of the
[MIT license](examples/LICENSE.txt).


## Getting Started

### Installation

To use a pre-packaged HTTP client, choose the backend via the relevant feature.
Supported features are:

* `with_hyper`
* `with_surf`
* `with_isahc`

This list will eventually use the lower-level client libraries instead (e.g., h1
instead of hyper).

Add b2-client as a dependency via cargo; for example, to use the
[Surf](https://crates.io/crates/surf) HTTP client:

```shell
cargo add b2-client --features with_surf
```

There is no default client, so you must choose one of the above features or use
a custom HTTP client. To use your own HTTP backend, simply implement the
`HttpClient` trait then pass the struct to `account::authorize_account`.


### Testing

API calls are faked via pre-recorded sessions using the surf backend, so to run
all tests run `cargo test --features=with_surf`. No test runs against the live
B2 service by default.

To run a test against the live B2 API, set the environment variables
`B2_CLIENT_TEST_KEY` and `B2_CLIENT_TEST_KEY_ID` to a key/id pair capable of
performing the task you wish to test, and change the test's `VcrMode` to
`Record`. Although there will be no major-destructive tests (like deleting all
buckets), don't run a test against the live API unless you know what it's doing,
especially if you have production keys or buckets on your account.

A few tests will need minor modifications or setup to run against the B2 API
(e.g., deleting a bucket, changing the bucket ID), and a few tests will not pass
their pre-recorded sessions if the environment variables are set.


### Known Issues

* Error handling is bifurcated a bit; for example, uploading a file without the
  `WriteFiles` capability will return `Error::Unauthorized`, but uploading to a
  private bucket without the `ReadFiles` capabillity returns `Error::B2Error`.

  This is due to the fact that we can validate authorization to write prior to
  making the API call, but cannot pre-validate the authorization to read. This
  is solveable; it just requires determining the best method to merge them.


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

* [b2_backblaze](https://crates.io/crates/b2_backblaze): Uses reqwest
* [raze](https://crates.io/crates/raze): Uses reqwest
* [backblaze-b2](https://crates.io/crates/backblaze-b2): Uses Hyper. Probably
  unmaintained
