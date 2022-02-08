# B2-client examples

Running the examples in this directory will incur charges to your account.

The files in the `examples` directory are licensed under the MIT license.


## Upload and download files

Uploads the text "abcd" to a bucket then immediately downloads it.

You need to specify an application key and key ID in the environment variables
`B2_CLIENT_KEY` and `B2_CLIENT_KEY`, respectively, and provide a bucket ID on
the command-line. For example:

```sh
B2_CLIENT_KEY=<key> B2_CLIENT_KEY_ID=<key-id> cargo run --features=with_hyper \
    -- <bucket ID>
```

This example can be an easy and effective test for your custom HTTP client;
every method of HttpClient's API is executed except for `head`,
`read_body_from_file`, and `user_agent`.
