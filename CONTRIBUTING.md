# Contributing to b2-client

This is mostly a set of guidelines, not fixed rules. They are also changeable --
if you have questions or think something can be improved please submit an
issue/PR or start a discussion.


## Table of Contents

* [Quick Reference to Websites](#quick-reference)
* [How Can I Contribute?](#how-can-i-contribute)
* [PR Checklist](#pr-checklist)
* [Style Guidelines](#style-guidelines)
    * [Commit and PR Style](#commit-and-pr-style)
    * [Code Style](#code-style)


## Quick Reference

* Source code repositories:
    * [https://git.sr.ht/~rjframe/b2-client](https://git.sr.ht/~rjframe/b2-client/)
    * [https://github.com/rjframe/b2-client](https://github.com/rjframe/b2-client/)
* Issue tracker:
  [https://todo.sr.ht/~rjframe/b2-client](https://todo.sr.ht/~rjframe/b2-client/)
* Mailing List:
  [https://lists.sr.ht/~rjframe/public](https://lists.sr.ht/~rjframe/public)


## How Can I Contribute?

* [Create tickets](https://todo.sr.ht/~rjframe/upim) for discovered bugs and
  ideas for improvement.
  reference material to answering questions other people have.
* Improve tests -- in particular, we should be testing against multiple HTTP
  clients.
* Help implement the B2 API.


## PR Checklist

Before submitting a PR or patchset, be sure to check that you haven't broken
various feature combinations:

* Can you build documentation with all HTTP client backends?
    - `cargo doc --no-deps --features=with_surf,with_hyper`
* Can you run tests with no default features?
    - `cargo test --no-default-features`
* Can you run tests with all HTTP client backends?
    - `cargo test --features=with_surf,with_hyper`

All new tests related to sending and receiving data from the B2 service need to
be based on real communication with the service, rather than generated solely
from their documentation; creating those tests will potentially result in
monetary charges; if you submit tests that have not been based on a real session
with B2, please let me know in the PR so that I can do so.


## Style Guidelines

## Commit and PR Style

The first line of a commit message should summarize the purpose of the commit.
It should be a full sentence but end without a period. The subject must be no
more than 72 characters, preferably no more than 50.

Write the subject in imperative style (like you're telling someone what to do);
use "Add xyz" instead of "Added xyz", "Fix" instead of "Fixed", etc.

Example commit subjects:

```
Add tests for authorize_account function
Add uniq iterator
Fix clippy warnings
```

If relevant, later paragraphs should provide context and explain anything that
may not be apparent. For example, if you made a design decision that may not be
obvious, why did you choose that over an alternative?

Answer the question "why?"; we can see "what" from the code itself. Use "Fix
typo in schedule documentation" rather than "Change schedull to schedule".

Text should be wrapped at 72 characters.

If a commit references, is related to, or fixes an issue in the tracker, list it
at the end.

A full commit message might look something like this:

```
Add a widget to the box

The box was looking empty with nothing inside it.

We could also have used a gadget, but widgets are shiny, and I like
shiny things.

This does mean we will no longer be able to fit some things inside the
box:

* contrivances will be too big
* devices might break nearby widgets
* gimmicks would no longer be relevant

Resolves: #4
```

It's best to keep commits small when possible, doing only one thing.

PRs that are only cosmetic (style) fixes will typically not be accepted since
this messes up `git blame`. Style-only commits in the code you're working with
while doing something else are fine, but the style fixes should be in a separate
commit from functional changes.


### Code Style

* Use four spaces for indentation.
* Use a hard 80 column line width.
* Write code with understandability and future maintainability in mind.
* Write tests whenever practical; exercise error conditions and edge cases as
  well as the happy path.
* Document all public declarations. Also document non-trivial private
  declarations.
* Follow the typical Rust naming conventions.
* If an import is used in one or very few places in a module, prefer a local
  import to a global one (import inside the function rather than the top of the
  file).
* In general, try to conform to the style of the code in which you're working.


#### Braces

Place opening braces on the same line as the function declaration/if
expression/etc. unless doing so would break the 80 column rule.


#### Function Definitions

If a function's return value would cross 80 columns, place the `->` on the next
line at column 1. `where` clauses should be indented four spaces, and the
opening brace should be placed on the next line on column 1.

If the parameter list will extend past 80 characters, place each parameter on
its own line, indented once. Place the closing parenthesis on the line past the
final paremeter, unindented, and with the `->` on the same line.

Examples:

```rust
fn my_function(a: u32) -> u32 {
    // ...
}

fn my_function_with_a_long_name(apple: u32, banana: &str, carrot: f32)
-> FoodFromIngredients {
    // ...
}

fn another_function<T>(food: &T) -> u32
    where T: SomeTrait,
{
    // ...
}

fn my_other_function_with_a_long_name<T>(apple: T, banana: &str, carrot: f32)
-> FoodFromIngredients
    where T: SomeTrait,
{
    // ...
}

fn another_function_that_goes_across_the_page<T>(
    apple: T,
    banana: &str,
    carrot: f32
) -> FoodFromIngredients {
    // ...
}
```
