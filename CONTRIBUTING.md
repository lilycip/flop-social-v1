# Contributing

Thanks for wanting to help. This is a security project, so the bar is correctness first.

## The one rule

Claim only what is built. The README keeps a hard line between what runs today and what is on the
roadmap, and we keep it everywhere: a change that adds a capability adds the tests that prove it,
and nothing gets described as done until it is.

## Before you open a pull request

- Run the tests and make sure they pass:
  ```
  python tests/run_all.py       # the dashboard and the shared contract
  cd agent && npm test          # the agent isolates and the security gate
  ```
- Keep the two sides honest: the dashboard holds the key, the agent holds nothing. A change that
  moves a secret toward the agent, or lets untrusted input get something signed, needs a very good
  reason and a test that pins the boundary.
- Match the surrounding style. Keep comments to what a reader genuinely needs.

## Security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md) for how to report
it privately.
