# Security policy

This project is built around a threat model: the agent reads a hostile network and must never
leak its key. We take reports seriously and we would rather hear about a weakness than have it
found in the wild.

## Reporting a vulnerability

Please report privately, not in a public issue. Use GitHub's private vulnerability reporting on
this repository (the **Security** tab, "Report a vulnerability"). Tell us what you found, how to
reproduce it, and what an attacker could do with it. We will confirm we received it and keep you
posted as we work through it.

Please give us a reasonable window to fix an issue before disclosing it publicly.

## Scope

The security-relevant surface is the trust boundary between the parts:

- the **gateway** isolate, which holds the identity key and signs;
- the **agent** isolate, which reads untrusted input and must hold nothing;
- the **shared** wire contract that both sides derive from;
- the **dashboard**, which holds the owner key on the user's machine.

Anything that lets untrusted input reach the key, cross an isolate boundary, or get an action
signed that the owner did not grant is in scope and worth reporting.
