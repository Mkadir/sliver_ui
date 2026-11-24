# Authorized use

**Sliver UI** is a graphical operator console for [Sliver](https://github.com/BishopFox/sliver), an open-source adversary-simulation / command-and-control (C2) framework used in **authorized** security assessments.

## Intended audience

- Red team operators
- Penetration testers
- Purple team / detection engineers validating controls
- Researchers studying C2 UX and defensive visibility

## Requirements

You may use this software only when **all** of the following are true:

1. You have **explicit written authorization** to operate against the target systems (rules of engagement, contract, bug-bounty scope, or your own lab).
2. You comply with applicable law in your jurisdiction.
3. You do **not** use the software to attack systems you do not own or are not authorized to test.

## What this project is not

- It is **not** a “FUD” or “undetectable malware” product.
- Compile-time obfuscation, unique hashes, and host-side loaders change **some** static indicators; they do **not** guarantee evasion of antivirus, EDR, or human review.
- The maintainers do not provide support for unauthorized or criminal use.

## Responsible disclosure

If you find a vulnerability in Sliver UI itself (the console, not a target you are testing), please open a private security advisory or contact the maintainers through GitHub.

## License

See [LICENSE](./LICENSE).
