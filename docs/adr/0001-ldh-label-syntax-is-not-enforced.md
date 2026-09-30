# LDH label syntax is not enforced

RFC 1035 §2.3.1's "preferred name syntax" is advice to whoever chooses a
hostname, not a rule about what the protocol carries; RFC 2181 §11 says "any
binary string whatever can be used as the label of any resource record".
Enforcing LDH would refuse `_dmarc`, every `_tcp` SRV owner, DNS-SD instance
names and `*` itself, so only §2.3.4's lengths are enforced.

## Considered Options

A `TODO` asking for LDH enforcement was deleted rather than done: doing it was
the defect (`TODO.md` #15).
