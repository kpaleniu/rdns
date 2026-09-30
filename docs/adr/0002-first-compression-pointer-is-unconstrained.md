# The first compression pointer in a chain may point forward

RFC 1035 §4.1.4 says a pointer refers to "a prior occurance of the same name".
Every pointer after the first must land strictly before the previous target,
which makes a cycle unreachable without a visited set. The first is
unconstrained because a name is parsed from a suffix slice that does not know
its own offset; one free step does not cost termination. The reasoning and the
cost of the alternative are in `rdns-core/src/dname.rs`, `unpack_internal`.
