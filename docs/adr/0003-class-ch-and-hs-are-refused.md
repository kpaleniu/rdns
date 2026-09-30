# Class CH and HS are refused rather than served

RFC 1034 §4.3.2 step 1 searches the zones of the question's class, and holding
none in a class is the same as holding no zone: a non-IN question is REFUSED,
and the zone parser refuses a non-IN record.

## Consequences

`version.bind CH TXT`, which BIND, NSD and Knot all answer, is not answered.
Serving it would need a second class in the zone index, which `TODO.md` #13d
made unrepresentable.
