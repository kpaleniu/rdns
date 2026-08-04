//! The control channel's protocol: one line in, a status line and a body out.
//!
//! Only the protocol lives here. The commands and the accept loop are `rdnsd`'s;
//! this is what both ends have to agree on, shared so the daemon and `rdnsctl`
//! cannot drift about what a reply means (`CLAUDE.md` §7).
//!
//! A Unix socket with filesystem permissions, as `knotc`, `pdns_control` and
//! `unbound-control` use. The two that use TCP put something in front of it —
//! `rndc` an HMAC, `nsd-control` a client certificate — which is the argument
//! against bolting `reload` onto the metrics endpoint as an uncredentialed POST.
//!
//! Text, one command per connection, terminated by the close, so
//! `printf 'status\n' | socat - UNIX-CONNECT:/run/rdns/rdnsd.sock` is a working
//! client on a box with nothing else installed.
//!
//! ```text
//! -> status\n
//! <- +OK\n
//! <- zones: 2 loaded\n
//! <- ...
//! ```
//!
//! ```text
//! -> dump nosuch.test.\n
//! <- -ERR no zone "nosuch.test." is loaded\n
//! ```

/// The first line of a reply that worked.
pub const OK: &str = "+OK";

/// The first line of a reply that did not, followed by why.
pub const ERR: &str = "-ERR";

/// Longest request we will read before giving up on the sender.
///
/// A command and a zone name; a name is at most 255 bytes on the wire and more
/// than that in presentation form, so this is generous by a wide margin and
/// still bounds what one connection can make us buffer.
pub const MAX_REQUEST: usize = 4096;

/// One request: a command and its arguments, whitespace-separated.
///
/// Deliberately not a parser with quoting rules. The arguments this protocol
/// carries are zone names, and a DNS name cannot contain a space that is not
/// escaped — so a syntax for spaces would be a syntax nothing needs and one
/// more thing for the two ends to disagree about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: String,
    pub args: Vec<String>,
}

impl Request {
    /// Read one request line. An empty or blank line parses to an empty
    /// command, which the daemon answers with the usage text rather than
    /// treating as a protocol error.
    pub fn parse(line: &str) -> Request {
        let mut words = line.split_whitespace();
        Request {
            command: words.next().unwrap_or_default().to_ascii_lowercase(),
            args: words.map(str::to_string).collect(),
        }
    }

    /// The bytes a client sends, newline included.
    pub fn encode(&self) -> String {
        let mut line = self.command.clone();
        for arg in &self.args {
            line.push(' ');
            line.push_str(arg);
        }
        line.push('\n');
        line
    }
}

/// A reply as the client sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The command ran; the body is whatever it had to say, possibly empty.
    Ok(String),
    /// The command did not run, and this is why — one line, no body.
    Err(String),
}

/// A successful reply carrying `body`.
pub fn ok(body: &str) -> String {
    if body.is_empty() {
        format!("{OK}\n")
    } else if body.ends_with('\n') {
        format!("{OK}\n{body}")
    } else {
        format!("{OK}\n{body}\n")
    }
}

/// A refusal, with the reason on the status line where a client can print it
/// without having to guess how much of the body is the error.
pub fn err(why: &str) -> String {
    // Newlines in `why` would make the rest of it look like a body, so they are
    // flattened rather than trusted. The reason text comes from an io::Error or
    // a zone name often enough that "it will not contain one" is not a claim
    // worth making.
    format!("{ERR} {}\n", why.replace('\n', "; "))
}

/// What the client makes of the bytes it read.
///
/// A reply with no recognizable status line is an error rather than a body:
/// something that is not this server is on the other end of the socket, and
/// printing its output as though it were a zone would be worse than saying so.
pub fn parse_reply(text: &str) -> Reply {
    let (first, rest) = match text.split_once('\n') {
        Some((first, rest)) => (first.trim_end_matches('\r'), rest),
        None => (text.trim_end_matches('\r'), ""),
    };
    if first == OK {
        Reply::Ok(rest.to_string())
    } else if let Some(why) = first.strip_prefix(ERR) {
        Reply::Err(why.trim().to_string())
    } else {
        Reply::Err(format!(
            "unrecognized reply from the control socket: {:?}",
            first.chars().take(40).collect::<String>()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips_through_the_wire_form() {
        let request = Request {
            command: "dump".to_string(),
            args: vec!["example.com.".to_string()],
        };
        assert_eq!(request.encode(), "dump example.com.\n");
        assert_eq!(Request::parse(&request.encode()), request);
    }

    /// The command is case-folded and the arguments are not: a zone name's case
    /// is not ours to change, and `Status` is the same command as `status`.
    #[test]
    fn the_command_folds_but_its_arguments_do_not() {
        let request = Request::parse("DUMP Example.COM.\n");
        assert_eq!(request.command, "dump");
        assert_eq!(request.args, ["Example.COM."]);
    }

    #[test]
    fn a_blank_line_is_an_empty_command_rather_than_an_error() {
        assert_eq!(Request::parse("   \r\n").command, "");
        assert!(Request::parse("").args.is_empty());
    }

    #[test]
    fn a_reply_round_trips() {
        assert_eq!(
            parse_reply(&ok("zones: 2\n")),
            Reply::Ok("zones: 2\n".to_string())
        );
        assert_eq!(parse_reply(&ok("")), Reply::Ok(String::new()));
        assert_eq!(
            parse_reply(&err("no such zone")),
            Reply::Err("no such zone".to_string())
        );
    }

    /// The body is handed back whole, including a trailing newline the daemon
    /// added, because a zone dump is compared byte for byte by whoever asked
    /// for it.
    #[test]
    fn a_body_without_a_trailing_newline_gets_one_and_keeps_its_shape() {
        assert_eq!(ok("one line"), "+OK\none line\n");
        assert_eq!(ok("two\nlines\n"), "+OK\ntwo\nlines\n");
    }

    /// A multi-line reason would put the rest of itself where a body goes, and
    /// the client would print half an error as though it were output.
    #[test]
    fn a_reason_with_a_newline_in_it_stays_on_one_line() {
        let reply = err("could not open the file\nbecause it is not there");
        assert_eq!(reply.lines().count(), 1);
        assert_eq!(
            parse_reply(&reply),
            Reply::Err("could not open the file; because it is not there".to_string())
        );
    }

    /// Somebody else's daemon, or a text file, on the other end of the path.
    #[test]
    fn a_reply_that_is_not_ours_is_an_error_and_not_a_body() {
        assert!(matches!(
            parse_reply("HTTP/1.1 200 OK\r\n\r\n"),
            Reply::Err(_)
        ));
        assert!(matches!(parse_reply(""), Reply::Err(_)));
    }
}
