//! The control channel's protocol: one line in, a status line and a body out.
//!
//! Only the protocol. The commands and the accept loop are `rdnsd`'s; this is
//! what both ends must agree on, so the daemon and `rdnsctl` cannot drift.
//!
//! A Unix socket with filesystem permissions, as `knotc`, `pdns_control` and
//! `unbound-control` use — authorization by file mode, so nothing here
//! authenticates.
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
const ERR: &str = "-ERR";

/// Longest request read before giving up on the sender. A command and a zone
/// name need far less; this bounds what one connection can make us buffer.
pub const MAX_REQUEST: usize = 4096;

/// One request: a command and its arguments, whitespace-separated.
///
/// No quoting rules. The arguments are zone names, and a DNS name cannot carry
/// an unescaped space.
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
    // A newline in `why` would make the rest of it look like a body. The text
    // comes from an io::Error or a zone name, so it can contain one.
    format!("{ERR} {}\n", why.replace('\n', "; "))
}

/// What the client makes of the bytes it read.
///
/// No recognizable status line is an error, not a body: something other than
/// this server is on the socket, and printing its output as a zone is worse.
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

    /// The body is handed back whole: a zone dump is compared byte for byte.
    #[test]
    fn a_body_without_a_trailing_newline_gets_one_and_keeps_its_shape() {
        assert_eq!(ok("one line"), "+OK\none line\n");
        assert_eq!(ok("two\nlines\n"), "+OK\ntwo\nlines\n");
    }

    /// A multi-line reason would put its tail where a body goes.
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
