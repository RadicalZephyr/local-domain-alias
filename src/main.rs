use std::{
    collections::HashSet,
    fmt,
    fs::{File, OpenOptions},
    io::{self, prelude::*, BufRead, Cursor},
    net::{IpAddr, Ipv4Addr},
    process::Command,
};

use failure::Fail;

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alpha1, alphanumeric1, digit1, hex_digit1, one_of, space1},
    combinator::{all_consuming, map_res, opt, recognize, rest},
    error::{convert_error, ErrorKind, ParseError, VerboseError},
    multi::{many0, many_m_n, separated_list},
    sequence::{preceded, tuple},
    Err, IResult,
};

use structopt::StructOpt;

static HOSTS_FILE: &str = "/etc/hosts";

#[derive(Debug, StructOpt)]
#[structopt(name = "local-domain-alias")]
struct Options {
    #[structopt(name = "port")]
    port: u16,

    #[structopt(name = "alias")]
    alias: String,
}

#[derive(Debug, Fail)]
enum Error {
    #[fail(display = "alias is already in use")]
    AliasAlreadyInUse,

    #[fail(display = "incomplete alias")]
    IncompleteAlias,

    #[fail(display = "invalid alias format\n{}", _0)]
    InvalidAliasFormat(String),

    #[fail(display = "could not set up port forwarding: ip tables error {}", _0)]
    IptablesCommandFailed(i32),

    #[fail(display = "must be run as root")]
    MustRunAsRoot,

    #[fail(display = "io error: {}", _0)]
    IoError(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        match error.kind() {
            io::ErrorKind::PermissionDenied => Error::MustRunAsRoot,
            _e => Error::IoError(dbg!(error)),
        }
    }
}

fn octet<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u8, E> {
    map_res(digit1, |s: &str| s.parse::<u8>())(input)
}

fn dotted_octet<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u8, E> {
    preceded(tag("."), octet)(input)
}

fn ip_v4_addr<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    recognize(tuple((octet, dotted_octet, dotted_octet, dotted_octet)))(input)
}

fn hextet<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u16, E> {
    map_res(hex_digit1, |s: &str| s.parse::<u16>())(input)
}

fn sep_hextet<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, u16, E> {
    preceded(tag("::"), hextet)(input)
}

fn ip_v6_addr<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    let parser = preceded(opt(hextet), many_m_n(1, 7, sep_hextet));
    recognize(parser)(input)
}

fn ip_addr<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, IpAddr, E> {
    map_res(alt((ip_v4_addr, ip_v6_addr)), |s: &str| s.parse::<IpAddr>())(input)
}

fn hostname<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    recognize(tuple((
        alpha1,
        many0(alt((alphanumeric1, recognize(one_of("-."))))),
    )))(input)
}

fn check_hostname<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, (), E> {
    all_consuming(hostname)(input).map(|(input, _)| (input, ()))
}

fn aliases<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Vec<String>, E> {
    let (input, aliases) = separated_list(tag(" "), hostname)(input)?;
    Ok((input, aliases.into_iter().map(String::from).collect()))
}

fn comment<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
    preceded(tag("#"), rest)(input)
}

#[derive(Debug)]
struct HostsLine {
    ip: IpAddr,
    canonical_hostname: String,
    aliases: Vec<String>,
    comment: Option<String>,
}

impl HostsLine {
    fn new(ip: IpAddr, canonical_hostname: String) -> HostsLine {
        let aliases = Vec::new();
        let comment = None;
        HostsLine {
            ip,
            canonical_hostname,
            aliases,
            comment,
        }
    }
}

impl fmt::Display for HostsLine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let HostsLine {
            ip,
            canonical_hostname,
            aliases,
            comment,
        } = self;

        let sep = match ip.to_string().chars().count() {
            0..=8 => "\t\t",
            7..=16 => "\t",
            _ => " ",
        };

        write!(
            f,
            "{ip}{sep}{ch}",
            ip = ip,
            sep = sep,
            ch = canonical_hostname,
        )?;

        if !aliases.is_empty() {
            write!(f, "\t{}", aliases.join(" "))?;
        }

        if let Some(comment) = comment {
            write!(f, "#{}", comment)?;
        }
        Ok(())
    }
}

fn hosts_line<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, HostsLine, E> {
    let (input, ip) = ip_addr(input)?;
    let (input, _) = space1(input)?;
    let (input, canonical_hostname) = hostname(input)?;
    let (input, _) = space1(input)?;
    let (input, aliases) = opt(aliases)(input)?;
    let (input, comment) = opt(comment)(input)?;

    let canonical_hostname = String::from(canonical_hostname);
    let aliases = aliases.unwrap_or_else(Vec::new);
    let comment = comment.map(String::from);
    Ok((
        input,
        HostsLine {
            ip,
            canonical_hostname,
            aliases,
            comment,
        },
    ))
}

#[derive(Debug)]
enum Line {
    Unstructured(String),
    Structured(HostsLine),
}

impl Line {
    fn structured(ip: IpAddr, canonical_name: String) -> Line {
        Line::Structured(HostsLine::new(ip, canonical_name))
    }

    fn structured_ref(&self) -> Option<&HostsLine> {
        match self {
            Line::Structured(line) => Some(line),
            Line::Unstructured(_) => None,
        }
    }
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Line::Unstructured(line) => write!(f, "{}", line),
            Line::Structured(hosts_line) => write!(f, "{}", hosts_line),
        }
    }
}

fn parse_line(line: &str) -> Line {
    match hosts_line::<(&str, ErrorKind)>(&line) {
        Ok((_, hosts_line)) => Line::Structured(hosts_line),
        Err(_error) => Line::Unstructured(String::from(line)),
    }
}

fn validate_alias(alias: &str) -> Result<(), Error> {
    check_hostname::<VerboseError<&str>>(alias)
        .map(|_| ())
        .map_err(|error| match error {
            Err::Incomplete(_) => Error::IncompleteAlias,
            Err::Error(e) | Err::Failure(e) => Error::InvalidAliasFormat(convert_error(alias, e)),
        })
}

fn iptables_rules_exist(options: &Options) -> Result<bool, Error> {
    let rule_match = format!(
        "-A OUTPUT -s 127.0.0.1/32 -d {alias}/32 -p tcp -m tcp --dport 80 -j DNAT --to-destination 127.0.0.1:",
        alias = options.alias,
    );
    let output = Command::new("iptables")
        .args(&["-t", "nat", "-S", "OUTPUT"])
        .output()?;
    let stdout = Cursor::new(output.stdout);
    let matched_lines: Vec<_> = stdout
        .lines()
        .filter_map(|line_ret| {
            line_ret.ok().and_then(|line| {
                let line: String = line;
                line.rfind(&rule_match).map(|index| (index, line))
            })
        })
        .collect();
    let port = format!("{}", options.port);
    if let Some((idx, line)) = matched_lines.first() {
        if line[*idx..] == port {
            return Ok(true);
        } else {
            return Err(Error::AliasAlreadyInUse);
        }
    }
    Ok(false)
}

fn write_iptables_rules(options: &Options) -> Result<(), Error> {
    let status = Command::new("iptables")
        .args(&[
            "-t",
            "nat",
            "--append",
            "OUTPUT",
            "--protocol",
            "tcp",
            "--dport",
            "80",
            "--source",
            "127.0.0.1",
            "--destination",
            &options.alias,
            "--jump",
            "DNAT",
            "--to-destination",
            &format!("127.0.0.1:{}", options.port),
        ])
        .status()?;
    if !status.success() {
        return Err(Error::IptablesCommandFailed(status.code().unwrap_or(-1)));
    }

    Ok(())
}

fn next_unused_local_ip(in_use_ips: &HashSet<IpAddr>) -> IpAddr {
    for b in 0..128 {
        for c in 0..128 {
            for d in 1..128 {
                let ip = IpAddr::V4(Ipv4Addr::new(127, b, c, d));
                if !in_use_ips.contains(&ip) {
                    return ip;
                }
            }
        }
    }
    "127.0.0.1".parse().unwrap()
}

fn run() -> Result<(), Error> {
    let options = Options::from_args();
    validate_alias(&options.alias)?;

    let mut file = File::open(HOSTS_FILE)?;
    file.seek(io::SeekFrom::Start(0))?;
    let reader = io::BufReader::new(file);

    let mut lines: Vec<_> = reader
        .lines()
        .map(|line_res| line_res.map(|line| parse_line(&line)))
        .collect::<Result<Vec<_>, io::Error>>()?;

    let mut file = OpenOptions::new().write(true).open(HOSTS_FILE)?;
    file.seek(io::SeekFrom::Start(0))?;

    let structured_refs: Vec<_> = lines
        .iter()
        .filter_map(|line| line.structured_ref())
        .collect();
    if structured_refs
        .iter()
        .find(|&x| *x.canonical_hostname == options.alias)
        .is_none()
    {
        let in_use_ips: HashSet<IpAddr> = structured_refs.iter().map(|line| line.ip).collect();
        let ip = next_unused_local_ip(&in_use_ips);
        lines.push(Line::structured(ip, options.alias.clone()));
    } else {
        eprintln!("Alias already in /etc/hosts not adding a second entry");
    }

    for line in &lines {
        writeln!(file, "{}", line)?;
    }
    file.sync_all()?;
    drop(file);

    if !iptables_rules_exist(&options)? {
        write_iptables_rules(&options)?;
    }

    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(err) => {
            eprintln!("local-domain-alias: {}", err);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_parse_err {
        { $fn_name:ident($input:literal), rest == $expected_rest:literal } => {
            match $fn_name::<VerboseError<&str>>($input) {
                Ok((rest, value)) => {
                    assert_eq!($expected_rest, rest, "actual unparsed input");
                    panic!("parse unexpectedly succeeded: {ifn}({iarg}) rest: '{rest}', value: '{value:?}'",
                               ifn = stringify!($fn_name),
                               iarg = stringify!($input),
                               rest = rest,
                               value = value,
                    );
                }
                Err(err) => err,
            }
        }
    }

    macro_rules! assert_parse_ok {
        { $fn_name:ident($input:literal) } => {
            match $fn_name::<VerboseError<&str>>($input) {
                Err(Err::Incomplete(i)) =>
                    panic!("incomplete input: '{}' {:?}", $input, i),
                Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                    panic!("failed to parse: {ifn}({iarg})\n{converted}",
                           ifn = stringify!($fn_name),
                           iarg = stringify!($input),
                           converted = convert_error($input, e));
                },
                Ok(ret) => ret,
            }
        }
    }

    #[test]
    fn parse_hostname() {
        assert_parse_err!(hostname("123"), rest == "");
        assert_parse_ok!(hostname("a123"));
        assert_parse_ok!(hostname("abc"));
        assert_parse_ok!(hostname("abc.def"));
        assert_parse_ok!(hostname("abc-def"));
        assert_parse_ok!(hostname("abc-def.ghi"));
    }

    #[test]
    fn parse_check_hostname() {
        assert_parse_err!(check_hostname("123"), rest == "");
        assert_parse_ok!(check_hostname("a123"));
        assert_parse_ok!(check_hostname("abc"));
        assert_parse_ok!(check_hostname("abc-def"));
        assert_parse_ok!(hostname("abc.def"));
        assert_parse_ok!(hostname("abc-def.ghi"));
    }

    #[test]
    fn parse_aliases() {
        assert_parse_ok!(aliases("123"));
        assert_parse_ok!(aliases("a123"));
        assert_parse_ok!(aliases("abc"));
    }

    #[test]
    fn parse_comment() {
        assert_parse_err!(comment("123"), rest == "123");
        assert_parse_err!(comment(""), rest == "");
        assert_parse_ok!(comment("#"));
        assert_parse_ok!(comment("#abc 123 !@# {}()[]"));
        assert_parse_ok!(comment("#abc123!@#\nfoobar"));
    }
}
