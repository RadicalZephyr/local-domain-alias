use std::{
    fmt,
    fs::OpenOptions,
    io::{self, prelude::*},
    net::IpAddr,
};

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alphanumeric1, digit1, hex_digit1, space1},
    combinator::{map_res, opt, recognize, rest},
    error::{make_error, ErrorKind, ParseError, VerboseError},
    multi::{many_m_n, separated_list},
    sequence::{preceded, tuple},
    Err, IResult,
};

use structopt::StructOpt;

static HOSTS_FILE: &str = "hosts";

#[derive(Debug, StructOpt)]
#[structopt(name = "local-domain-alias")]
struct Options {
    #[structopt(name = "port")]
    port: u16,

    #[structopt(name = "alias")]
    alias: String,
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
    let (input, hostname) = alphanumeric1(input)?;
    if let Some(first_char) = hostname.chars().nth(0) {
        if !first_char.is_alphabetic() {
            return Err(Err::Error(make_error(&hostname[0..1], ErrorKind::Alpha)));
        }
    }
    Ok((input, hostname))
}

fn aliases<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Vec<String>, E> {
    let (input, _) = space1(input)?;
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

impl fmt::Display for HostsLine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let HostsLine {
            ip,
            canonical_hostname,
            aliases,
            comment,
        } = self;
        let aliases = aliases.join(" ");
        let ret = write! {
            f, "{ip} {ch} {aliases}",
            ip = ip,
            ch = canonical_hostname,
            aliases = aliases,
        }?;

        if let Some(comment) = comment {
            write!(f, "#{}", comment)
        } else {
            Ok(ret)
        }
    }
}

fn hosts_line<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, HostsLine, E> {
    let (input, ip) = ip_addr(input)?;
    let (input, _) = space1(input)?;
    let (input, canonical_hostname) = hostname(input)?;
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

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Line::Unstructured(line) => write!(f, "{}", line),
            Line::Structured(hosts_line) => write!(f, "{}", hosts_line),
        }
    }
}

fn parse_line(line: &str) -> Line {
    match hosts_line::<VerboseError<&str>>(&line) {
        Ok((_, hosts_line)) => Line::Structured(hosts_line),
        Err(_error) => Line::Unstructured(String::from(line)),
        // Err::Error(_) | Err::Failure(_) => Line::Unstructured(String::from(line)),
    }
}

fn run() -> io::Result<()> {
    let options = Options::from_args();
    let mut file = OpenOptions::new().read(true).write(true).open(HOSTS_FILE)?;
    file.seek(io::SeekFrom::Start(0))?;
    let reader = io::BufReader::new(file);

    let lines: Vec<_> = reader
        .lines()
        .map(|line_res| line_res.map(|line| parse_line(&line)))
        .collect::<Result<Vec<_>, io::Error>>()?;
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    }
}
