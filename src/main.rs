use std::{
    error::Error,
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
    error::{convert_error, make_error, ErrorKind, ParseError, VerboseError},
    multi::{many_m_n, separated_list},
    sequence::{preceded, tuple},
    Err, IResult,
};

use structopt::StructOpt;

static HOSTS_FILE: &str = "hosts";

#[derive(Debug)]
struct NomError {
    error_trace: String,
}

impl NomError {
    fn new(error_trace: String) -> NomError {
        NomError { error_trace }
    }
}

impl fmt::Display for NomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "parsing error: {}", self.error_trace)
    }
}

impl Error for NomError {
    fn description(&self) -> &str {
        "NomError"
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "local-domain-alias")]
struct Options {
    #[structopt(name = "port")]
    port: u16,

    #[structopt(name = "alias")]
    alias: String,
}

#[derive(Debug)]
struct Line {
    ip: IpAddr,
    canonical_hostname: String,
    aliases: Vec<String>,
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

fn comment<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, (), E> {
    let (input, _) = preceded(tag("#"), rest)(input)?;
    Ok((input, ()))
}

fn hosts_line<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, Line, E> {
    let (input, ip) = ip_addr(input)?;
    let (input, _) = space1(input)?;
    let (input, canonical_hostname) = hostname(input)?;
    let (input, aliases) = opt(aliases)(input)?;
    let (input, _) = opt(comment)(input)?;

    let canonical_hostname = String::from(canonical_hostname);
    let aliases = aliases.unwrap_or_else(Vec::new);
    Ok((
        input,
        Line {
            ip,
            canonical_hostname,
            aliases,
        },
    ))
}

fn parse_line(line: &str) -> io::Result<Line> {
    let (_, line) = hosts_line::<VerboseError<&str>>(&line).map_err(|e| match e {
        Err::Incomplete(_) => io::Error::from(io::ErrorKind::NotFound),
        Err::Error(e) | Err::Failure(e) => io::Error::new(
            io::ErrorKind::NotFound,
            NomError::new(convert_error(&line, e)),
        ),
    })?;

    Ok(line)
}

fn run() -> io::Result<()> {
    let options = Options::from_args();
    let mut file = OpenOptions::new().read(true).write(true).open(HOSTS_FILE)?;
    file.seek(io::SeekFrom::Start(0))?;
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line: String = line?;
        match parse_line(&line) {
            Ok(host_line) => {
                dbg!(&host_line);
            }
            Err(e) => println!("error parsing line: '{}'\n{}", line, e),
        }
    }
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
