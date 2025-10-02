//! # Outlook's Autodiscover
//!
//! This module implements autoconfiguration via POX (Plain Old XML) interface to Autodiscover
//! Service. Newer SOAP interface, introduced in Exchange 2010, is not used.

use std::io::BufRead;

use quick_xml::events::Event;

use super::{Error, ServerParams};
use crate::context::Context;
use crate::log::warn;
use crate::net::read_url;
use crate::provider::{Protocol, Socket};

/// Result of parsing a single `Protocol` tag.
///
/// <https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/protocol-pox>
#[derive(Debug)]
struct ProtocolTag {
    /// Server type, such as "IMAP", "SMTP" or "POP3".
    ///
    /// <https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/type-pox>
    pub typ: String,

    /// Server identifier, hostname or IP address for IMAP and SMTP.
    ///
    /// <https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/server-pox>
    pub server: String,

    /// Network port.
    ///
    /// <https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/port-pox>
    pub port: u16,

    /// Whether connection should be secure, "on" or "off", default is "on".
    ///
    /// <https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/ssl-pox>
    pub ssl: bool,
}

enum ParsingResult {
    Protocols(Vec<ProtocolTag>),

    /// XML redirect via `RedirectUrl` tag.
    RedirectUrl(String),
}

/// Parses a single Protocol section.
fn parse_protocol<B: BufRead>(
    reader: &mut quick_xml::Reader<B>,
) -> Result<Option<ProtocolTag>, quick_xml::Error> {
    let mut protocol_type = None;
    let mut protocol_server = None;
    let mut protocol_port = None;
    let mut protocol_ssl = true;

    let mut buf = Vec::new();

    let mut current_tag: Option<String> = None;
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(ref event) => {
                current_tag = Some(
                    String::from_utf8_lossy(event.name().as_ref())
                        .trim()
                        .to_lowercase(),
                );
            }
            Event::End(ref event) => {
                let tag = String::from_utf8_lossy(event.name().as_ref())
                    .trim()
                    .to_lowercase();
                if tag == "protocol" {
                    break;
                }
                if Some(tag) == current_tag {
                    current_tag = None;
                }
            }
            Event::Text(ref e) => {
                let val = e.xml_content().unwrap_or_default();

                if let Some(ref tag) = current_tag {
                    match tag.as_str() {
                        "type" => protocol_type = Some(val.trim().to_string()),
                        "server" => protocol_server = Some(val.trim().to_string()),
                        "port" => protocol_port = Some(val.trim().parse().unwrap_or_default()),
                        "ssl" => {
                            protocol_ssl = match val.trim() {
                                "on" => true,
                                "off" => false,
                                _ => true,
                            }
                        }
                        _ => {}
                    };
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if let (Some(protocol_type), Some(protocol_server), Some(protocol_port)) =
        (protocol_type, protocol_server, protocol_port)
    {
        Ok(Some(ProtocolTag {
            typ: protocol_type,
            server: protocol_server,
            port: protocol_port,
            ssl: protocol_ssl,
        }))
    } else {
        Ok(None)
    }
}

/// Parses `RedirectUrl` tag.
fn parse_redirecturl<B: BufRead>(
    reader: &mut quick_xml::Reader<B>,
) -> Result<String, quick_xml::Error> {
    let mut buf = Vec::new();
    match reader.read_event_into(&mut buf)? {
        Event::Text(ref e) => {
            let val = e.xml_content().unwrap_or_default();
            Ok(val.trim().to_string())
        }
        _ => Ok("".to_string()),
    }
}

fn parse_xml_reader<B: BufRead>(
    reader: &mut quick_xml::Reader<B>,
) -> Result<ParsingResult, quick_xml::Error> {
    let mut protocols = Vec::new();

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(ref e) => {
                let tag = String::from_utf8_lossy(e.name().as_ref())
                    .trim()
                    .to_lowercase();

                if tag == "protocol" {
                    if let Some(protocol) = parse_protocol(reader)? {
                        protocols.push(protocol);
                    }
                } else if tag == "redirecturl" {
                    let redirecturl = parse_redirecturl(reader)?;
                    return Ok(ParsingResult::RedirectUrl(redirecturl));
                }
            }
            Event::Eof => break,
            _ => (),
        }
        buf.clear();
    }

    Ok(ParsingResult::Protocols(protocols))
}

fn parse_xml(xml_raw: &str) -> Result<ParsingResult, Error> {
    let mut reader = quick_xml::Reader::from_str(xml_raw);
    reader.config_mut().trim_text(true);

    parse_xml_reader(&mut reader).map_err(|error| Error::InvalidXml {
        position: reader.buffer_position(),
        error,
    })
}

fn protocols_to_serverparams(protocols: Vec<ProtocolTag>) -> Vec<ServerParams> {
    protocols
        .into_iter()
        .filter_map(|protocol| {
            Some(ServerParams {
                protocol: match protocol.typ.to_lowercase().as_ref() {
                    "imap" => Some(Protocol::Imap),
                    "smtp" => Some(Protocol::Smtp),
                    _ => None,
                }?,
                socket: match protocol.ssl {
                    true => Socket::Automatic,
                    false => Socket::Plain,
                },
                hostname: protocol.server,
                port: protocol.port,
                username: String::new(),
            })
        })
        .collect()
}

pub(crate) async fn outlk_autodiscover(
    context: &Context,
    mut url: String,
) -> Result<Vec<ServerParams>, Error> {
    /* Follow up to 10 xml-redirects (http-redirects are followed in read_url() */
    for _i in 0..10 {
        let xml_raw = read_url(context, &url).await?;
        let res = parse_xml(&xml_raw);
        if let Err(err) = &res {
            warn!(context, "{}", err);
        }
        match res? {
            ParsingResult::RedirectUrl(redirect_url) => url = redirect_url,
            ParsingResult::Protocols(protocols) => {
                return Ok(protocols_to_serverparams(protocols));
            }
        }
    }
    Err(Error::Redirection)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_redirect() {
        let res = parse_xml("
<?xml version=\"1.0\" encoding=\"utf-8\"?>
  <Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">
    <Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">
      <Account>
        <AccountType>email</AccountType>
        <Action>redirectUrl</Action>
        <RedirectUrl>https://mail.example.com/autodiscover/autodiscover.xml</RedirectUrl>
      </Account>
    </Response>
  </Autodiscover>
 ").expect("XML is not parsed successfully");
        if let ParsingResult::RedirectUrl(url) = res {
            assert_eq!(
                url,
                "https://mail.example.com/autodiscover/autodiscover.xml"
            );
        } else {
            panic!("redirecturl is not found");
        }
    }

    #[test]
    fn test_parse_loginparam() {
        let res = parse_xml(
            "\
<?xml version=\"1.0\" encoding=\"utf-8\"?>
<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">
  <Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>example.com</Server>
        <Port>993</Port>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>smtp.example.com</Server>
        <Port>25</Port>
        <SSL>off</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>",
        )
        .expect("XML is not parsed successfully");

        match res {
            ParsingResult::Protocols(protocols) => {
                assert_eq!(protocols[0].typ, "IMAP");
                assert_eq!(protocols[0].server, "example.com");
                assert_eq!(protocols[0].port, 993);
                assert_eq!(protocols[0].ssl, true);

                assert_eq!(protocols[1].typ, "SMTP");
                assert_eq!(protocols[1].server, "smtp.example.com");
                assert_eq!(protocols[1].port, 25);
                assert_eq!(protocols[1].ssl, false);
            }
            ParsingResult::RedirectUrl(_) => {
                panic!("RedirectUrl is not expected");
            }
        }
    }
}
