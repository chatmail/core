//! Variable server parameters lists

pub use crate::provider::{Protocol, Socket};

/// Set of variable parameters to try during configuration.
///
/// Can be loaded from online configuration
/// or derived from user entered parameters.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ServerParams {
    /// Protocol, such as IMAP or SMTP.
    pub protocol: Protocol,

    /// Server hostname, empty if unknown.
    pub hostname: String,

    /// Server port, zero if unknown.
    pub port: u16,

    /// Socket security, such as TLS or STARTTLS, Socket::Automatic if unknown.
    pub socket: Socket,

    /// Username, empty if unknown.
    pub username: String,
}

impl ServerParams {
    fn expand_usernames(self, addr: &str) -> Vec<ServerParams> {
        if self.username.is_empty() {
            vec![Self {
                username: addr.to_string(),
                ..self.clone()
            }]
        } else {
            vec![self]
        }
    }

    fn expand_hostnames(self, param_domain: &str) -> Vec<ServerParams> {
        if self.hostname.is_empty() {
            vec![
                // Try "imap.ex.org"/"smtp.ex.org" and "mail.ex.org" first because if a server exists
                // under this address, it's likely the correct one.
                Self {
                    hostname: match self.protocol {
                        Protocol::Imap => "imap.".to_string() + param_domain,
                        Protocol::Smtp => "smtp.".to_string() + param_domain,
                    },
                    ..self.clone()
                },
                Self {
                    hostname: "mail.".to_string() + param_domain,
                    ..self.clone()
                },
                // Try "ex.org" last because if it's wrong and the server is configured to
                // not answer at all, configuration may be stuck for several minutes.
                Self {
                    hostname: param_domain.to_string(),
                    ..self
                },
            ]
        } else {
            vec![self]
        }
    }

    fn expand_ports(mut self) -> Vec<ServerParams> {
        // Try to infer port from socket security.
        if self.port == 0 {
            self.port = match self.socket {
                Socket::Ssl => match self.protocol {
                    Protocol::Imap => 993,
                    Protocol::Smtp => 465,
                },
                Socket::Starttls | Socket::Plain => match self.protocol {
                    Protocol::Imap => 143,
                    Protocol::Smtp => 587,
                },
                Socket::Automatic => 0,
            }
        }

        if self.port == 0 {
            // Neither port nor security is set.
            //
            // Try common secure combinations.

            vec![
                // Try TLS
                Self {
                    socket: Socket::Ssl,
                    port: match self.protocol {
                        Protocol::Imap => 993,
                        Protocol::Smtp => 465,
                    },
                    ..self.clone()
                },
                // Try STARTTLS
                Self {
                    socket: Socket::Starttls,
                    port: match self.protocol {
                        Protocol::Imap => 143,
                        Protocol::Smtp => 587,
                    },
                    ..self
                },
            ]
        } else if self.socket == Socket::Automatic {
            vec![
                // Try TLS over user-provided port.
                Self {
                    socket: Socket::Ssl,
                    ..self.clone()
                },
                // Try STARTTLS over user-provided port.
                Self {
                    socket: Socket::Starttls,
                    ..self
                },
            ]
        } else {
            vec![self]
        }
    }
}

/// Expands vector of `ServerParams`, replacing placeholders with
/// variants to try.
pub(crate) fn expand_param_vector(
    v: Vec<ServerParams>,
    addr: &str,
    domain: &str,
) -> Vec<ServerParams> {
    v.into_iter()
        // The order of expansion is important.
        //
        // Ports are expanded the last, so they are changed the first.
        .flat_map(|params| params.expand_usernames(addr).into_iter())
        .flat_map(|params| params.expand_hostnames(domain).into_iter())
        .flat_map(|params| params.expand_ports().into_iter())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_param_vector() {
        let v = expand_param_vector(
            vec![ServerParams {
                protocol: Protocol::Imap,
                hostname: "example.net".to_string(),
                port: 0,
                socket: Socket::Ssl,
                username: "foobar".to_string(),
            }],
            "foobar@example.net",
            "example.net",
        );

        assert_eq!(
            v,
            vec![ServerParams {
                protocol: Protocol::Imap,
                hostname: "example.net".to_string(),
                port: 993,
                socket: Socket::Ssl,
                username: "foobar".to_string(),
            }],
        );

        let v = expand_param_vector(
            vec![ServerParams {
                protocol: Protocol::Smtp,
                hostname: "example.net".to_string(),
                port: 123,
                socket: Socket::Automatic,
                username: "foobar".to_string(),
            }],
            "foobar@example.net",
            "example.net",
        );

        assert_eq!(
            v,
            vec![
                ServerParams {
                    protocol: Protocol::Smtp,
                    hostname: "example.net".to_string(),
                    port: 123,
                    socket: Socket::Ssl,
                    username: "foobar".to_string(),
                },
                ServerParams {
                    protocol: Protocol::Smtp,
                    hostname: "example.net".to_string(),
                    port: 123,
                    socket: Socket::Starttls,
                    username: "foobar".to_string(),
                },
            ],
        );

        let v = expand_param_vector(
            vec![ServerParams {
                protocol: Protocol::Smtp,
                hostname: "example.net".to_string(),
                port: 123,
                socket: Socket::Plain,
                username: "foobar".to_string(),
            }],
            "foobar@example.net",
            "example.net",
        );
        assert_eq!(
            v,
            vec![ServerParams {
                protocol: Protocol::Smtp,
                hostname: "example.net".to_string(),
                port: 123,
                socket: Socket::Plain,
                username: "foobar".to_string(),
            }],
        );

        // Test that "example.net" is tried after "*.example.net".
        let v = expand_param_vector(
            vec![ServerParams {
                protocol: Protocol::Imap,
                hostname: "".to_string(),
                port: 10480,
                socket: Socket::Ssl,
                username: "foobar".to_string(),
            }],
            "foobar@example.net",
            "example.net",
        );
        assert_eq!(
            v,
            vec![
                ServerParams {
                    protocol: Protocol::Imap,
                    hostname: "imap.example.net".to_string(),
                    port: 10480,
                    socket: Socket::Ssl,
                    username: "foobar".to_string(),
                },
                ServerParams {
                    protocol: Protocol::Imap,
                    hostname: "mail.example.net".to_string(),
                    port: 10480,
                    socket: Socket::Ssl,
                    username: "foobar".to_string(),
                },
                ServerParams {
                    protocol: Protocol::Imap,
                    hostname: "example.net".to_string(),
                    port: 10480,
                    socket: Socket::Ssl,
                    username: "foobar".to_string(),
                }
            ],
        );

        // Test that TLS is preferred to STARTTLS
        // when the port and security are not set.
        let v = expand_param_vector(
            vec![ServerParams {
                protocol: Protocol::Smtp,
                hostname: "example.net".to_string(),
                port: 0,
                socket: Socket::Automatic,
                username: "foobar".to_string(),
            }],
            "foobar@example.net",
            "example.net",
        );
        assert_eq!(
            v,
            vec![
                ServerParams {
                    protocol: Protocol::Smtp,
                    hostname: "example.net".to_string(),
                    port: 465,
                    socket: Socket::Ssl,
                    username: "foobar".to_string(),
                },
                ServerParams {
                    protocol: Protocol::Smtp,
                    hostname: "example.net".to_string(),
                    port: 587,
                    socket: Socket::Starttls,
                    username: "foobar".to_string(),
                },
            ],
        );

        // Test that email address is used as the default username.
        // We do not try other usernames
        // such as the local part of the address
        // as this is very uncommon configuration
        // and not worth doubling the number of candidates to try.
        // If such configuration is used, email provider
        // should provide XML autoconfig.
        let v = expand_param_vector(
            vec![ServerParams {
                protocol: Protocol::Imap,
                hostname: "example.net".to_string(),
                port: 0,
                socket: Socket::Automatic,
                username: "".to_string(),
            }],
            "foobar@example.net",
            "example.net",
        );
        assert_eq!(
            v,
            vec![
                ServerParams {
                    protocol: Protocol::Imap,
                    hostname: "example.net".to_string(),
                    port: 993,
                    socket: Socket::Ssl,
                    username: "foobar@example.net".to_string(),
                },
                ServerParams {
                    protocol: Protocol::Imap,
                    hostname: "example.net".to_string(),
                    port: 143,
                    socket: Socket::Starttls,
                    username: "foobar@example.net".to_string(),
                },
            ],
        );
    }
}
