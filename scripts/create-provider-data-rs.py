#!/usr/bin/env python3
# if the yaml import fails, run "pip install pyyaml"

import sys
import yaml
import datetime
from pathlib import Path

out_all = ""
out_domains = ""
out_ids = ""
domains_set = set()


def camel(name):
    words = name.split("_")
    return "".join(w.capitalize() for i, w in enumerate(words))


def cleanstr(s):
    s = s.strip()
    s = s.replace("\n", " ")
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    return s


def file2id(f):
    return f.stem


def file2varname(f):
    f = file2id(f)
    f = f.replace(".", "_")
    f = f.replace("-", "_")
    return "P_" + f.upper()


def file2url(f):
    f = file2id(f)
    f = f.replace(".", "-")
    return "https://providers.delta.chat/" + f


def process_opt(data):
    if not "opt" in data:
        return "ProviderOptions::new()"
    opt = "ProviderOptions {\n"
    opt_data = data.get("opt", "")
    for key in opt_data:
        value = str(opt_data[key])
        if key == "max_smtp_rcpt_to":
            value = "Some(" + value + ")"
        if value in {"True", "False"}:
            value = value.lower()
        opt += "        " + key + ": " + value + ",\n"
    opt += "        ..ProviderOptions::new()\n"
    opt += "    }"
    return opt


def process_config_defaults(data):
    if not "config_defaults" in data:
        return "None"
    defaults = "Some(&[\n"
    config_defaults = data.get("config_defaults", "")
    for key in config_defaults:
        value = str(config_defaults[key])
        defaults += (
            "        ConfigDefault { key: Config::"
            + camel(key)
            + ', value: "'
            + value
            + '" },\n'
        )
    defaults += "    ])"
    return defaults


def process_data(data, file):
    status = data.get("status", "")
    if status != "OK" and status != "PREPARATION" and status != "BROKEN":
        raise TypeError("bad status")

    comment = ""
    domains = ""
    if not "domains" in data:
        raise TypeError("no domains found")
    for domain in data["domains"]:
        domain = cleanstr(domain)
        if domain == "" or domain.lower() != domain:
            raise TypeError("bad domain: " + domain)

        global domains_set
        if domain in domains_set:
            raise TypeError("domain used twice: " + domain)
        domains_set.add(domain)

        domains += '    ("' + domain + '", &' + file2varname(file) + "),\n"
        comment += domain + ", "

    ids = ""
    ids += '    ("' + file2id(file) + '", &' + file2varname(file) + "),\n"

    server = ""
    has_imap = False
    has_smtp = False
    if "server" in data:
        for s in data["server"]:
            hostname = cleanstr(s.get("hostname", ""))
            port = int(s.get("port", ""))
            if hostname == "" or hostname.lower() != hostname or port <= 0:
                raise TypeError("bad hostname or port")

            protocol = s.get("type", "").upper()
            if protocol == "IMAP":
                has_imap = True
            elif protocol == "SMTP":
                has_smtp = True
            else:
                raise TypeError("bad protocol")

            socket = s.get("socket", "").upper()
            if socket != "STARTTLS" and socket != "SSL" and socket != "PLAIN":
                raise TypeError("bad socket")

            username_pattern = s.get("username_pattern", "EMAIL").upper()
            if username_pattern != "EMAIL" and username_pattern != "EMAILLOCALPART":
                raise TypeError("bad username pattern")

            server += (
                "        Server { protocol: "
                + protocol.capitalize()
                + ", socket: "
                + socket.capitalize()
                + ', hostname: "'
                + hostname
                + '", port: '
                + str(port)
                + ", username_pattern: "
                + username_pattern.capitalize()
                + " },\n"
            )

    opt = process_opt(data)
    config_defaults = process_config_defaults(data)

    oauth2 = data.get("oauth2", "")
    oauth2 = "Some(Oauth2Authorizer::" + camel(oauth2) + ")" if oauth2 != "" else "None"

    provider = ""
    before_login_hint = cleanstr(data.get("before_login_hint", "") or "")
    after_login_hint = cleanstr(data.get("after_login_hint", ""))
    if (not has_imap and not has_smtp) or (has_imap and has_smtp):
        provider += (
            "static "
            + file2varname(file)
            + ": Provider = Provider {\n"
        )
        provider += '    id: "' + file2id(file) + '",\n'
        provider += "    status: Status::" + status.capitalize() + ",\n"
        provider += '    before_login_hint: "' + before_login_hint + '",\n'
        provider += '    after_login_hint: "' + after_login_hint + '",\n'
        provider += '    overview_page: "' + file2url(file) + '",\n'
        provider += "    server: &[\n" + server + "    ],\n"
        provider += "    opt: " + opt + ",\n"
        provider += "    config_defaults: " + config_defaults + ",\n"
        provider += "    oauth2_authorizer: " + oauth2 + ",\n"
        provider += "};\n\n"
    else:
        raise TypeError("SMTP and IMAP must be specified together or left out both")

    if status != "OK" and before_login_hint == "":
        raise TypeError(
            "status PREPARATION or BROKEN requires before_login_hint: " + file
        )

    # finally, add the provider
    global out_all, out_domains, out_ids
    out_all += "// " + file.name + ": " + comment.strip(", ") + "\n"

    # also add provider with no special things to do -
    # eg. _not_ supporting oauth2 is also an information and we can skip the mx-lookup in this case
    out_all += provider
    out_domains += domains
    out_ids += ids


def process_file(file):
    print("processing file: {}".format(file), file=sys.stderr)
    with open(file) as f:
        # load_all() loads "---"-separated yamls -
        # by coincidence, this is also the frontmatter separator :)
        data = next(yaml.load_all(f, Loader=yaml.SafeLoader))
        process_data(data, file)


def process_dir(dir):
    print("processing directory: {}".format(dir), file=sys.stderr)
    files = sorted(f for f in dir.iterdir() if f.suffix == ".md")
    for f in files:
        process_file(f)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: update.py DIR_WITH_MD_FILES > data.rs")

    out_all = (
        "// file generated by src/provider/update.py\n\n"
        "use crate::provider::Protocol::*;\n"
        "use crate::provider::Socket::*;\n"
        "use crate::provider::UsernamePattern::*;\n"
        "use crate::provider::{\n"
        "    Config, ConfigDefault, Oauth2Authorizer, Provider, ProviderOptions, Server, Status,\n"
        "};\n"
        "use std::collections::HashMap;\n\n"
        "use std::sync::LazyLock;\n\n"
    )

    process_dir(Path(sys.argv[1]))

    out_all += "pub(crate) static PROVIDER_DATA: [(&str, &Provider); " + str(len(domains_set)) + "] = [\n";
    out_all += out_domains
    out_all += "];\n\n"

    out_all += "pub(crate) static PROVIDER_IDS: LazyLock<HashMap<&'static str, &'static Provider>> = LazyLock::new(|| HashMap::from([\n"
    out_all += out_ids
    out_all += "]));\n\n"

    if len(sys.argv) < 3:
        now = datetime.datetime.utcnow()
    else:
        now = datetime.datetime.fromisoformat(sys.argv[2])
    out_all += (
        "pub static _PROVIDER_UPDATED: LazyLock<chrono::NaiveDate> = "
        "LazyLock::new(|| chrono::NaiveDate::from_ymd_opt("
        + str(now.year)
        + ", "
        + str(now.month)
        + ", "
        + str(now.day)
        + ").unwrap());\n"
    )

    print(out_all)
