#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: ts=4
###
#
# Copyright (c) 2012 Mehdi Abaakouk
# -- Original Software
# Copyright (c) 2024 Andreas Duering
# -- Fork
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
###

"""Python / Flask based Looking Glass application."""

import subprocess
import logging
from logging.handlers import TimedRotatingFileHandler
import re
from urllib.error import HTTPError
from urllib.request import urlopen
from urllib.parse import quote, unquote
import argparse
import typing

from flask import Flask, render_template, jsonify, redirect, session, request, abort

# import flask.typing as flaskty
from flask.typing import ResponseReturnValue

from toolbox import (
    mask_is_valid,
    ipv6_is_valid,
    ipv4_is_valid,
    resolve,
)

re_pat_time = re.compile("([0-9]{2}:[0-9]{2}(:[0-9]{2})?)")

app = Flask(__name__)
app.config.from_pyfile("lg.cfg")
app.secret_key = app.config["SESSION_KEY"]
app.debug = app.config["DEBUG"]

file_handler = TimedRotatingFileHandler(
    filename=app.config["LOG_FILE"],
    when="midnight",
    backupCount=app.config.get("LOG_NUM_DAYS", 0),
)
file_handler.setLevel(getattr(logging, app.config["LOG_LEVEL"].upper()))
app.logger.addHandler(file_handler)

# should always match
proto_include = re.compile(app.config.get("INCLUDE_PROTO_PATTERN", r""))
# should never match
proto_exclude = re.compile(app.config.get("EXCLUDE_PROTO_PATTERN", r"^$"))


def get_asn_from_as(n: str) -> list[str]:
    """
    Given an AS number, return some info about the AS.
    """
    asn_zone = app.config.get("ASN_ZONE", "asn.cymru.com")
    try:
        data = resolve(f"AS{n}.{asn_zone}", "TXT").replace("'", "").replace('"', "")
    except Exception:
        return [" "] * 5
    return [field.strip() for field in data.split("|")]


def add_links(text: str | list[str]) -> str:
    """Browser a string and replace ipv4, ipv6, as number, with a
    whois link"""

    if isinstance(text, str):
        text = text.split("\n")

    ret_text: list[str] = []
    # this code is very inefficient
    if len(text) < 200:
        for line in text:
            # Some heuristic to create link
            if line.strip().startswith("BGP.as_path:") or line.strip().startswith(
                "Neighbor AS:"
            ):
                ret_text.append(
                    # simply match an AS number
                    re.sub(
                        r"(\d+)", r'<a href="/whois?q=\1" class="whois">\1</a>', line
                    )
                )
            else:
                # I have no idea what this is supposed to be
                # probably domain names???
                line = re.sub(
                    r"([a-zA-Z0-9\-]*\.([a-zA-Z]{2,3}){1,2})(\s|$)",
                    r'<a href="/whois?q=\1" class="whois">\1</a>\3',
                    line,
                )
                # AS number on route line (directly)
                line = re.sub(
                    r"(?<=\[)AS(\d+)",
                    r'<a href="/whois?q=\1" class="whois">AS\1</a>',
                    line,
                )
                # IPv4 address
                line = re.sub(
                    r"(\d+\.\d+\.\d+\.\d+)",
                    r'<a href="/whois?q=\1" class="whois">\1</a>',
                    line,
                )
                if len(request.path) >= 2:
                    hosts = "/".join(request.path.split("/")[2:])
                else:
                    hosts = "/"
                # *probably* matches protocol names
                line = re.sub(
                    r"\[(\w+)\s+((|\d\d\d\d-\d\d-\d\d\s)(|\d\d:)\d\d:\d\d|\w\w\w\d\d)",
                    rf'[<a href="/detail/{hosts}?q=\1">\1</a> \2',
                    line,
                )
                # matches IP prefixes
                line = re.sub(
                    r"(^|\s+)(([a-f\d]{0,4}:){3,10}[a-f\d]{0,4})",
                    r'\1<a href="/whois?q=\2" class="whois">\2</a>',
                    line,
                    re.I,
                )
                ret_text.append(line)
    else:
        ret_text = text

    return "\n".join(ret_text)


def set_session(request_type: str, hosts: str, proto: str, request_args: str) -> None:
    """Store all data from user in the user session"""
    session.permanent = True
    session.update(
        {
            "request_type": request_type,
            "hosts": hosts,
            "proto": proto,
            "request_args": request_args,
        }
    )
    history = session.get("history", [])

    # erase old format history
    if not isinstance(history, list):
        history = []

    t = (hosts, proto, request_type, request_args)
    if t in history:
        del history[history.index(t)]
    history.insert(0, t)
    session["history"] = history[:20]


def whois_command(query: str) -> str:
    """Get whois information for a specified object"""
    server = []
    whois_server: str = app.config.get("WHOIS_SERVER", "")
    if whois_server:
        server = ["-h", whois_server]
    return (
        subprocess.Popen(["whois"] + server + [query], stdout=subprocess.PIPE)
        .communicate()[0]
        .decode("utf-8", "ignore")
    )


def bird_command(host: str, proto: str, query: str) -> tuple[bool, str]:
    """Alias to bird_proxy for bird service"""
    return bird_proxy(host, proto, "bird", query)


def bird_proxy(host: str, proto: str, service: str, query: str) -> tuple[bool, str]:
    """Retreive data of a service from a running lgproxy on a remote node

    First and second arguments are the node and the port of the running lgproxy
    Third argument is the service, can be "traceroute" or "bird"
    Last argument, the query to pass to the service

    return tuple with the success of the command and the returned data

    if error, second element is errors separated by \n.
    """

    l_error = []
    if len(query.split("\n")) > 1:
        l_error.append("Multiple commands are not allowed.")
    if not query.startswith("show"):
        l_error.append("Only show commands are allowed.")
    # all table X or table X all are both valid syntaxes.
    if re.match(r"show\s+route(?:\s+all)?\s+table\s+(?:\w+)(?:\s+all)?", query):
        l_error.append("It looks like you are trying to query too much.")

    path = ""
    if proto == "ipv6":
        path = service + "6"
    elif proto == "ipv4":
        # path = service
        l_error.append("IPv4 is not supported")

    if not path:
        l_error.append(f'Proto "{proto}" invalid')

    if host not in app.config["HOSTS"]:
        l_error.append(f'Host "{host}" invalid')

    if l_error:
        return False, "\n".join(l_error)

    endpoint = app.config["HOSTS"][host]["endpoint"]
    url = f"{endpoint}/{path}?"
    if "SHARED_SECRET" in app.config:
        url = f"{url}secret={app.config['SHARED_SECRET']}&"
    url = f"{url}q={quote(query)}"

    result: str
    status = False
    try:
        with urlopen(url, timeout=2) as f:
            result = f.read().decode("utf-8")
            status = True  # retreive remote status
    except HTTPError as ex:
        status = False
        result = f"HTTP Error occurred: {ex.fp.read().decode('utf-8')}"
    except IOError:
        result = f"Failed to retrieve data from host {host}"
        app.logger.warning("Failed to retrieve URL for host %s: %s", host, url)

    return status, result


@app.context_processor
def inject_commands() -> dict[str, typing.Any]:
    """Get commands for the navbar"""

    # map route to description
    commands: list[tuple[str, str]] = [
        ("summary", "show protocols"),
        ("detail", "show protocols ... all"),
        ("prefix", "show route for ..."),
        ("prefix_detail", "show route for ... all"),
        ("where", "show route where net ~ [ ... ]"),
        ("where_detail", "show route where net ~ [ ... ] all"),
        ("adv", "show route ..."),
    ]
    commands_dict = dict(commands)
    return {"commands": commands, "commands_dict": commands_dict}


@app.context_processor
def inject_all_host() -> dict[str, typing.Any]:
    """Get hosts for the navbar"""
    all_hosts = "+".join(list(app.config["HOSTS"].keys()))
    return {"all_hosts": all_hosts}


@app.route("/")
def hello() -> ResponseReturnValue:
    """Get the index page contant (or the redirect)"""
    page_content = app.config.get("INDEX_PAGE", None)
    all_hosts = "+".join(list(app.config["HOSTS"].keys()))
    if page_content:
        # site behaves weird if this isn't there, some defaults aren't set...
        set_session("summary", all_hosts, "ipv6", "")
        return render_template("index.html", output=page_content)

    return redirect(f"/summary/{all_hosts}/ipv6")


def error_page(text: str) -> ResponseReturnValue:
    """Default error page for exceptions/errors"""
    return render_template("error.html", errors=[text]), 500


@app.errorhandler(400)
def incorrect_request(e: str) -> ResponseReturnValue:
    """Error handeler for 400 errors"""
    return (
        render_template(
            "error.html", warnings=["The server could not understand the request"]
        ),
        400,
    )


@app.errorhandler(404)
def page_not_found(e: str) -> ResponseReturnValue:
    """Returns the file-not-found page"""
    return (
        render_template(
            "error.html", warnings=["The requested URL was not found on the server."]
        ),
        404,
    )


def get_query() -> str:
    """Get the "safe" query parameter of the URL"""
    q = unquote(request.args.get("q", "").strip())
    return q


@app.route("/whois")
def whois() -> ResponseReturnValue:
    """Handle whois resource.

    Execute a whois, query is given by ?q parameter.
    """
    query = get_query()
    if not query:
        abort(400)

    try:
        asnum = int(query)
        query = f"as{asnum}"
    except Exception:
        m = re.match(r"[\w\d-]*\.(?P<domain>[\d\w-]+\.[\d\w-]+)$", query)
        if m:
            query = m.groupdict()["domain"]

    output = whois_command(query)
    return jsonify(output=output, title=query)


SUMMARY_UNWANTED_PROTOS = ["Kernel", "Static", "Device", "Direct", "Pipe"]


@app.route("/summary/<hosts>")
@app.route("/summary/<hosts>/<proto>")
def summary(hosts: str, proto: str = "ipv6") -> ResponseReturnValue:
    """Handle the summary resource.

    Shows a list of protocols.
    """
    set_session("summary", hosts, proto, "")
    command = "show protocols"

    proto_summary = {}
    errors = []
    for host in hosts.split("+"):
        ret, output = bird_command(host, proto, command)

        if ret is False:
            errtxts = output.split("\n")
            errors.extend(errtxts)
            continue

        res = output.split("\n")

        if len(res) <= 1:
            errors.append(
                "%s: bird command failed with error, %s" % (host, "\n".join(res))
            )
            continue

        data: list[dict[str, str]] = []
        for line in res[1:]:
            line = line.strip()
            if line and (line.split() + [""])[1] not in SUMMARY_UNWANTED_PROTOS:
                split = line.split()
                if len(split) >= 5:
                    props: dict[str, str] = {}
                    props["name"] = split[0]
                    props["proto"] = split[1]
                    props["table"] = split[2]
                    props["state"] = split[3]
                    props["since"] = split[4]
                    idx = 5
                    if re_pat_time.match(split[idx]):
                        props["since"] += " " + split[idx]
                        idx += 1
                    props["info"] = " ".join(split[idx:]) if len(split) > idx else ""
                    data.append(props)
                else:
                    app.logger.warning("couldn't parse: %s", line)

        data = [
            p
            for p in data
            if (proto_include.match(p["name"]) and not proto_exclude.match(p["name"]))
        ]
        proto_summary[host] = data

    return render_template(
        "summary.html", summary=proto_summary, command=command, errors=errors
    )


@app.route("/detail/<hosts>/<proto>")
def detail(hosts: str, proto: str) -> ResponseReturnValue:
    """Handle the protocol detail resource.

    Shows the details of a protocol on a given host.
    """
    name = get_query()

    if not name:
        abort(400)

    proto_detail = {}
    errors = []
    command = f"show protocols all {name}"

    if proto_exclude.match(name):
        for host in hosts.split("+"):
            errors.append(f"{host}: bird command failed with error, Parse error")
    else:
        set_session("detail", hosts, proto, name)

        for host in hosts.split("+"):
            ret, output = bird_command(host, proto, command)
            res = output.split("\n")

            if ret is False:
                errors.append(f"{res}")
                continue

            if len(res) <= 1:
                all_errors = "\n".join(res)
                errors.append(f"{host}: bird command failed with error, {all_errors}")
                continue

            proto_detail[host] = {"status": res[1], "description": add_links(res[2:])}

    return render_template(
        "detail.html", detail=proto_detail, command=command, errors=errors
    )


@app.route("/traceroute/<hosts>/<proto>")
def traceroute(hosts: str, proto: str) -> ResponseReturnValue:
    """For compatibility: Used to execute a traceroute"""
    return error_page("Not supported")


@app.route("/adv/<hosts>/<proto>")
def show_route_filter(hosts: str, proto: str) -> ResponseReturnValue:
    """Show detailed route statistics for a prefix"""
    return show_route("adv", hosts, proto)


@app.route("/adv_bgpmap/<hosts>/<proto>")
def show_route_filter_bgpmap(hosts: str, proto: str) -> ResponseReturnValue:
    """For compatibility: Used to create a bgpmap"""
    return error_page("Not supported")


@app.route("/where/<hosts>/<proto>")
def show_route_where(hosts: str, proto: str) -> ResponseReturnValue:
    """Show route statistics for (multiple) prefixes"""
    return show_route("where", hosts, proto)


@app.route("/where_detail/<hosts>/<proto>")
def show_route_where_detail(hosts: str, proto: str) -> ResponseReturnValue:
    """Show detailed route statistics for (multiple) prefixes"""
    return show_route("where_detail", hosts, proto)


@app.route("/where_bgpmap/<hosts>/<proto>")
def show_route_where_bgpmap(hosts: str, proto: str) -> ResponseReturnValue:
    """For compatibility: Used to create a bgpmap"""
    return error_page("Not supported")


@app.route("/prefix/<hosts>/<proto>")
def show_route_for(hosts: str, proto: str) -> ResponseReturnValue:
    """Show route for a single given prefix"""
    return show_route("prefix", hosts, proto)


@app.route("/prefix_detail/<hosts>/<proto>")
def show_route_for_detail(hosts: str, proto: str) -> ResponseReturnValue:
    """Show detailed route for a single given prefix"""
    return show_route("prefix_detail", hosts, proto)


@app.route("/prefix_bgpmap/<hosts>/<proto>")
def show_route_for_bgpmap(hosts: str, proto: str) -> ResponseReturnValue:
    """For compatibility: Used to create a bgpmap"""
    return error_page("Not supported")


def get_as_name(_as: str) -> str:
    """Returns a string that contain the as number following by the as name"""
    if not _as:
        return "AS?????"

    if not _as.isdigit():
        return _as.strip()

    name = get_asn_from_as(_as)[-1].replace(" ", "\r", 1)
    return f"AS{_as} | {name}"


def get_as_number_from_protocol_name(host: str, proto: str, protocol: str) -> str:
    """Get neighbor AS for given protocol"""
    _, res = bird_command(host, proto, f"show protocols all {protocol}")
    re_asnumber = re.search(r"Neighbor AS:\s*(\d*)", res)
    if re_asnumber:
        return re_asnumber.group(1)

    return "?????"


@app.route("/bgpmap/")
def show_bgpmap() -> ResponseReturnValue:
    """For compatibility: Used to create a bgpmap"""
    return error_page("Not supported")


def build_as_tree_from_raw_bird_ouput(text: list[str]):
    """Extract the as path from the raw bird "show route all" command"""

    path = None
    paths = []
    net_dest = ""
    peer_protocol_name = ""

    # No idea how I could clean this up, pylint complains...
    for line in text:
        line = line.strip()

        # bird1: cli_printf(c, -1008, "\tType: %s %s %s", src_names[a->source], \
        #                    cast_names[a->cast], ip_scope_text(a->scope));
        # bird2: cli_msg(-1009, "%N\t%s", r->net, rta_dest_names[r->dest]);
        #                   -- for (none|blackhole|unreachable|prohibit)
        #        cli_printf(c, -1007, "%-20s %s [%s %s%s]%s%s", ia, rta_dest_name(a->dest), \
        #                   a->src->proto->name, tm, from, \
        #                   primary ? (sync_error ? " !" : " *") : "", info);
        # represents the start of a (route,protocol) output
        #   start of a new route (w/ or w/o prefix)
        re_bird_route = re.search(r"(.*)unicast\s+\[(\w+)\s+", line)
        if re_bird_route:
            l_prefix = re_bird_route.group(1).strip()
            if l_prefix:
                net_dest = l_prefix
            peer_protocol_name = re_bird_route.group(2).strip()

        # bird1 ONLY:
        #        rt_format_via
        #           bsprintf(via, "via %I on %s", a->gw, a->iface->name); break;
        #
        # bird1 ONLY!
        #        rt_show_rte
        #           cli_printf(c, -1007, "%-18s %s [%s %s%s]%s%s", ia, rt_format_via(e), \
        #               a->src->proto->name, tm, from, \
        #               primary ? (sync_error ? " !" : " *") : "", info);
        #
        # bird1 / bird2
        #           for (nh = a->nexthops; nh; nh = nh->next)
        #               cli_printf(c, -1007, "\tvia %I on %s weight %d", nh->gw, nh->iface->name, \
        #                           nh->weight + 1);
        #
        #        rt_show_rte

        # ... probably.
        re_bird_hop = re.search(
            r"(.*)via\s+([0-9a-fA-F:\.]+)\s+on\s+\S+(\s+\[(\w+)\s+)?", line
        )
        if re_bird_hop:
            if path:
                path.append(net_dest)
                paths.append(path)
                path = None

            # this only occurs for Bird 1
            l_re_destnet = re_bird_hop.group(1).strip()
            if l_re_destnet:
                net_dest = l_re_destnet

            nexthop_gateway = re_bird_hop.group(2).strip()
            l_re_protoname = re_bird_hop.group(4)
            if l_re_protoname:
                peer_protocol_name = l_re_protoname.strip()
            # Check if via line is an internal route (special case for internal routing)
            for other_host in list(app.config["HOSTS"].keys()):
                # eurgh. This won't do (for link-local sessions, or external peers)
                if nexthop_gateway in app.config["HOSTS"][other_host].get(
                    "routerip", []
                ):
                    path = [other_host]
                    break
            else:
                # ugly hack for good printing
                path = [peer_protocol_name]

        # this could be either static or a dynamic protocol?
        # though it doesn't make sense to create a bgpmap for a static route...
        # Bird1: rt_format_via again
        re_unreachable_route = re.search(r"(.*)unreachable\s+\[(\w+)\s+", line)
        if re_unreachable_route:
            if path:
                path.append(net_dest)
                paths.append(path)
                path = None

            if path is None:
                l_protocol_name = re_unreachable_route.group(2).strip()
                path = [l_protocol_name]

            re_prefix = re_unreachable_route.group(1).strip()
            if re_prefix:
                net_dest = re_prefix

        path = _extract_as_path(line, path)

    if path:
        path.append(net_dest)
        paths.append(path)

    return paths


def _extract_as_path(line: str, path: list[str] | None) -> list[str] | None:
    """Given a line, if it's an as_path, extract it."""
    if line.startswith("BGP.as_path:"):
        as_path = line.replace("BGP.as_path:", "").strip().split(" ")
        if path:
            path.extend(as_path)
        else:
            path = as_path
    return path


def show_route(request_type: str, hosts: str, proto: str) -> ResponseReturnValue:
    """Render various route pages"""
    expression = get_query()
    if not expression:
        abort(400)

    set_session(request_type, hosts, proto, expression)
    if proto == "ipv4":
        return error_page("IPv4 is not supported")

    show_route_details = " all" if request_type.endswith("detail") else ""
    if request_type.startswith("adv"):
        command = "show route " + expression.strip()
    elif request_type.startswith("where"):
        command = "show route where net ~ [ " + expression + " ]" + show_route_details
    else:
        mask = ""
        if proto == "ipv4":
            mask = "32"
        elif proto == "ipv6":
            mask = "128"

        pref_netmask = expression.split("/")
        if len(pref_netmask) == 2:
            expression, mask = pref_netmask

        if not mask_is_valid(mask):
            return error_page(f"mask {mask} is invalid")

        try:
            expression = try_to_resolve(proto, expression)
        except Exception:
            return error_page(f"{expression} is unresolvable or invalid for {proto}")

        if mask:
            expression += "/" + mask

        command = "show route for " + expression + show_route_details

    host_details = {}
    errors = []
    # needed for non-default tables
    # ideally, you'd specify one table here...
    if "table" not in command:
        command += " table all"

    for host in hosts.split("+"):
        ret, output = bird_command(host, proto, command)
        res = output.split("\n")

        if ret is False:
            errors.append(f"{res}")
            continue

        if len(res) <= 1:
            errors.append(
                "%s: bird command failed with error, %s" % (host, "\n".join(res))
            )
            continue

        host_details[host] = add_links(res)

    return render_template(
        "route.html",
        detail=host_details,
        command=command,
        expression=expression,
        errors=errors,
    )


def try_to_resolve(proto, expression):
    """Turn expression into an IP address.

    If expression is already a valid IPv4/IPv6, depending on proto,
    return it, else try to resolve it, as if it's a domain name.

    Throws an exception if expression is not a valid domain name,
    either.
    """
    if proto == "ipv6" and not ipv6_is_valid(expression):
        expression = resolve(expression, "AAAA")
    if proto == "ipv4" and not ipv4_is_valid(expression):
        expression = resolve(expression, "A")
    return expression


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # parser.add_argument(
    #     "-c", dest="config_file", help="path to config file", default="lg.cfg"
    # )
    args = parser.parse_args()
    # start_app(args.config_file) ...

    app.logger.info("lg start")
    app.run(app.config.get("BIND_IP", "0.0.0.0"), app.config.get("BIND_PORT", 5000))
