#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: ts=4
###
#
# Copyright (c) 2006 Mehdi Abaakouk
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

"""HTTP proxy for BIRD socket."""


import logging
from logging.handlers import TimedRotatingFileHandler
from urllib.parse import unquote

import argparse

from flask import Flask, request, abort

from bird import BirdSocket

app = Flask(__name__)
app.debug = app.config["DEBUG"]
app.config.from_pyfile("lgproxy.cfg")

file_handler = TimedRotatingFileHandler(
    filename=app.config["LOG_FILE"],
    when="midnight",
    backupCount=app.config.get("LOG_NUM_DAYS", 0),
)
app.logger.setLevel(getattr(logging, app.config["LOG_LEVEL"].upper()))
app.logger.addHandler(file_handler)


@app.before_request
def access_log_before(*_args, **_kwargs):
    """Write each request to log."""
    hdrs = "|".join([f"{k}:{v}" for k, v in list(request.headers.items())])
    app.logger.info(
        "[%s] request %s, %s",
        request.remote_addr,
        request.url,
        hdrs,
    )


@app.after_request
def access_log_after(response, *_args, **_kwargs):
    """Write each response code to log."""
    app.logger.info(
        "[%s] reponse %s, %s", request.remote_addr, request.url, response.status_code
    )
    return response


def check_security():
    """check whether host is allowed to access site."""
    if (
        app.config["ACCESS_LIST"]
        and request.remote_addr not in app.config["ACCESS_LIST"]
    ):
        app.logger.info("Your remote address is not valid")
        abort(401)

    if (
        app.config.get("SHARED_SECRET")
        and request.args.get("secret") != app.config["SHARED_SECRET"]
    ):
        app.logger.info("Your shared secret is not valid")
        abort(401)


@app.route("/traceroute")
@app.route("/traceroute6")
def traceroute():
    """Execute a traceroute to a given target."""
    return "Not allowed."


@app.route("/bird")
@app.route("/bird6")
def bird():
    """Execute an arbitrary bird command, return the result"""
    check_security()

    # Just use Bird2
    b = BirdSocket(file=app.config.get("BIRD_SOCKET", "/var/run/bird/bird.ctl"))

    query = request.args.get("q", "")
    query = unquote(query)
    # TODO: Only allow show commands

    _, result = b.cmd(query)
    b.close()
    # FIXME: use status
    return result


# TODO: Application factory, needs to move all routes inside factory function... meh
# allow config file....
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    app.logger.info("lgproxy start")
    app.run(app.config.get("BIND_IP", "0.0.0.0"), app.config.get("BIND_PORT", 5000))
