# -*- coding: utf-8 -*-
# vim: ts=4
###
#
# Copyright (c) 2006 Mehdi Abaakouk
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

"""Tool functions for BIRD looking glass."""

import socket
import pickle

from dns import resolver

dns_cache = resolver.LRUCache(max_size=10000)
resolv = resolver.Resolver()
resolv.timeout = 0.5
resolv.lifetime = 1
resolv.cache = dns_cache


def resolve(name, query_type):
    """Resolve a given name via DNS."""
    return str(resolv.query(name, query_type)[0])


def mask_is_valid(n):
    """Check whther network mask is valid."""
    if not n:
        return True
    try:
        mask = int(n)
        return 1 <= mask <= 128
    except Exception:
        return False


def ipv4_is_valid(ipv4_adr):
    """Check whether a given IPv4 address is valid."""
    try:
        socket.inet_pton(socket.AF_INET, ipv4_adr)
        return True
    except socket.error:
        return False


def ipv6_is_valid(ipv6_adr):
    """Check whether a given IPv6 address is valid."""
    try:
        socket.inet_pton(socket.AF_INET6, ipv6_adr)
        return True
    except socket.error:
        return False


def save_cache_pickle(filename, data):
    """Helper function: Save/Pickle data."""
    with open(filename, "wb") as output:
        pickle.dump(data, output)


def load_cache_pickle(filename, default=None):
    """Helper function: Load/Pickle data."""
    data = default
    try:
        with open(filename, "rb") as pkl_file:
            data = pickle.load(pkl_file)
    except IOError:
        # return default
        pass

    return data
