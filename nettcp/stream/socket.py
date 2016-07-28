#!/usr/bin/env python3
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import

import select
import logging
import warnings
import sys
try:
    from helperlib import print_hexdump
except ImportError:
    warnings.warn('python-helperlib not installed, no hexdump available (https://github.com/bluec0re/python-helperlib)')
    print_hexdump = False

log = logging.getLogger(__name__ + '.SocketStream')


class SocketStream:
    def __init__(self, socket):
        self._socket = socket

    def read(self, count=None):
        data = None
        if count is None:
            self._socket.setblocking(0)
            rs = [self._socket]
            rs, _, _ = select.select(rs, [], [])
            if rs:
                data = rs[0].recv(4096)
        else:
            self._socket.setblocking(1)
            data = b''
            while count:
                d = self._socket.recv(count)
                count -= len(d)
                data += d

        if log.isEnabledFor(logging.DEBUG) and print_hexdump is not False:
            log.debug('Recved Data:')
            print_hexdump(data, colored=True, file=sys.stderr)
        return data

    def write(self, data):
        if log.isEnabledFor(logging.DEBUG) and print_hexdump is not False:
            log.debug('Sent Data:')
            print_hexdump(data, colored=True, file=sys.stderr)

        self._socket.setblocking(1)
        self._socket.sendall(data)

    def close(self):
        # self._socket.shutdown()
        self._socket.close()
