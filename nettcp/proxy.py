#!/usr/bin/env python2
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import
import socket
import logging
import sys
import binascii
import threading
import warnings
import datetime

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

from .stream.socket import SocketStream
from .nmf import (Record, EndRecord, KnownEncodingRecord,
                  UpgradeRequestRecord, UpgradeResponseRecord, register_types)
try:
    from .stream.gssapi import GSSAPIStream
except ImportError:
    warnings.warn('gssapi not installed, no negotiate protocol available')
    GSSAPIStream = None

try:
    from helperlib import print_hexdump
except ImportError:
    warnings.warn('python-helperlib not installed, no hexdump available (https://github.com/bluec0re/python-helperlib)')
    print_hexdump = False


logging.basicConfig(level='DEBUG')
log = logging.getLogger(__name__ + '.NETTCPProxy')

trace_file = None


def print_data(msg, data):
    if log.isEnabledFor(logging.DEBUG):
        print(msg, file=sys.stderr)
        if print_hexdump:
            print_hexdump(data, colored=True, file=sys.stderr)
        else:
            print(data, file=sys.stderr)


class RecvThread(threading.Thread):
    def __init__(self, handler):
        self.stop = threading.Event()
        super(RecvThread, self).__init__()
        self.handler = handler
        self.close_after_next_packet = False

    def run(self):
        log.debug('Handling data coming from the server')
        while not self.stop.is_set():
            obj = Record.parse_stream(self.handler.stream)
            log.debug('Got from server: %r', obj)
            data = obj.to_bytes()

            self.handler.log_data('s>c', data)

            print_data('Got Data from server:', data)
            self.handler.request.sendall(data)

            if obj.code == EndRecord.code:
                self.handler.stop.set()
                if self.stop.is_set():
                    log.info('Server confirmed end')
                    self.handler.stream.close()
                    self.handler.request.close()
                else:
                    log.info('Server requested end')
                    self.stop.wait()

    def terminate(self):
        self.stop.set()


class NETTCPProxy(SocketServer.BaseRequestHandler):
    negotiate = True
    server_name = None

    def log_data(self, direction, data):
        if trace_file is None:
            return

        args = self.client_address + (direction, binascii.b2a_hex(data).decode())
        trace_file.write('{}\t{}:{}\t{}\t{}\n'.format(datetime.datetime.today(), *args))
        trace_file.flush()

    def handle(self):
        log.info('New connection from %s:%d', *self.client_address)
        self.stop = threading.Event()
        s = socket.create_connection((TARGET_HOST, TARGET_PORT))
        self.stream = SocketStream(s)
        self.negotiated = False
        t = RecvThread(self)
        # t.daemon = True

        try:
            self.mainloop(s, t)
        finally:
            t.terminate()

    def mainloop(self, s, t):
        request_stream = SocketStream(self.request)
        while not self.stop.is_set():
            obj = Record.parse_stream(request_stream)

            log.debug('Client record: %s', obj)

            data = obj.to_bytes()

            self.log_data('c>s', data)

            print_data('Got Data from client:', data)

            self.stream.write(data)

            if obj.code == KnownEncodingRecord.code:
                if self.negotiate:
                    upgr = UpgradeRequestRecord(UpgradeProtocolLength=21,
                                                UpgradeProtocol='application/negotiate').to_bytes()
                    s.sendall(upgr)
                    resp = Record.parse_stream(SocketStream(s))
                    assert resp.code == UpgradeResponseRecord.code, resp
                    self.stream = GSSAPIStream(self.stream, self.server_name)
                    self.stream.negotiate()
                    self.negotiated = True
                # start receive thread
                t.start()
            elif obj.code == EndRecord.code:
                t.terminate()
                if self.stop.is_set():
                    log.info('Client confirmed end')
                    s.close()
                    self.request.close()
                else:
                    log.info('Client requested end')
                    self.stop.wait()


def main():
    import argparse
    global trace_file, TARGET_HOST, TARGET_PORT

    HOST, PORT = "localhost", 8090

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--trace_file', type=argparse.FileType('w'))
    parser.add_argument('-b', '--bind', default=HOST)
    parser.add_argument('-p', '--port', type=int, default=PORT)
    parser.add_argument('-n', '--negotiate', help='Negotiate with the given server name')
    parser.add_argument('TARGET_HOST')
    parser.add_argument('TARGET_PORT', type=int)

    args = parser.parse_args()

    TARGET_HOST = args.TARGET_HOST
    TARGET_PORT = args.TARGET_PORT

    trace_file = args.trace_file

    register_types()

    NETTCPProxy.negotiate = bool(args.negotiate)
    NETTCPProxy.server_name = args.negotiate

    if GSSAPIStream is None and NETTCPProxy.negotiate:
        log.error("GSSAPI not available, negotiation not possible. Try python2 with gssapi")
        sys.exit(1)

    server = SocketServer.ThreadingTCPServer((args.bind, args.port), NETTCPProxy)

    server.serve_forever()

if __name__ == "__main__":
    main()
