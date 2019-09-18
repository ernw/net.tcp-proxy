#!/usr/bin/env python3
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import

import enum
import struct
from ..nmf import Record
import logging

log = logging.getLogger(__name__ + '.NegotiateStream')


class MessageType(enum.IntEnum):
    HANDSHAKE_DONE = 0x14
    HANDSHAKE_ERROR = 0x15
    HANDSHAKE_IN_PROGRESS = 0x16


class Handshake(Record):
    _records = {}


class HandshakeDone(Record):
    code = MessageType.HANDSHAKE_DONE
    fields = [
        ('major', 'B'),
        ('minor', 'B'),
        ('payload_size', '>H')
    ]


class HandshakeError(HandshakeDone):
    code = MessageType.HANDSHAKE_ERROR


class HandshakeInProgress(HandshakeDone):
    code = MessageType.HANDSHAKE_IN_PROGRESS

Handshake.register(HandshakeInProgress)
Handshake.register(HandshakeDone)
Handshake.register(HandshakeError)


class NegotiateStream:
    def __init__(self, stream):
        self._inner = stream
        self._handshake_done = False

    def write(self, data):
        if not self._handshake_done:
            handshake = HandshakeInProgress(
                                major=1,
                                minor=0,
                                payload_size=len(data)
                            ).to_bytes()
            self._inner.write(handshake + data)
        else:
            while data:
                # See [MS-NNS] 2.2.2 Data Message v8.0 for length
                data2 = data[:0xFC30]
                self._inner.write(struct.pack('<I', len(data2)) + data2)
                data = data[0xFC30:]

    def read(self, count=None):
        if not self._handshake_done:
            _, message = Handshake.parse(self._inner.read(5))

            if message.code == int(MessageType.HANDSHAKE_ERROR):
                error = None
                if message.payload_size > 0:
                    error = struct.unpack('>II', self._inner.read(8))[1]
                raise IOError("Negotiate Error: {:08x}".format(error))
            elif message.code == int(MessageType.HANDSHAKE_DONE):
                self._handshake_done = True
                log.debug('NNS Handshake done')

            return self._inner.read(message.payload_size)
        else:
            payload_size = struct.unpack('<I', self._inner.read(4))[0]
            return self._inner.read(payload_size)
