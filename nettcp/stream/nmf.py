#!/usr/bin/env python3
# encoding: utf-8
# Copyright 2016 Timo Schmid
from ..nmf import (PreambleEndRecord, ViaRecord, VersionRecord,
                   ModeRecord, KnownEncodingRecord, UpgradeRequestRecord,
                   UpgradeResponseRecord, Record, register_types,
                   SizedEnvelopedMessageRecord, PreambleAckRecord, EndRecord)
from .gssapi import GSSAPIStream


class NMFStream:
    def __init__(self, stream, url, server_name=None):
        self._inner = stream
        self._server_name = server_name
        self.url = url

        register_types()

    def preamble(self):
        data = [
            VersionRecord(MajorVersion=1, MinorVersion=0),
            ModeRecord(Mode=2),
            ViaRecord(ViaLength=len(self.url), Via=self.url),
            KnownEncodingRecord(Encoding=8),
        ]

        self._inner.write(b''.join(d.to_bytes() for d in data))

        if self._server_name:
            msg = UpgradeRequestRecord(UpgradeProtocolLength=21,
                                       UpgradeProtocol='application/negotiate').to_bytes()
            self._inner.write(msg)
            d = self._inner.read(1)
            if d != UpgradeResponseRecord().to_bytes():
                raise IOError('Negotiate not supported')

            self._inner = GSSAPIStream(self._inner, self._server_name)

        self._inner.write(PreambleEndRecord().to_bytes())

        if self._inner.read(1) != PreambleAckRecord().to_bytes():
            raise IOError('Preamble end not acked')

    def write(self, data):
        msg = SizedEnvelopedMessageRecord(Size=len(data), Payload=data)
        self._inner.write(msg.to_bytes())

    def read(self, count=None):
        if count:
            data = self._inner.read(count)
            s, msg = Record.parse(data)
            return data[s:msg.Size+s]
        else:
            msg = Record.parse_stream(self._inner)

            return msg.Payload

    def close(self):
        self._inner.write(EndRecord().to_bytes())
        self._inner.close()
