#!/usr/bin/env python3
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import unicode_literals

import struct
import enum
import logging
from functools import partial

__all__ = [
    'Record',
    'VersionRecord',
    'ViaRecord',
    'KnownEncodingRecord',
    'UpgradeRequestRecord',
    'UpgradeResponseRecord',
    'ModeRecord',
    'PreambleEndRecord',
    'PreambleAckRecord',
    'EndRecord',
    'SizedEnvelopedMessageRecord',
    'UnsizedEnvelopedMessageRecord',
    'register_types'
]

log = logging.getLogger(__name__)


def b(data):
    return 1, struct.unpack('B', data[:1])[0]


def pt(func, *args, **kwargs):
    func2 = partial(func, *args, **kwargs)
    if hasattr(func, 'encode'):
        func2.encode = func.encode
    if hasattr(func, 'stream'):
        func2.stream = partial(func.stream, *args, **kwargs)
    return func2


def varint(obj, data):
    val = 0
    cnt = 0
    while data:
        d = b(data)[1]
        data = data[1:]
        if not d:
            break

        val |= (d & 0x7f) << (7*cnt)
        cnt += 1
        if not d & 0x80:
            break

    return cnt, val


def varint_stream(obj, stream):
    val = 0
    cnt = 0
    while True:
        d = b(stream.read(1))[1]
        if not d:
            break

        val |= (d & 0x7f) << (7*cnt)
        cnt += 1
        if not d & 0x80:
            break

    return val

varint.stream = varint_stream


def varint_encode(val):
    print(repr(val))
    if not val:
        return b'\x00'
    elif val < 0x80:
        return struct.pack('B', val)
    elif val < 0x4000:
        return struct.pack('B', val & 0x7f | 0x80) +\
               struct.pack('B', (val >> 7) & 0x7f)
    elif val < 0x200000:
        return struct.pack('B', val & 0x7f | 0x80) + \
               struct.pack('B', (val >> 7) & 0x7f | 0x80) +  \
               struct.pack('B', (val >> 14) & 0x7f)
    elif val < 0x10000000:
        return struct.pack('B', val & 0x7f | 0x80) + \
               struct.pack('B', (val >> 7) & 0x7f | 0x80) + \
               struct.pack('B', (val >> 14) & 0x7f | 0x80) + \
               struct.pack('B', (val >> 21) & 0x7f)
    else:
        return struct.pack('B', val & 0x7f | 0x80) + \
               struct.pack('B', (val >> 7) & 0x7f | 0x80) +  \
               struct.pack('B', (val >> 14) & 0x7f | 0x80) + \
               struct.pack('B', (val >> 21) & 0x7f | 0x80) + \
               struct.pack('B', (val >> 28) & 0x7f)

varint.encode = varint_encode


def utf8(name, obj, data):
    l = getattr(obj, name)
    return l, data[:l].decode('utf-8')
utf8.encode = lambda v: v.encode('utf-8')


def utf8_stream(name, obj, stream):
    l = getattr(obj, name)
    return stream.read(l).decode('utf-8')
utf8.stream = utf8_stream


def raw_bytes(name, obj, data):
    l = getattr(obj, name)
    return l, data[:l]
raw_bytes.encode = lambda v: v


def raw_bytes_stream(name, obj, stream):
    l = getattr(obj, name)
    return stream.read(l)
raw_bytes.stream = raw_bytes_stream


def as_enum(fmt, enum):
    def internal(obj, data):
        s = struct.calcsize(fmt)
        value = struct.unpack(fmt, data[:s])[0]
        return s, enum(value)

    def stream(obj, stream):
        s = struct.calcsize(fmt)
        value = struct.unpack(fmt, stream.read(s))[0]
        return enum(value)

    def encode(enum):
        return struct.pack(fmt, enum.value)

    internal.stream = stream
    internal.encode = encode
    return internal


class Enum(enum.IntEnum):
    def __repr__(self):
        return str(self)


class KnownEncoding(Enum):
    UTF8 = 3
    UTF16 = 4
    UNICODE_LITTL_ENDIAN = 5
    MTOM = 6
    BINARY = 7
    BINARY_DICT = 8


class Mode(Enum):
    SINGLETON_UNSIZED = 1
    DUPLEX = 2
    SIMPLEX = 3
    SINGLETON_SIZED = 4


class Record(object):
    code_fmt = 'B'
    code = None
    fields = []
    _records = {}

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    @classmethod
    def register(cls, rec):
        cls._records[rec.code] = rec

    @classmethod
    def parse(cls, data):
        s = struct.calcsize(cls.code_fmt)
        code = struct.unpack(cls.code_fmt, data[:s])[0]
        data = data[s:]

        rec = cls._records[code]

        obj = rec()
        l = s
        for name, dtype in rec.fields:
            if hasattr(dtype, '__call__'):
                s, val = dtype(obj, data)
                setattr(obj, name, val)
            else:
                s = struct.calcsize(dtype)
                setattr(obj, name, struct.unpack(dtype, data[:s])[0])

            data = data[s:]
            l += s

        return l, obj

    @classmethod
    def parse_stream(cls, stream):
        s = struct.calcsize(cls.code_fmt)
        data = stream.read(s)
        assert len(data) == s, repr(data)
        code = struct.unpack(cls.code_fmt, data)[0]

        rec = cls._records[code]

        obj = rec()
        for name, dtype in rec.fields:
            if hasattr(dtype, '__call__') and hasattr(dtype, 'stream'):
                val = dtype.stream(obj, stream)
                setattr(obj, name, val)
            else:
                s = struct.calcsize(dtype)
                setattr(obj, name, struct.unpack(dtype, stream.read(s))[0])

        return obj

    def to_bytes(self):
        data = struct.pack(self.code_fmt, self.code)
        for name, dtype in self.fields:
            if hasattr(dtype, '__call__'):
                val = getattr(self, name)
                try:
                    data += dtype.encode(val)
                except Exception as e:
                    log.error('Error during encoding field %s as %r of %s', name, val, self)
                    raise
            else:
                data += struct.pack(dtype, getattr(self, name))
        return data

    def __repr__(self):
        fields = [
            '{}={!r}'.format(name, getattr(self, name))
            for name, _ in self.fields
        ]

        return '{}({})'.format(type(self).__name__, ', '.join(fields))


class VersionRecord(Record):
    code = 0x00
    fields = [
        ('MajorVersion', 'B'),
        ('MinorVersion', 'B'),
    ]


class ModeRecord(Record):
    code = 0x01
    fields = [
        ('Mode', as_enum('B', Mode)),
    ]


class ViaRecord(Record):
    code = 0x02
    fields = [
        ('ViaLength', varint),
        ('Via', pt(utf8, 'ViaLength')),
    ]


class KnownEncodingRecord(Record):
    code = 0x03
    fields = [
        ('Encoding', as_enum('B', KnownEncoding)),
    ]


class UpgradeRequestRecord(Record):
    code = 0x09
    fields = [
        ('UpgradeProtocolLength', varint),
        ('UpgradeProtocol', pt(utf8, 'UpgradeProtocolLength')),
    ]


class UpgradeResponseRecord(Record):
    code = 0x0A


class PreambleEndRecord(Record):
    code = 0x0c


class PreambleAckRecord(Record):
    code = 0x0b


class SizedEnvelopedMessageRecord(Record):
    code = 0x06
    fields = (
        ('Size', varint),
        ('Payload', pt(raw_bytes, 'Size'))
    )


class EndRecord(Record):
    code = 0x07


class FaultRecord(Record):
    code = 0x08
    fields = (
        ('FaultSize', varint),
        ('Fault', pt(utf8, 'FaultSize'))
    )


class UnsizedEnvelopedMessageRecord(Record):
    code = 0x05


def register_types(module=None, baseclass=Record):
    import inspect

    if not module:
        module = __name__

    if isinstance(module, str):
        import sys
        module = sys.modules[module]

    for name, cls in inspect.getmembers(module, inspect.isclass):
        if issubclass(cls, baseclass):
            baseclass.register(cls)


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('TRACE_FILE', type=argparse.FileType('r'))

    args = parser.parse_args()

    register_types()

    for line in args.TRACE_FILE:
        parts = line.strip().split('\t')
        if len(parts) == 2:
            dir, data = parts
        else:
            timestamp, connection, dir, data = parts

        data = bytes.fromhex(data)

        while data:
            s, obj = Record.parse(data)
            data = data[s:]
            print(dir, obj)

if __name__ == '__main__':
    main()
