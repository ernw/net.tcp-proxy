#!/usr/bin/env python2
# encoding: utf-8
# Copyright 2016 Timo Schmid
from __future__ import print_function, unicode_literals, absolute_import

import warnings
from io import BytesIO, StringIO
from binascii import a2b_hex
from collections import defaultdict

from wcf.records import Record, print_records
from wcf.datatypes import MultiByteInt31, Utf8String
from wcf.dictionary import dictionary
from .nmf import Record as NMFRecord, register_types

try:
    import pygments
    import pygments.lexers
    import pygments.formatters
except ImportError:
    warnings.warn('Pygments not found, no syntax highlighting available')
    pygments = None


old_dictionary = dictionary.copy()
dictionary_cache = defaultdict(dict)


def build_dictionary(fp, key):
    size = MultiByteInt31.parse(fp).value
    print("Dictionary table: {} bytes".format(size))
    table_data = fp.read(size)
    table = BytesIO(table_data)

    idx = 1
    while table.tell() < size:
        string = Utf8String.parse(table)
        assert idx not in dictionary_cache[key]
        dictionary_cache[key][idx] = string.value
        idx += 2
    dictionary.clear()
    dictionary.update(old_dictionary)
    dictionary.update(dictionary_cache[key])

    for idx, value in dictionary_cache[key].items():
        print('{}: {}'.format(idx, value))
    return dictionary_cache[key]


def parse(data, key):
    fp = BytesIO(data)
    build_dictionary(fp, key)
    records = Record.parse(fp)
    out = StringIO()
    print_records(records, fp=out)
    out.seek(0)

    if pygments is not None:
        print(pygments.highlight(out.read(),
                                 pygments.lexers.get_lexer_by_name('XML'),
                                 pygments.formatters.get_formatter_by_name('terminal')))
    else:
        print(out.read())


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('TRACE_FILE', type=argparse.FileType('r'))

    args = parser.parse_args()
    register_types()

    with args.TRACE_FILE as fp:
        for line in fp:
            parse_line(line)


def parse_line(line):
    parts = line.strip().split('\t')
    if len(parts) == 2:
        timestamp, connection, dir, data = ['0000-00-00 00:00:00', '?'] + parts
    else:
        timestamp, connection, dir, data = parts

    data = a2b_hex(data)

    while data:
        s, obj = NMFRecord.parse(data)
        data = data[s:]
        header = "[{}] {{{}}} {}".format(timestamp, connection, dir)
        print(header)
        print("#" * len(header))
        print(obj)
        if obj.code == 6:
            print()
            parse(obj.Payload, (connection, dir))
        print()

if __name__ == '__main__':
    main()
