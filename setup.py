#!/usr/bin/env python

from distutils.core import setup

setup(name='nettcp',
      version='1.0',
      description='Python Library to interact with net.tcp webservices',
      author='Timo Schmid',
      author_email='tschmid@ernw.de',
      url='https://www.insinuator.net/?p=7513',
      packages=['nettcp'],
      scripts=[
        'scripts/decode-nmf.py',
        'scripts/decode-wcfbin.py',
        'scripts/nettcp-proxy.py',
      ]
      )
