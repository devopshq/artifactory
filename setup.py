#!/usr/bin/env python

import seqno

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

requires = ['pathlib', 'dateutil']

setup(
    name='artifactory',
    version='0.1',
    description='Artifactory interface library',
    long_description=open('README.md').read(),
    author='Konstantin Nazarov',
    author_email='knazarov@parallels.com',
    url='http://parallels.com/',
    packages=[],
    install_requires=requires,
    license=open('LICENSE').read(),
    zip_safe=False
)
