#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
import re

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


# PyPi RST variant doesn't understand the 'code' tag. so replacing it
# with a regular quote
def rst_strip_code_tag(string):
    return re.sub('^\\.\\. code:: .*', '::', string, flags=re.MULTILINE)


# Utility function to read the README file.
# To upload to PyPi, you need to have 'pypandoc'.
# Otherwise the readme will be clumsy.
def convert_rst():
    return lambda fname: rst_strip_code_tag(
        convert(os.path.join(os.path.dirname(__file__), fname), 'rst'))


def read_md():
    return lambda fname: open(os.path.join(os.path.dirname(__file__), fname), 'r').read()


try:
    from pypandoc import convert
    read_md = convert_rst()

except ImportError:
    print("warning: pypandoc module not found, could not convert Markdown to RST")
    read_md = read_md()


setup(
    name='dohq_artifactory',
    version='0.1.18',
    py_modules=['artifactory'],
    license='MIT License',
    description='A Python to Artifactory interface',
    long_description=read_md('README.md'),
    author='Konstantin Nazarov',
    author_email='knazarov@parallels.com',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Filesystems',
    ],
    url='https://devopshq.github.io/artifactory/',
    download_url='https://github.com/devopshq/artifactory',
    install_requires=['pathlib', 'requests', 'python-dateutil'],
    zip_safe=False,
    package_data={'': ['README.md']}
)
