#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


__version__ = '0.3'  # identify main version of dohq-artifactory

if 'TRAVIS_BUILD_NUMBER' in os.environ and 'TRAVIS_BRANCH' in os.environ:
    print("This is TRAVIS-CI build")
    print("TRAVIS_BUILD_NUMBER = {}".format(os.environ['TRAVIS_BUILD_NUMBER']))
    print("TRAVIS_BRANCH = {}".format(os.environ['TRAVIS_BRANCH']))

    __version__ += '.{}{}'.format(
        '' if 'release' in os.environ['TRAVIS_BRANCH'] or os.environ['TRAVIS_BRANCH'] == 'master' else 'dev',
        os.environ['TRAVIS_BUILD_NUMBER'],
    )

else:
    print("This is local build")
    __version__ += '.localbuild'  # set version as major.minor.localbuild if local build: python setup.py install

print("dohq-artifactory build version = {}".format(__version__))

setup(
    name='dohq-artifactory',
    version=__version__,
    py_modules=['artifactory'],
    license='MIT License',
    description='A Python interface to Artifactory',
    long_description='See full documentation here: https://devopshq.github.io/artifactory/',
    author='Alexey Burov',
    author_email='aburov@ptsecurity.com',
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
    install_requires=[
        'pathlib',
        'requests',
        'python-dateutil'
    ],
    zip_safe=False,
    package_data={'': ['README.md']},
    packages=[
        'dohq_artifactory',
    ]
)
