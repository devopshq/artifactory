#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

__version__ = '0.4.105'  # identify main version of dohq-artifactory

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
