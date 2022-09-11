#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open("version.txt") as file:
    __version__ = file.readline().strip()

# check that version is correct (X.X.X or X.X.X.devXXX or X.X.X.alphaX), eg 0.8.0.dev0
assert re.match(
    r"^\d\.\d\.\d$|^\d\.\d\.\d\.dev\d+$|^\d\.\d\.\d\.alpha\d+$", __version__
)


# default build status, see: https://pypi.python.org/pypi?%3Aaction=list_classifiers
if "alpha" in __version__:
    dev_status = "3 - Alpha"
elif "dev" in __version__:
    dev_status = "4 - Beta"
else:
    dev_status = "5 - Production/Stable"


setup(
    name="dohq-artifactory",
    version=__version__,
    py_modules=["artifactory"],
    license="MIT License",
    description="A Python interface to Artifactory",
    long_description="See full documentation here: https://devopshq.github.io/artifactory/",
    author="Alexey Burov",
    author_email="aburov@ptsecurity.com",
    classifiers=[
        "Development Status :: {}".format(dev_status),
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Filesystems",
    ],
    url="https://devopshq.github.io/artifactory/",
    download_url="https://github.com/devopshq/artifactory",
    install_requires=[
        "requests",
        "python-dateutil",
        "PyJWT~=2.0",
    ],
    zip_safe=False,
    package_data={"": ["README.md"]},
    packages=["dohq_artifactory"],
)
