#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import os


__version__ = "0.7"
devStatus = "4 - Beta"  # default build status, see: https://pypi.python.org/pypi?%3Aaction=list_classifiers

if "TRAVIS_BUILD_NUMBER" in os.environ and "TRAVIS_BRANCH" in os.environ:
    print("This is TRAVIS-CI build")
    print("TRAVIS_BUILD_NUMBER = {}".format(os.environ["TRAVIS_BUILD_NUMBER"]))
    print("TRAVIS_BRANCH = {}".format(os.environ["TRAVIS_BRANCH"]))

    __version__ += ".{}{}".format(
        ""
        if "release" in os.environ["TRAVIS_BRANCH"]
        or os.environ["TRAVIS_BRANCH"] == "master"
        else "dev",
        os.environ["TRAVIS_BUILD_NUMBER"],
    )

    if (
        "release" in os.environ["TRAVIS_BRANCH"]
        or os.environ["TRAVIS_BRANCH"] == "master"
    ):
        devStatus = "5 - Production/Stable"

    else:
        devStatus = devStatus

else:
    print("This is local build")
    __version__ += ".dev0"  # set version as major.minor.localbuild if local build: python setup.py install


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
        "Development Status :: {}".format(devStatus),
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Filesystems",
    ],
    url="https://devopshq.github.io/artifactory/",
    download_url="https://github.com/devopshq/artifactory",
    install_requires=['pathlib ; python_version<"3.4"', "requests", "python-dateutil"],
    zip_safe=False,
    package_data={"": ["README.md"]},
    packages=["dohq_artifactory"],
)
