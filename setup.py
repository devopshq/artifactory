#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import os

__version__ = "0.7"
devStatus = "4 - Beta"  # default build status, see: https://pypi.python.org/pypi?%3Aaction=list_classifiers
build_prefix = "dev"


def get_branch():
    if "CIRCLE_BRANCH" in os.environ:
        build_branch = os.getenv("CIRCLE_BRANCH")
        build_number = os.getenv("CIRCLE_BUILD_NUM")
        ci_builder = "Circle CI"
    else:
        build_branch = os.getenv("TRAVIS_BRANCH")
        build_number = os.getenv("TRAVIS_BUILD_NUMBER")
        ci_builder = "Travis CI"

    print("This is {} build".format(ci_builder))
    print("Branch: {}".format(build_branch))
    print("Build number: {}".format(build_number))
    return build_branch, build_number, ci_builder


if "TRAVIS_BRANCH" in os.environ or "CIRCLE_BRANCH" in os.environ:
    branch, build_id, builder = get_branch()
    if "release" in branch or branch == "master":
        build_prefix = ""
        devStatus = "5 - Production/Stable"
    __version__ += ".{}{}".format(build_prefix, build_id)
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
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Filesystems",
    ],
    url="https://devopshq.github.io/artifactory/",
    download_url="https://github.com/devopshq/artifactory",
    install_requires=[
        "requests",
        "python-dateutil",
        "PyJWT",
    ],
    zip_safe=False,
    package_data={"": ["README.md"]},
    packages=["dohq_artifactory"],
)
