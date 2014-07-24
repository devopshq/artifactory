#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='artifactory',
    version='0.1',
    py_modules=['artifactory'],
    license='MIT License',
    description='A Python to Artifactory interface',
    long_description=open('README.md').read(),
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
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Filesystems',
    ],
    url='http://github.com/parallels/artifactory',
    download_url='http://github.com/parallels/artifactory',
    install_requires=['pathlib', 'requests', 'python-dateutil'],
    zip_safe=False
)
