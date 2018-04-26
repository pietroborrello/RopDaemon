#!/usr/bin/env python

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2018, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"


from setuptools import setup

VER = "1.0.0"

setup(
    name='ropd',
    version=VER,
    license=__license__,
    description='ropd gadget compiling library',
    author=__author__,
    author_email=__email__,
    url='https://github.com/pietroborrello/Ropd',
    download_url = 'https://github.com/pietroborrello/Ropd/archive/' + VER + '.tar.gz',
    package_dir={'ropd': 'ropd'},
    packages=['ropd'],
    install_requires=[
            'capstone',
            'ropper',
            'enum34',
            'unicorn',
            'tqdm',
            'ipdb',
            'angr'
    ]
)