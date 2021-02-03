#!/usr/bin/env python3

__author__ = "Pietro Borrello"
__copyright__ = "Copyright 2021, ROPD Project"
__license__ = "BSD 2-clause"
__email__ = "pietro.borrello95@gmail.com"


from setuptools import setup

VER = "1.0.0"

setup(
    name='ropd',
    version=VER,
    license=__license__,
    description='RopDaemon: gadget compiling tool',
    author=__author__,
    author_email=__email__,
    url='https://github.com/pietroborrello/RopDaemon',
    download_url = 'https://github.com/pietroborrello/RopDaemon/archive/' + VER + '.tar.gz',
    package_dir={'ropd': 'ropd'},
    packages=['ropd'],
    install_requires=[
            'capstone',
            'ropper',
            'enum34',
            'unicorn',
            'tqdm',
            'ipdb',
            'angr',
            'lief',
            'networkx'
    ],
    entry_points={
        'console_scripts': [
            'ropd = ropd.ropcli:main'
        ]
    },
)