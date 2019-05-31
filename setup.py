# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
import os, sys, ast

here = os.path.abspath(os.path.dirname(__file__))
version = '1.0'

#with open(path.join(here, 'README.md'), encoding='utf-8') as f:
#    long_description = f.read()
long_description = "See website for more info."

setup(
    name='frida-stalk',
    version=version,
    description='Wrapper around Frida and calling it\'s Stalk functionality.',
    long_description=long_description,
    url='https://github.com/bannsec/frida-stalk',
    author='Michael Bann',
    author_email='self@bannsecurity.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console'
    ],
    keywords='frida stalker python3',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=['frida', 'frida-tools', 'prettytable', 'colorama', 'termcolor', 'psutil'],
    entry_points={
        'console_scripts': [
            'frida-stalk = frida_stalk.stalk:main',
        ],
    },
)

