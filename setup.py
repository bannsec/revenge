# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
import os, sys, ast

here = os.path.abspath(os.path.dirname(__file__))
version = '0.6'

#with open(path.join(here, 'README.md'), encoding='utf-8') as f:
#    long_description = f.read()
long_description = "See website for more info."

setup(
    name='frida-util',
    version=version,
    description='Silly python wrapper around Frida.',
    long_description=long_description,
    url='https://github.com/bannsec/frida-util',
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
    install_requires=['frida', 'prettytable', 'colorama', 'termcolor', 'psutil', 'pyelftools', 'pefile', 'appdirs', 'bs4', 'requests'],
    extras_require={
        'dev': ['ipython','twine','pytest','python-coveralls','coverage','pytest-cov','pytest-xdist','sphinxcontrib-napoleon', 'sphinx_rtd_theme','sphinx-autodoc-typehints', 'pyOpenSSL', 'numpy'],
    },
    entry_points={
        'console_scripts': [
            'frida-util = frida_util.cli.cli:main',
        ],
    },
    include_package_data = True,
)

