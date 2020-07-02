#!/usr/bin/env python
# coding: utf-8

# ----------------------------------------------------------------------------
# This setup.py file was adapted from the setup.py file of the repository
# jupyterhub/oathenticator on 06/10/2020.
# ----------------------------------------------------------------------------

# Copyright (c) Michael Albert.
# Distributed under the terms of the Modified BSD License.

#-----------------------------------------------------------------------------
# Minimal Python version sanity check (from IPython/Jupyterhub)
#-----------------------------------------------------------------------------
from __future__ import print_function

import os
import sys

from setuptools import setup
from setuptools.command.bdist_egg import bdist_egg

class bdist_egg_disabled(bdist_egg):
    """Disabled version of bdist_egg
    Prevents setup.py install from performing setuptools' default easy_install,
    which it should never ever do.
    """

    def run(self):
        sys.exit(
            "Aborting implicit building of eggs. Use `pip install .` to install from source."
        )

pjoin = os.path.join
here = os.path.abspath(os.path.dirname(__file__))

# Get the current package version.
version_ns = {}
with open(pjoin(here, 'SAMLAuthenticator', '_version.py')) as f:
    exec(f.read(), {}, version_ns)


setup_args = dict(
    name                = 'SAMLAuthenticator',
    packages            = ['SAMLAuthenticator'],
    version             = version_ns['__version__'],
    description         = "SAMLAuthenticator: Authenticate JupyterHub users with the SAML protocol.",
    long_description    = open("README.md").read(),
    long_description_content_type = "text/markdown",
    author              = "Michael Albert",
    author_email        = "albertmichaelj@gmail.com",
    # url                 = "https://jupyter.org",
    license             = "BSD",
    platforms           = "Linux, Mac OS X",
    keywords            = ['Interactive', 'Interpreter', 'Shell', 'Web'],
    python_requires     = ">=3.5",
    entry_points={
        'jupyterhub.authenticators': [
            'saml_authenticator = SAMLAuthenticator:SAMLAuthenticator',
        ],
    },
    classifiers         = [
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
)

setup_args['cmdclass'] = {
    'bdist_egg': bdist_egg if 'bdist_egg' in sys.argv else bdist_egg_disabled,
}

setup_args['install_requires'] = install_requires = []
with open('requirements.txt') as f:
    for line in f.readlines():
        req = line.strip()
        if not req or req.startswith(('-e', '#')):
            continue
        install_requires.append(req)


# setup_args['extras_require'] = {
#     'googlegroups': ['google-api-python-client==1.7.11', 'google-auth-oauthlib==0.4.1'],
#     'globus': ['globus_sdk[jwt]>=1.0.0,<2.0.0']
# }

def main():
    setup(**setup_args)

if __name__ == '__main__':
    main()