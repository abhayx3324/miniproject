from setuptools import setup, find_packages

setup(
    name='kyber-py',
    version='0.1',
    packages=find_packages(where='kyber-py/src'),
    package_dir={'': 'kyber-py/src'},
)
