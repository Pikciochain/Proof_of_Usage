# coding: utf-8

from setuptools import setup, find_packages

with open('requirements.txt', 'r') as fin:
    requires = [line for line in fin if not line.startswith(
        '-i')]  # Excepted index instructions lines.

setup(
    name="proof-of-usage",
    version='version='0.1.0'',
    description="Proof of Usage Consensus",
    author='Thibault Drevon',
    author_email="thibault@yellowstones.io",
    url='https://pikciochain.com',
    keywords=["Blockchain", "Proof", "Usage", "Pikcio"],
    install_requires=requires,
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    packages=find_packages(),
    test_suite='tests'
)
