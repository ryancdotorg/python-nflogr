import setuptools
from distutils.core import setup, Extension

setup(
    name="nflogr",
    version='0.0.1',
    description='An object-oriented Python interface to read data via NFLOG',
    author='Ryan Castellucci',
    author_email='pypi-b51f@ryanc.org',
    license='MIT',
    url='https://github.com/ryancdotorg/python-nflogr',
    ext_modules=[Extension(
        name="nflogr",
        sources=["nflogr.cc", "nflog.cc", "nflogdata.cc"],
        libraries=["netfilter_log", "nfnetlink"]
        )],
    classifiers=[
        'Development Status :: 3 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: C',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
        'Topic :: Communications',
        'Topic :: Internet :: Log Analysis',
        'Topic :: System :: Networking :: Monitoring'
        ],
    keywords='nflog linux',
    packages=setuptools.find_packages(),
    python_requires=">=3.5",
)
