import setuptools, shutil, re
from os import path
from hashlib import sha256
from distutils.core import setup, Extension

this_directory = path.abspath(path.dirname(__file__))

# read the contents of README file
with open(path.join(this_directory, 'README.md')) as f:
    long_description = f.read()

# generate functions to add constants to module from system header files
def make_constants(header, prefix, regex):
    warn = '/* XXX This file is automatically generated by setup.py! */'
    hfile = '/usr/include/' + header
    out = path.join(this_directory, 'nflogconst%s.cc' % prefix)
    if path.isfile(hfile):
        # get checksum of header file
        with open(hfile, 'rb') as f:
            cksum = sha256(f.read()).hexdigest()

        # if checksum matches, don't regenerate
        if path.isfile(out):
            with open(out) as f:
                for line in f.readlines():
                    if cksum in line:
                        return None

        # generate lines of output file
        r = re.compile(regex)
        with open(hfile) as h:
            output = [
                warn,
                '/* %s */' % cksum,
                '#include <Python.h>',
                '#include <%s>' % header,
                '#include "nflogconst.h"',
                'int nflog_add_%ss(PyObject *m) {' % prefix,
                '  if (!m) { return -1; }'
            ]
            for line in h.readlines():
                m = r.match(line)
                if m:
                    tup = (prefix.upper(), m.group(1), m.group(2))
                    output.append('  ADDINTCONST(m, "%s_%s", %s);' % tup)
            output.append('  return 0;\n}')

        # actually write output file
        with open(out, 'w') as f:
            f.writelines(map(lambda x: x+'\n', output))
    else:
        # fall back to pregenerated file if header can't be found
        with open(path.join(this_directory, 'nflogconst%s_def.cc' % prefix)) as i:
            with open(out, 'w') as o:
                o.write(warn+'\n')
                o.writelines(i.readlines())

make_constants('linux/if_arp.h', 'hwtype', r'.+ARPHRD_(\S+)\s+(\S+).*')
make_constants('linux/if_ether.h', 'proto', r'.+ETH_P_(\S+)\s+(\S+).*')

setup(
    name="nflogr",
    version='0.0.3',
    description='An object-oriented Python interface to read data via NFLOG',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Ryan Castellucci',
    author_email='pypi-b51f@ryanc.org',
    license='MIT',
    url='https://github.com/ryancdotorg/python-nflogr',
    ext_modules=[Extension(
        name="nflogr",
        sources=[
            "nflogr.cc", "nflog.cc", "nflogdata.cc",
            "nflogconstproto.cc", "nflogconsthwtype.cc",
        ],
        libraries=["netfilter_log", "nfnetlink"]
    )],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: C',
        'Programming Language :: C++',
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
