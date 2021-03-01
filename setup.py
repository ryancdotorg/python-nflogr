import setuptools, shutil, re
from distutils.core import setup, Extension

from os import path
this_directory = path.abspath(path.dirname(__file__))

# read the contents of README file
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# generate functions to add constants to module from system header files
def make_constants(header, prefix, regex):
    hfile = '/usr/include/' + header
    out = path.join(this_directory, 'nflogconst%s.cc' % prefix)
    if path.isfile(hfile):
        r = re.compile(regex)
        h = open(hfile)
        output = [
            '/* XXX This file is automatically generated by setup.py! */',
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
        h.close()

        f = open(out, 'w')
        f.writelines(map(lambda x: x+'\n', output))
        f.close()
    else:
        shutil.copy2(path.join(this_directory, 'nflogconst%s_def.cc' % prefix), out)

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
