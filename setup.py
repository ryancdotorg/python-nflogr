import re, setuptools, shutil

from pathlib import Path
from hashlib import sha256
from distutils.core import Extension
from distutils.command.build_ext import build_ext

here = Path(__file__).parent
root = here.resolve().root
gen = Path(here, 'gen')

# read the contents of README file
with open(Path(here, 'README.md')) as f:
    long_description = f.read()

pkg_attrs = dict(
    name='nflogr',
    version='0.2.8',
    description='An object-oriented Python interface to read data via NFLOG',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Ryan Castellucci',
    author_email='pypi-b51f@ryanc.org',
    license='MIT',
    url='https://github.com/ryancdotorg/python-nflogr',
    ext_modules=[Extension(
        name='nflogr',
        sources=[
            'nflogr.cc', 'nflog.cc', 'nflogdata.cc', 'nflogopt.cc',
            str(Path(gen, 'nflogconstproto.cc')),
            str(Path(gen, 'nflogconsthwtype.cc')),
        ],
        libraries=['netfilter_log', 'nfnetlink'],
    )],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: C',
        'Programming Language :: C++',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
        'Topic :: Communications',
        'Topic :: Internet :: Log Analysis',
        'Topic :: System :: Networking :: Monitoring'
    ],
    keywords='nflog linux',
    platforms=['linux'],
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
)

# give an escaped representation of a `str`, `bytes` or `Iterable[int]` value
def c_str(s):
    out = '' # see https://w.wiki/34HP
    escape = {8: 98, 9: 116, 10: 110, 13: 114, 34: 34, 39: 39, 63: 63, 92: 92}
    if isinstance(s, str): s = map(ord, s)
    for n in s:
        if n in escape:   out += f'\\{escape[n]:c}'
        elif n <=   0x1f: out += f'\\{n:o}'
        elif n <=   0x7e: out += f'{n:c}'
        elif n <=   0xff: out += f'\\x{n:02x}'
        elif n <= 0xffff: out += f'\\u{n:04x}'
        else:             out += f'\\U{n:08x}'

    return f'"{out}"'

# generate functions to add constants to module from system header files
def make_constants(log, header, prefix, regex):
    warn = '/* XXX This file is automatically generated by setup.py! */'
    hfile = Path(root, 'usr', 'include', header)
    outfile = Path(gen, f'nflogconst{prefix}.cc')
    if not outfile.parent.exists():
        log.info(f'creating {outfile.parent}')
        outfile.parent.mkdir()

    if hfile.is_file():
        # get checksum of header file
        with open(hfile, 'rb') as f:
            cksum = sha256(f.read()).hexdigest()

        # if checksum matches, don't regenerate
        if outfile.is_file():
            with open(outfile) as f:
                for line in f.readlines():
                    if cksum in line:
                        return None

        # generate lines of output file
        r = re.compile(regex)
        with open(hfile) as h:
            lines = [
                warn,
                f'/* {cksum} */',
                '#include <Python.h>',
                f'#include <{header}>',
                f'int nflog_add_{prefix}s(PyObject *m) {{',
                '  if (!m) { return -1; }'
            ]

            for line in h.readlines():
                m = r.match(line)
                if m:
                    (x, y, z) = (prefix.upper(), m.group(1), m.group(2))
                    lines.append(f'  if (PyModule_AddIntConstant(m, "{x}_{y}", {z}) != 0) {{ return -1; }}')

            lines.append('  return 0;\n}')

        # actually write output file
        log.info(f'generating {outfile} from {hfile}')
        with open(outfile, 'w') as f:
            f.writelines(map(lambda x: x+'\n', lines))
    else:
        # fall back to pregenerated file if header can't be found
        infile = Path(here, f'{prefix}_def.cc')
        log.info(f'generating {outfile} from {infile}')
        with open(infile) as i:
            with open(outfile, 'w') as o:
                o.write(warn+'\n')
                o.writelines(i.readlines())

def _git():
    import re, time
    from subprocess import check_output, run, DEVNULL

    class git(object):
        @staticmethod
        def is_clean():
            try:
                r = run(['git', 'diff', '--quiet'], stderr=DEVNULL).returncode
                if r == 0:   return True
                elif r == 1: return False
            except FileNotFoundError:
                pass

            return None

        def build_info(version):
            clean = git.is_clean()
            if clean is True:
                tag = git.get_tag()
                if tag == version:
                    return ''
                elif tag:
                    raise ValueError(f'tag `{tag}` does not match module version `{version}`')

                return '+{}.{}.{}'.format(git.get_ct(), git.get_br(), git.get_ci())
            elif clean is False:
                return '+{}.{}.{}'.format(git.get_ts(), git.get_br(), 'dirty')
            else:
                return ''

        def get_tag():
            p = run(
                ['git', 'describe', '--exact-match', '--tags'],
                capture_output=True, encoding='utf-8'
            )
            if p.returncode == 0:
                return re.sub(r'^v', '', p.stdout.strip())

            return None

        def get_br():
            return check_output(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                encoding='utf-8'
            ).strip()

        def get_ci():
            return check_output(
                ['git', 'rev-parse', '--short', 'HEAD'],
                encoding='utf-8'
            ).strip()

        def get_ct():
            return check_output(
                ['git', 'show', '-s', '--date=format-local:%Y%m%d%H%M%S', '--format=%cd'],
                encoding='utf-8'
            ).strip()

        def get_ts():
            return time.strftime('%Y%m%d%H%M%S', time.gmtime())

    return git

git = _git()

# wrapper around distutils.setup that injects some compiler arguments
def setup(**attrs):
    import distutils, json, time, types

    attrs['version'] += git.build_info(attrs['version'])
    cmd = attrs.setdefault('cmdclass', {})

    class push(distutils.cmd.Command):
        user_options = []

        def initialize_options(self):
            pass

        def finalize_options(self):
            pass

        def run(self):
            from subprocess import check_call

            if git.is_clean() is True and git.get_tag() == attrs['version']:
                check_call(['git', 'push'])
                check_call(['git', 'push', '--tags'])
                check_call([
                    'twine', 'upload', '--repository', 'pypi',
                    'dist/{name}-{version}.tar.gz'.format(**attrs)
                ])
            else:
                raise ValueError('can only push from cleanly tagged repo')

    class build_ext(cmd.get('build_ext', distutils.command.build_ext.build_ext)):
        def run(self):
            make_constants(distutils.log, 'linux/if_arp.h', 'hwtype', r'.+ARPHRD_(\S+)\s+(\S+).*')
            make_constants(distutils.log, 'linux/if_ether.h', 'proto', r'.+ETH_P_(\S+)\s+(\S+).*')

            prefix = re.sub('[^A-Z0-9_]', '_', attrs['name'].upper())
            # https://filippo.io/instance-monkey-patching-in-python/
            _build_extension = self.build_extension
            def build_extension(self, ext):
                if not isinstance(getattr(ext, 'extra_compile_args', 0), list):
                    setattr(ext, 'extra_compile_args', [])

                ext.extra_compile_args.extend([
                    f'-D{prefix}_DEBUG=' + str(self.debug or 0),
                    f'-D{prefix}_META=' + c_str(json.dumps({
                        '__build_debug__':  bool(self.debug),
                        '__title__':        attrs['name'],
                        '__description__':  attrs['description'],
                        '__url__':          attrs['url'],
                        '__version__':      attrs['version'],
                        '__author__':       attrs['author'],
                        '__author_email__': attrs['author_email'],
                        '__license__':      attrs['license'],
                    }, ensure_ascii=False, separators=(',', ':'))),
                ])

                _build_extension(ext)

            self.build_extension = types.MethodType(build_extension, self)
            super().run()

    cmd['build_ext'] = build_ext
    cmd['push'] = push
    return distutils.core.setup(**attrs)

setup(**pkg_attrs)
