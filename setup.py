"""The setup.py script."""

import os

from setuptools import setup, Extension
from setuptools.command.build_py import build_py


class libnetfilter_build_py(build_py):

    def run(self):
        build_py.run(self)
        dest = os.path.join(
            self.build_lib,
            'libnetfilterqueue-stubs',
            '__init__.pyi',
        )
        self.mkpath(os.path.dirname(dest))
        self.copy_file('libnetfilterqueue.pyi', dest)


setup(name="python-libnetfilter-queue",
      version='0.0.1',
      description='Python wrapper for libnetfilter_queue',
      author='John Lawrence M. Penafiel',
      author_email='jonh@teamredlabs.com',
      license='BSD-2-Clause',
      url='https://github.com/teamredlabs/python-libnetfilter-queue',
      classifiers=['Development Status :: 4 - Beta',
                   'Environment :: Plugins',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: POSIX :: Linux',
                   'Programming Language :: C',
                   'Programming Language :: Python :: 2.7',
                   'Topic :: Communications',
                   'Topic :: Internet :: Log Analysis',
                   'Topic :: System :: Networking :: Monitoring'],
      keywords='libnetfilter libnetfilterqueue netfilter nfqueue',
      ext_modules=[Extension(name="libnetfilterqueue",
                             sources=["libnetfilterqueue.c"],
                             libraries=["netfilter_queue", "nfnetlink"])],
      cmdclass={'build_py': libnetfilter_build_py},
      packages=['libnetfilterqueue-stubs'],
      zip_safe=False)
