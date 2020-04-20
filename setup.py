#!/usr/bin/env python3

from setuptools import setup


with open("README.md", "r") as fh:
    long_description = fh.read()


setup(name='jitsi-monitor',
      version='0.1',
      description='Monitor public Jitsi Meet instances',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='Guardian Project',
      url='https://guardianproject.info',
      license='Apache-2.0',
      scripts=['jitsi-monitor.py'],
      python_requires='>=3.4',
      install_requires=[
          'bs4',
          'json2html',
          'lxml',
          'PyYAML',
          'requests >= 2.5.2, != 2.11.0, != 2.12.2, != 2.18.0',
      ],
      classifiers=[
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'Intended Audience :: System Administrators',
          'Intended Audience :: Telecommunications Industry',
          'Operating System :: POSIX',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Unix',
          'Topic :: Utilities',
      ],
      )
