import os

from setuptools import setup

long_description = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

setup(
    name='gummy_scan',
    version='0.1',
    description='Automated LAN scanner based on masscan and nmap',
    long_description=long_description,
    author='Vladimir Yarmiychuk',
    author_email='evil.gummy.bear@protonmail.com',
    install_requires=[
        'prompt_toolkit',
        'prettytable',
        'colorama',
        'objectpath',
        'jsonmerge',
        'jsonschema',
        'psutil'
    ],
    entry_points={
        'console_scripts': [
            'gummy = gummy.entry_points.gummy_run:run'
        ]},
    packages=['gummy',
              'gummy.tools',
              'gummy.modules',
              'gummy.entry_points'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: Unix',
        'License :: OSI Approved :: MIT License',
        "Topic :: Security",
        "Topic :: System :: Networking",
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6'
    ],
    include_package_data=True,
    keywords=['security']
)
