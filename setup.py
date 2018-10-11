import os

from setuptools import setup

import gummy

long_description = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

setup(
    name='gummy',
    version=gummy.__version__,
    description='Automated LAN scanner based on masscan and nmap',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Vladimir Yarmiychuk',
    author_email='yarmiychuk@protonmail.com ',
    url='https://github.com/v-yar/gummy',
    keywords=['security'],
    install_requires=[
        'prompt_toolkit>2.0',
        'prettytable',
        'colorama',
        'objectpath',
        'jsonmerge',
        'jsonschema',
        'psutil',
        'pytz'
    ],
    entry_points={
        'console_scripts': [
            'gummy = gummy.entry_points.gummy_run:run'
        ]},

    packages=['gummy',
              'gummy.tools',
              'gummy.modules',
              'gummy.entry_points'],
    package_data={'gummy': ['data/ManPortRating.csv',
                            'data/PortDescription.csv',
                            'data/NmapPortRating.csv',
                            'data/StatPortRating.csv']},
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
    ]
)
