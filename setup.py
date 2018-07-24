from setuptools import setup, find_packages

setup(
    name='dellhelper',
    version='0.1',
    author='Lars Kellogg-Stedman',
    author_email='lars@oddbit.com',
    url='https://github.com/larsks/dellhelper',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'dellhelper = dellhelper.commands:main',
        ],
    }
)
