from setuptools import setup

with open('bsvlib/__init__.py', 'r') as f:
    for line in f:
        if line.startswith('__version__'):
            version = line.strip().split('=')[1].strip(' ').strip("'")
            break

setup(
    version=version,
)
