from setuptools import setup, find_packages


def desc():
    with open("README.md") as f:
        return f.read()

def reqs():
    with open('requirements.txt') as f:
        return f.read().splitlines()

setup(
    name='frasco-users',
    version='0.1',
    url='http://github.com/frascoweb/frasco-users',
    license='MIT',
    author='Maxime Bouroumeau-Fuseau',
    author_email='maxime.bouroumeau@gmail.com',
    description="Users management for Frasco",
    long_description=desc(),
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=reqs() + [
        'frasco',
        'frasco-forms',
        'frasco-models'
    ]
)