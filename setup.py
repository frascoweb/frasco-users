from setuptools import setup, find_packages


def desc():
    with open("README.md") as f:
        return f.read()


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
    install_requires=[
        'frasco',
        'frasco-forms',
        'frasco-models',
        'Flask-Login==0.2.11',
        'Flask-Bcrypt==0.6.0',
        'Flask-OAuth==0.12'
    ]
)