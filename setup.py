from setuptools import setup, find_packages


setup(
    name='frasco-users',
    version='0.4',
    url='http://github.com/frascoweb/frasco-users',
    license='MIT',
    author='Maxime Bouroumeau-Fuseau',
    author_email='maxime.bouroumeau@gmail.com',
    description="Users management for Frasco",
    packages=find_packages(),
    package_data={
        'frasco_users': [
            'templates/users/*.html',
            'emails/users/*.txt',
            'admin/templates/admin/users/*.html']
    },
    zip_safe=False,
    platforms='any',
    install_requires=[
        'frasco',
        'frasco-forms',
        'frasco-models>=0.2',
        'Flask-Login>=0.3.0',
        'Flask-Bcrypt>=0.6.0',
        'Flask-OAuthlib>=0.9.0'
    ]
)
