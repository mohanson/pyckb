import setuptools

setuptools.setup(
    name='ckb',
    version='0.1.0',
    url='https://github.com/mohanson/pyckb',
    license='MIT',
    author='Mohanson',
    author_email='mohanson@outlook.com',
    description='Python SDK for CKB',
    packages=['ckb'],
    install_requires=[
        'requests'
    ],
)
