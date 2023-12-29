import setuptools

with open('README.md') as f:
    data = f.read()

setuptools.setup(
    name='pyckb',
    version='0.1.1',
    url='https://github.com/mohanson/pyckb',
    license='MIT',
    author='Mohanson',
    author_email='mohanson@outlook.com',
    description='Python SDK for CKB',
    packages=['ckb'],
    long_description=data,
    long_description_content_type='text/markdown',
    install_requires=[
        'requests',
        'pytest'
    ],
)
