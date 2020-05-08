from setuptools import setup, find_packages

setup(
    name='PyFLocker',

    version='0.1.0',
    author="Arunanshu Biswas",
    author_email="mydellpc07@gmail.com",

    packages=find_packages(),
    license='MIT License',

    description="File Locking library",
    long_description=open("README.md").read(),

    url="https://github.com/arunanshub/pyflocker",
)

