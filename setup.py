from setuptools import setup, find_packages


setup(
    name='PyFLocker',

    version='0.1.0',
    author="Arunanshu Biswas",
    author_email="mydellpc07@gmail.com",

    packages=find_packages(),

    description="File Locking library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license='MIT License',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],

    url="https://github.com/arunanshub/pyflocker",
)
