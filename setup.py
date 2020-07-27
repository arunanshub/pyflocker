from setuptools import setup, find_packages


setup(
    name='PyFLocker',

    version='0.1.0',
    author="Arunanshu Biswas",
    author_email="mydellpc07@gmail.com",

    packages=find_packages(),

    description="Python Cryptographic (File Locking) Library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license='MIT License',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
    ],

    install_requires=[
        "cryptography",
        # for best case: we don't want python to
        # ignore an older Crypto library and later
        # this library raises errors!
        "pycryptodomex",
    ],
    url="https://github.com/arunanshub/pyflocker",
)
