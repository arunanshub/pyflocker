from setuptools import find_packages, setup

setup(
    name="PyFLocker",
    version="0.3.1",
    author="Arunanshu Biswas",
    author_email="mydellpc07@gmail.com",
    packages=find_packages(exclude=["tests"]),
    description="Python Cryptographic (File Locking) Library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license="MIT License",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=2.7",
        # for best case: we don't want python to
        # ignore an older Crypto library and later
        # this library raises errors!
        "pycryptodomex>=3.9.8",
    ],
    url="https://github.com/arunanshub/pyflocker",
)
