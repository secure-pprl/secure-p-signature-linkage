from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

requirements = [
        "cffi>=1.7",
        "numpy>=1.14"
    ]


setup(
    name="seclink",
    version='0.1.0',
    description='Nope',
    setup_requires=["cffi>=1.7"],
    install_requires=requirements,
    packages=find_packages(exclude=[
        '_cffi_build', '_cffi_build/*']),
    package_data={'seclink': ['_cffi_build/']},
    ext_package="seclink",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Security :: Cryptography",
    ],

    # for cffi
    cffi_modules=["_cffi_build/seclink.py:ffibuilder"],
    zip_safe=False,
    include_package_data=True,
)
