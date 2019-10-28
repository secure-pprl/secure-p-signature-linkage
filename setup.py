from setuptools import setup, Extension, find_packages
import os
from glob import glob

try:
    from Cython.Build import cythonize, build_ext
except ImportError:
    # No Cython but we may have pre-converted the files
    maybe_cythonize = lambda x: x
    cython_cpp_ext = 'cc'

here = os.path.abspath(os.path.dirname(__file__))

requirements = [
        "bitarray>=0.8.1",
        "cffi>=1.7",
        "numpy>=1.14",
        "mypy-extensions>=0.3",
        "Cython>=0.29.10"
    ]

#extensions = [Extension(
#    name="_secure_thingy",
#    sources=["_cffi_build/seclink.cc", "_cffi_build/encrypt.cc",
#             "_cffi_build/decrypt.cc", "_cffi_build/multiply.cc",
#             "_cffi_build/secure-linkage.cc", "_cffi_build/memstream.cc"],
#    include_dirs=["_cffi_build/"],
#    language="c++",
#    extra_compile_args=['-Wall', '-Wextra', '-O3', '-std=gnu++17'],
#    extra_link_args=["-std=gnu++17"],
#    define_macros=[('NDEBUG', None)]
#    )]


setup(
    name="seclink",
    version='0.1.0',
    description='Nope',
    setup_requires=["cffi>=1.7"],
    install_requires=requirements,
    packages=find_packages(exclude=[
        '_cffi_build', '_cffi_build/*']),
    package_data={'seclink': ['_cffi_build/']},
#    ext_modules=maybe_cythonize(extensions),
#    ext_modules = [Extension('_cffi_build', glob('_cffi_build/*.cc') + glob('_cffi_build/*.h'))],
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
    #headers=["_cffi_build/memstream.h"]
)
