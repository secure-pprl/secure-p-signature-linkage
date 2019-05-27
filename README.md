# secure-p-signature-linkage

This code currently demonstrates secure matrix multiplication using
the systolic matrix encoding. It is based on
[SEAL](https://github.com/Microsoft/SEAL).


## Prerequisites

The only prerequisite is [SEAL](https://github.com/Microsoft/SEAL).
Build that according to the instructions. You do not need to `make
install` it unless you want to for other purposes. In any case, make a
note of the location of the `libseal.a` library. If it is not located
at `/usr/local/lib/libseal.a`, then set the environment variable
`LIBSEAL_PATH` to the actual path when calling `make` below.


## Building

To build, you need a C++ compiler with support for C++17, OpenMP and
PThreads. This is the case for any modern version of GCC or Clang. To
build, simply run
```
$ make
```
or, if your `libseal.a` is in a non-default location,
```
$ LIBSEAL_PATH=path/to/libseal.a make
```

## Running

The build process produces a shared library `libseclink.so` and an
executable file `secure-linkage`. The easiest way to use the library
is via the Python interface. One proceeds as follows. Run your
favourite Python interpreter in the build directory and set the load
library path at the same time:
```
$ LD_LIBRARY_PATH=. python3
Python 3.6.7 (default, Oct 22 2018, 11:32:17)
[GCC 8.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>
```
Now load the library and run the test function:
```
>>> import seclink
Loaded lib <cffi.api._make_ffi_library.<locals>.FFILibrary object at 0x7fdfec1efb00>
>>> seclink.run_test(log = print)
creating context... 103.6ms
generating keys... 1727.1ms
encrypting 2048x512 left matrix... 567.9ms
encrypting 512x2 right matrix... 1.2ms
multiplying encrypted matrices... 4597.8ms
decrypting 2048x2 product matrix... 11.1ms
result is correct?  True
True
>>>
```
Have a look at
[seclink.py](https://github.com/secure-pprl/secure-p-signature-linkage/blob/master/seclink.py#L160)
to see what is happening here. You can pass different matrix dimensions to `run_test(...)`
to see the effect on the run time.

You can also run the `secure-linkage` program from the build directory
which is very similar to the Python function above. It produces the
following output
```
$ ./secure-linkage
/ Encryption parameters:
| scheme: BFV
| poly_modulus_degree: 4096
| coeff_modulus size: 109 bits
| plain_modulus: 40961
\ noise_standard_deviation: 3.2

encrypting left...
encrypting right...
multiplying...
decrypting...
cleaning up...
```
See [here](https://github.com/secure-pprl/secure-p-signature-linkage/blob/master/secure-linkage.cc#L114)
for what the code is doing.
