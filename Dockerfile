FROM alpine:latest

RUN apk add --no-cache python3 py3-cffi py3-numpy
RUN apk add --no-cache git g++ make cmake && \
    mkdir -p /opt/src && \
    cd /opt/src && \
    git clone https://github.com/microsoft/SEAL.git && \
    cd SEAL/native/src && \
    cmake . && \
    make -j8 && \
    cd /opt/src && \
    git clone https://github.com/secure-pprl/secure-p-signature-linkage.git && \
    cd secure-p-signature-linkage/ && \
    CPPFLAGS='-isystem /opt/src/SEAL/native/src' LIBSEAL_PATH=/opt/src/SEAL/native/lib/libseal.a make && \
    cp secure-linkage /usr/local/bin && \
    cp libseclink.so /usr/local/lib && \
    cp seclink.py /opt && \
    cd /opt && \
    rm -fr src && \
    apk del git make cmake

WORKDIR /opt
CMD ["python3", "-ic", "import seclink;  seclink.run_test(log = print)"]
