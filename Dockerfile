# Stage 1: Building
FROM alpine:3.10.2 AS build
# Build tools
RUN apk add --no-cache git g++ make cmake
# Build SEAL & spsl
RUN mkdir /building && cd /building && \
    git clone --single-branch --branch 3.3.1 https://github.com/microsoft/SEAL.git && cd SEAL/native/src && \
    cmake . && make -j8 && cd /building && \
    git clone https://github.com/secure-pprl/secure-p-signature-linkage.git && \
    cd secure-p-signature-linkage/ && \
    CPPFLAGS='-isystem /building/SEAL/native/src' LIBSEAL_PATH=/building/SEAL/native/lib/libseal.a make -j8

# Stage 2: Deployment
FROM alpine:3.10.2 AS deploy
# Library packages required for running
RUN apk add --no-cache python3 py3-cffi py3-numpy libstdc++ libgomp
# Brings over essential SEAL source and SPPRL systems
COPY --from=build /building/SEAL/native/src/seal /building/SEAL/native/src/seal
COPY --from=build /building/secure-p-signature-linkage /building/secure-p-signature-linkage
# Move items into place
RUN cd /building/secure-p-signature-linkage && \
    cp secure-linkage /usr/local/bin && cp libseclink.so /usr/local/lib && \
    cp seclink.py /opt

# Sets Non-Root user for running instances after image setup
RUN addgroup -S spprlgroup && adduser -S pprluser -G spprlgroup
USER pprluser

# Final touches
WORKDIR /opt
CMD ["python3", "-ic", "import seclink;  seclink.run_test(log = print)"]
