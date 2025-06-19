FROM python:3.11-slim

LABEL authors="Santiago Arias, Alfonso González-Lamuño"

ENV \
  PYTHONUNBUFFERED=1 \
  LD_LIBRARY_PATH="/opt/oqs/lib" \
  OQS_INSTALL_PATH="/opt/oqs"

WORKDIR /app

# 1) system deps + pip
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git \
      libgmp-dev libssl-dev libffi-dev \
      python3-dev python3-pip \
    && rm -rf /var/lib/apt/lists/*

# 2) Build liboqs
RUN git clone --branch 0.12.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git /opt/liboqs \
 && cd /opt/liboqs && mkdir build && cd build \
 && cmake -GNinja .. \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_ENABLE_KEMS=ON \
      -DOQS_ENABLE_KEM_BIKE=ON \
      -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=ON \
      -DOQS_ENABLE_KEM_HQC=ON \
      -DOQS_ENABLE_KEM_KYBER=ON \
      -DOQS_ENABLE_KEM_NTRU=ON \
      -DOQS_ENABLE_KEM_NTRUPRIME=ON \
      -DOQS_ENABLE_KEM_SABER=ON \
      -DOQS_ENABLE_SIGS=OFF \
 && ninja install \
 && ln -sf /opt/oqs/lib/liboqs.so /usr/lib/liboqs.so

# 3) Install matching Python binding for v0.12.0
RUN python3 -m pip install --upgrade pip \
 && python3 -m pip install --no-cache-dir \
      git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0
# 4) copy & install your app
COPY . /app
RUN python3 -m pip install --no-cache-dir -r requirements.txt \
 && python3 -m pip install --no-cache-dir ./Crypto/py-fhe waitress

# 5) entrypoint
RUN chmod +x dockerstart.sh
EXPOSE 5000
CMD ["./dockerstart.sh"]