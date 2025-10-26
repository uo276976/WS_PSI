# Builder
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git libgmp-dev libssl-dev libffi-dev \
      python3-dev && rm -rf /var/lib/apt/lists/*

# Build liboqs
RUN git clone --branch 0.12.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git \
 && cd liboqs && mkdir build && cd build \
 && cmake -GNinja .. \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_ENABLE_SIGS=OFF \
      -DOQS_ENABLE_KEM_BIKE=ON \
      -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=ON \
      -DOQS_ENABLE_KEM_FRODOKEM=ON \
      -DOQS_ENABLE_KEM_HQC=ON \
      -DOQS_ENABLE_KEM_KYBER=ON \
      -DOQS_ENABLE_KEM_NTRU=ON \
      -DOQS_ENABLE_KEM_NTRUPRIME=ON \
 && ninja install

RUN python3 -m pip install --upgrade pip \
 && python3 -m pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git@0.12.0

# Runtime
FROM python:3.11-slim

LABEL authors="Santiago Arias, Alfonso González-Lamuño"

ENV PYTHONUNBUFFERED=1 \
    LD_LIBRARY_PATH="/opt/oqs/lib" \
    OQS_INSTALL_PATH="/opt/oqs"

WORKDIR /app

# Dependencias mínimas en tiempo de ejecución
RUN apt-get update && apt-get install -y --no-install-recommends \
      libgmp-dev libssl-dev libffi-dev \
 && rm -rf /var/lib/apt/lists/*

# Copiar binarios de liboqs y site-packages de liboqs-python
COPY --from=builder /opt/oqs /opt/oqs
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . /app

RUN python3 -m pip install --no-cache-dir -r requirements.txt \
 && python3 -m pip install --no-cache-dir ./Crypto/py-fhe waitress

RUN chmod +x dockerstart.sh
EXPOSE 5000
CMD ["./dockerstart.sh"]
