FROM python:3.11-alpine

LABEL authors="Santiago Arias"

# --- Environment Setup ---
ENV PYTHONUNBUFFERED=1
ENV LD_LIBRARY_PATH="/opt/oqs/lib"
ENV PYTHONPATH="/app"

WORKDIR /app

# --- Install only required system dependencies ---
RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    git \
    gmp-dev \
    openssl-dev \
    libffi-dev \
    linux-headers

# --- Build liboqs from source (minimal installation) ---
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /opt/liboqs \
    && cd /opt/liboqs && mkdir build && cd build \
    && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/opt/oqs -DBUILD_SHARED_LIBS=ON .. \
    && ninja install \
    && ln -s /opt/oqs/lib/liboqs.so /usr/lib/liboqs.so

# --- Copy project ---
COPY . .

# --- Install Python packages ---
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install ./Crypto/py-fhe \
    && pip install waitress

# --- Set startup script ---
RUN chmod +x dockerstart.sh

EXPOSE 5000
CMD ["./dockerstart.sh"]
