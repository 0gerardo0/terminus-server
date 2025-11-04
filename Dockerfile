FROM alpine:latest AS builder

RUN apk add --no-cache \
    build-base \
    cmake \
    pkgconfig \
    libsodium-dev \
    libmicrohttpd-dev \
    bash

WORKDIR /app
COPY . .

RUN rm -rf build && bash scripts/build.sh


FROM alpine:latest AS final

RUN apk add --no-cache \
    libsodium \
    libmicrohttpd \
    python3 \
    py3-cffi 

WORKDIR /app

COPY src/python_wrapper/main_server.py ./src/python_wrapper/
COPY src/python_wrapper/config.py ./src/python_wrapper/

COPY --from=builder /app/build/libterminus_core.so ./build/libterminus_core.so

EXPOSE 8080
CMD ["python3", "src/python_wrapper/main_server.py"]
