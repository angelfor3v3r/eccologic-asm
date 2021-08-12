## Build stage ##
FROM gcc:11.2-bullseye AS build

COPY backend /tmp/asm/backend
COPY frontend /tmp/asm/frontend

ENV VCPKG_ROOT="/opt/vcpkg"

# Install dependencies.
RUN set -eux                                                                                                  \
    && apt-get update                                                                                         \
    && apt-get install -y bash zip git curl libssl-dev pkg-config python                                      \
    && curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -                                             \
    && apt-get install -y nodejs                                                                              \
    && mkdir /tmp/cmake_src                                                                                   \
    && cd /tmp/cmake_src                                                                                      \
    && curl -L https://github.com/Kitware/CMake/releases/download/v3.20.5/cmake-3.20.5.tar.gz -o cmake.tar.gz \
    && tar --strip-components=1 -xvf cmake.tar.gz                                                             \
    && rm -rf cmake.tar.gz                                                                                    \
    && ./bootstrap                                                                                            \
    && make -j$(nproc)                                                                                        \
    && make install                                                                                           \
    && mkdir -p /opt/vcpkg                                                                                    \
    && cd /opt/vcpkg                                                                                          \
    && git clone https://github.com/microsoft/vcpkg .                                                         \
    && ./bootstrap-vcpkg.sh -disableMetrics                                                                   \
    && apt-get upgrade -y                                                                                     \
    && rm -rf /var/lib/apt/lists/*

# Build server/client.
RUN rm -rf /tmp/asm/backend/build \
    && cd /tmp/asm/backend        \
    && chmod +x build.sh          \
    && ./build.sh                 \
    && cd /tmp/asm/frontend       \
    && npm install                \
    && npm run build

## Runtime stage ##
FROM gcc:11.2-bullseye

WORKDIR /opt/asm

COPY --from=build /tmp/asm/bin /opt/asm

ENV LD_PRELOAD="/opt/asm/libmimalloc.so"
ENTRYPOINT [ "./asm" ]