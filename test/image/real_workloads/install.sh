#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$(id -u)" -ne 0 ]; then
    printf 'install.sh must run as root\n' >&2
    exit 1
fi

readonly SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SOURCE_DIR/versions.env"

readonly PREFIX=/opt/aoa-workloads
readonly DOWNLOAD_DIR=/var/tmp/aoa-workload-downloads
readonly BUILD_DIR=/var/tmp/aoa-workload-build

download() {
    local url="$1" sha256="$2" destination="$3"
    if [ -s "$destination" ] && \
        printf '%s  %s\n' "$sha256" "$destination" | sha256sum --check --status; then
        printf '[aoa-workload-install] reusing verified %s\n' "$destination"
        return 0
    fi
    rm -f "$destination"
    curl -L --fail --show-error --silent --connect-timeout 20 \
        --speed-limit 1024 --speed-time 30 --max-time 300 \
        --retry 8 --retry-delay 2 --retry-all-errors \
        -o "$destination" "$url"
    if ! printf '%s  %s\n' "$sha256" "$destination" | sha256sum --check --status; then
        rm -f "$destination"
        return 1
    fi
}

dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs \
    --setopt=max_parallel_downloads=1 --setopt=timeout=30 \
    --setopt=minrate=1024 --setopt=retries=10 \
    redis memcached nginx postgresql-server postgresql-contrib \
    ffmpeg rocksdb rocksdb-devel ImageMagick etcd wrk \
    autoconf automake libtool gcc-c++ make libevent-devel openssl-devel \
    pcre2-devel unzip jq time curl

id aoa-workload >/dev/null 2>&1 || \
    useradd --system --home-dir /var/lib/aoa-workloads --create-home \
        --shell /usr/sbin/nologin aoa-workload

rm -rf "$BUILD_DIR" "$PREFIX"
install -d -m 0755 "$DOWNLOAD_DIR" "$BUILD_DIR" "$PREFIX/bin" "$PREFIX/src"

download "$MEMTIER_URL" "$MEMTIER_SHA256" "$DOWNLOAD_DIR/memtier.tar.gz"
tar -xzf "$DOWNLOAD_DIR/memtier.tar.gz" -C "$BUILD_DIR"
mv "$BUILD_DIR"/memtier_benchmark-* "$PREFIX/src/memtier"
(
    cd "$PREFIX/src/memtier"
    autoreconf -ivf
    ./configure --prefix="$PREFIX" --disable-tls --disable-prometheus \
        CXXFLAGS='-O2 -DNDEBUG -Wall'
    make -j6
    make install
    make clean
)

download "$WRK2_URL" "$WRK2_SHA256" "$DOWNLOAD_DIR/wrk2.tar.gz"
tar -xzf "$DOWNLOAD_DIR/wrk2.tar.gz" -C "$BUILD_DIR"
(
    cd "$BUILD_DIR"/wrk2-*
    make -j6
    install -m 0755 wrk "$PREFIX/bin/wrk2"
)

download "$NATS_SERVER_URL" "$NATS_SERVER_SHA256" "$DOWNLOAD_DIR/nats-server.tar.gz"
tar -xzf "$DOWNLOAD_DIR/nats-server.tar.gz" -C "$BUILD_DIR"
install -m 0755 "$BUILD_DIR"/nats-server-*/nats-server "$PREFIX/bin/nats-server"

download "$NATS_CLI_URL" "$NATS_CLI_SHA256" "$DOWNLOAD_DIR/nats.zip"
unzip -q "$DOWNLOAD_DIR/nats.zip" -d "$BUILD_DIR/nats-cli"
install -m 0755 "$BUILD_DIR"/nats-cli/nats-*/nats "$PREFIX/bin/nats"

download "$ROCKSDB_URL" "$ROCKSDB_SHA256" "$DOWNLOAD_DIR/rocksdb.tar.gz"
tar -xzf "$DOWNLOAD_DIR/rocksdb.tar.gz" -C "$BUILD_DIR"
(
    cd "$BUILD_DIR"/rocksdb-*
    make -j2 db_bench DEBUG_LEVEL=0 DISABLE_WARNING_AS_ERROR=1 PORTABLE=1
    install -m 0755 db_bench "$PREFIX/bin/db_bench"
)

strip "$PREFIX/bin/memtier_benchmark" "$PREFIX/bin/wrk2" \
    "$PREFIX/bin/nats-server" "$PREFIX/bin/nats" "$PREFIX/bin/db_bench" || true

install -d -m 0755 /etc/aoa-workloads "$PREFIX/www" /usr/local/libexec
install -m 0644 "$SOURCE_DIR/redis.conf" /etc/aoa-workloads/redis.conf
install -m 0644 "$SOURCE_DIR/nginx.conf" /etc/aoa-workloads/nginx.conf
install -m 0644 "$SOURCE_DIR/index.html" "$PREFIX/www/index.html"
install -m 0755 "$SOURCE_DIR/aoa-real-workload" /usr/local/sbin/aoa-real-workload
install -m 0755 "$SOURCE_DIR/summarize_workloads.py" \
    /usr/local/libexec/aoa-summarize-workloads
install -m 0644 "$SOURCE_DIR/aoa-real-workload-autostart.service" \
    /usr/lib/systemd/system/aoa-real-workload-autostart.service
chown -R aoa-workload:aoa-workload "$PREFIX/src/memtier"

install -d -m 0755 /var/lib/aoa-workloads
install -d -m 0700 -o postgres -g postgres /var/lib/aoa-workloads/postgres
if [ ! -s /var/lib/aoa-workloads/postgres/PG_VERSION ]; then
    runuser -u postgres -- /bin/sh -c \
        'cd /var/lib/aoa-workloads && exec /usr/bin/initdb -D /var/lib/aoa-workloads/postgres \
            --auth=trust --encoding=UTF8 --no-locale'
fi
install -d -m 0755 -o postgres -g postgres /run/aoa-postgres-build
runuser -u postgres -- /usr/bin/pg_ctl -D /var/lib/aoa-workloads/postgres \
    -o '-h 127.0.0.1 -p 15432 -k /run/aoa-postgres-build -c fsync=off -c synchronous_commit=off -c full_page_writes=off' \
    -w start
if ! runuser -u postgres -- /usr/bin/psql -h 127.0.0.1 -p 15432 -lqt | \
    awk '{print $1}' | grep -qx aoa_bench; then
    runuser -u postgres -- /usr/bin/createdb -h 127.0.0.1 -p 15432 aoa_bench
    runuser -u postgres -- /usr/bin/pgbench -h 127.0.0.1 -p 15432 \
        -i -s 4 aoa_bench
fi
runuser -u postgres -- /usr/bin/pg_ctl -D /var/lib/aoa-workloads/postgres -w stop
rm -rf /run/aoa-postgres-build

systemctl disable redis memcached nginx postgresql etcd 2>/dev/null || true
systemctl enable aoa-real-workload-autostart.service

{
    printf 'memtier_benchmark=%s\n' "$MEMTIER_VERSION"
    printf 'wrk2=%s\n' "$WRK2_COMMIT"
    printf 'nats-server=%s\n' "$NATS_SERVER_VERSION"
    printf 'nats-cli=%s\n' "$NATS_CLI_VERSION"
    printf 'rocksdb-db-bench=%s\n' "$ROCKSDB_VERSION"
    rpm -q redis memcached nginx postgresql-server postgresql-contrib \
        ffmpeg rocksdb ImageMagick etcd zstd openssl
} >"$PREFIX/versions.txt"

dnf clean all
rm -rf "$DOWNLOAD_DIR" "$BUILD_DIR" /var/cache/dnf
sync
fstrim -av
sync
