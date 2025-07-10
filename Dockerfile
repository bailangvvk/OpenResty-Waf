# FROM alpine:3.20 AS builder
# FROM alpine:latest AS builder
FROM bailangvvking/openresty:latest AS builder

USER root

WORKDIR /build

# 安装构建依赖
RUN set -eux && apk add --no-cache \
    build-base \
    curl \
    git \
    bash \
    linux-headers \
    pcre-dev \
    pcre2 \
    pcre2-dev \
    zlib-dev \
    openssl-dev \
    libxml2-dev \
    libxslt-dev \
    yajl-dev \
    lmdb-dev \
    lua-dev \
    geoip-dev \
    brotli-dev \
    libtool \
    autoconf \
    automake \
    pkgconfig \
    perl \
    sed \
    grep \
    make \
    g++ \
    wget \
    && \
    # OPENRESTY_VERSION=$(wget --timeout 10 -q -O - https://openresty.org/en/download.html | grep -oE 'openresty-[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d'-' -f2) \
    OPENRESTY_VERSION=$(wget --timeout=10 -q -O - https://openresty.org/en/download.html \
    | grep -ioE 'openresty [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
    | head -n1 \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+') \
    && \
    OPENSSL_VERSION=$(wget -q -O - https://www.openssl.org/source/ | grep -oE 'openssl-[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d'-' -f2) \
    && \
    ZLIB_VERSION=$(wget -q -O - https://zlib.net/ | grep -oE 'zlib-[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -d'-' -f2) \
    && \
    ZSTD_VERSION=$(curl -Ls https://github.com/facebook/zstd/releases/latest | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 | cut -c2-) \
    && \
    CORERULESET_VERSION=$(curl -s https://api.github.com/repos/coreruleset/coreruleset/releases/latest | grep -oE '"tag_name": "[^"]+' | cut -d'"' -f4 | sed 's/v//') \
    && \
    PCRE_VERSION=$(curl -sL https://sourceforge.net/projects/pcre/files/pcre/ \
    | grep -oE 'pcre/[0-9]+\.[0-9]+/' \
    | grep -oE '[0-9]+\.[0-9]+' \
    | sort -Vr \
    | head -n1) \
    && \
    # ModSecurity模块和ModSecurity-nginx模块
    git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity \
    && cd ModSecurity \
    && git submodule update --init --depth 1 \
    && ./build.sh \
    && ./configure \
    && make -j$(nproc) \
    && make install && \
    git clone https://github.com/owasp-modsecurity/ModSecurity-nginx \
    && cd ModSecurity-nginx \
    && cd .. && \
    # Br压缩模块
    git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli \
    && \
    # ZSTD压缩模块
    wget https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz \
    && tar -xzf zstd-${ZSTD_VERSION}.tar.gz \
    && cd zstd-${ZSTD_VERSION} \
    && make clean \
    && CFLAGS="-fPIC" make && make install \
    && cd .. \
    && \
    git clone --depth=10 https://github.com/tokers/zstd-nginx-module.git \
    && \
    echo "=============版本号=============" && \
    echo "OPENRESTY_VERSION=${OPENRESTY_VERSION}" && \
    echo "OPENSSL_VERSION=${OPENSSL_VERSION}" && \
    echo "ZLIB_VERSION=${ZLIB_VERSION}" && \
    echo "ZSTD_VERSION=${ZSTD_VERSION}" && \
    echo "CORERULESET_VERSION=${CORERULESET_VERSION}" && \
    echo "PCRE_VERSION=${CORERULESET_VERSION}" && \
    \
    # fallback 以防 curl/grep 失败
    OPENRESTY_VERSION="${OPENRESTY_VERSION:-1.21.4.1}" && \
    OPENSSL_VERSION="${OPENSSL_VERSION:-3.3.0}" && \
    ZLIB_VERSION="${ZLIB_VERSION:-1.3.1}" && \
    ZSTD_VERSION="${ZSTD_VERSION:-1.5.7}" && \
    CORERULESET_VERSION="${CORERULESET_VERSION:-4.15.0}" && \
    PCRE_VERSION="${PCRE_VERSION:-8.45}" && \
    \
    echo "==> Using versions: openresty-${OPENRESTY_VERSION}, openssl-${OPENSSL_VERSION}, zlib-${ZLIB_VERSION}, ZSTD_VERSION-${ZSTD_VERSION}, CORERULESET_VERSION-${CORERULESET_VERSION}, CORERULESET_VERSION-${CORERULESET_VERSION}" && \
    \
    curl -fSL https://openresty.org/download/openresty-${OPENRESTY_VERSION}.tar.gz -o openresty.tar.gz && \
    # curl -fSL https://github.com/openresty/openresty/releases/download/v${OPENRESTY_VERSION}/openresty-${OPENRESTY_VERSION}.tar.gz  && \
    tar xzf openresty.tar.gz && \
    \
    curl -fSL https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz -o openssl.tar.gz && \
    tar xzf openssl.tar.gz && \
    \
    curl -fSL https://fossies.org/linux/misc/zlib-${ZLIB_VERSION}.tar.gz -o zlib.tar.gz && \
    tar xzf zlib.tar.gz && \
    \
    curl -fSL https://sourceforge.net/projects/pcre/files/pcre/${PCRE_VERSION}/pcre-${PCRE_VERSION}.tar.gz/download -o pcre.tar.gz && \
    tar xzf pcre.tar.gz && \
    \
    # tree \
    # && \
  
    # cd openresty-${OPENRESTY_VERSION} && \
    # ./configure \
    #   --prefix=/etc/openresty \
    #   --user=root \
    #   --group=root \
    #   --with-cc-opt="-static -static-libgcc" \
    #   --with-ld-opt="-static" \
    #   --with-openssl=../openssl-${OPENSSL_VERSION} \
    #   --with-zlib=../zlib-${ZLIB_VERSION} \
    #   --with-pcre \
    #   --with-pcre-jit \
    #   --with-http_ssl_module \
    #   --with-http_v2_module \
    #   --with-http_gzip_static_module \
    #   --with-http_stub_status_module \
    #   --without-http_rewrite_module \
    #   --without-http_auth_basic_module \
    #   --with-threads && \
    # make -j$(nproc) && \
    # make install \
  
    cd openresty-${OPENRESTY_VERSION} && \
    # ./configure \
    # --prefix=/usr/local \
    # --modules-path=/usr/local/nginx/modules \
    # --sbin-path=/usr/local/nginx/sbin/nginx \
    # --conf-path=/usr/local/nginx/conf/nginx.conf \
    # --error-log-path=/data/logs/error.log \
    # --http-log-path=/data/logs/access.log \
    # # --with-cc-opt="-static -O3 -DNGX_LUA_ABORT_AT_PANIC -static-libgcc" \
    # # --with-ld-opt="-static -Wl,--export-dynamic" \
    # --with-cc-opt="-O3 -DNGX_LUA_ABORT_AT_PANIC" \
    # --with-ld-opt="-Wl,--export-dynamic" \
    # --with-openssl=../openssl-${OPENSSL_VERSION} \
    # --with-zlib=../zlib-${ZLIB_VERSION} \
    # --with-pcre=../pcre-${PCRE_VERSION} \
    # --with-pcre-jit \
    # --with-stream \
    # --user=nobody \
    # --group=nobody \
    # --with-stream_ssl_module \
    # --with-stream_ssl_preread_module \
    # --with-http_v2_module \
    # --without-mail_pop3_module \
    # --without-mail_imap_module \
    # --without-mail_smtp_module \
    # --with-http_stub_status_module  \
    # --with-http_realip_module \
    # --with-http_gzip_static_module \
    # --with-http_sub_module \
    # --with-http_gunzip_module \
    # --with-threads \
    # --with-compat \
    # --with-stream=dynamic \
    # --with-http_ssl_module \
    # --with-debug \

    # --without-lua_resty_dns \
    # --without-lua_resty_memcached \
    # --without-lua_redis_parser \
    # --without-lua_rds_parser \
    # --without-lua_resty_redis \
    # --without-lua_resty_mysql \
    # --without-lua_resty_upload \
    # --without-lua_resty_upstream_healthcheck \
    # --without-lua_resty_string \
    # --without-lua_resty_websocket \
    # --without-lua_resty_limit_traffic \
    # --without-lua_resty_lrucache \
    # --without-lua_resty_lock \
    # --without-lua_resty_signal \
    # --without-lua_resty_lrucache \
    # --without-lua_resty_shell \
    # --without-lua_resty_core \
    # --without-select_module \
    # --without-lua_resty_mysql \
    # --without-http_charset_module \
    # --without-http_ssi_module \
    # --without-http_userid_module \
    # --without-http_auth_basic_module \
    # --without-http_mirror_module \
    # --without-http_autoindex_module \
    # --without-http_split_clients_module \
    # --without-http_memcached_module \
    # --without-http_empty_gif_module \
    # --without-http_browser_module \
    # --without-stream_limit_conn_module \
    # --without-stream_geo_module \
    # --without-stream_map_module \
    # --without-stream_split_clients_module \
    # --without-stream_return_module \

    # cd openresty-${OPENRESTY_VERSION} && \
    # ./configure \
    # --prefix=/usr/local/openresty \
    # --with-luajit \
    # --with-pcre-jit \
    # --with-ipv6 \
    # --with-http_ssl_module \
    # --with-http_realip_module \
    # --with-http_addition_module \
    # --with-http_sub_module \
    # --with-http_dav_module \
    # --with-http_flv_module \
    # --with-http_mp4_module \
    # --with-http_gunzip_module \
    # --with-http_gzip_static_module \
    # --with-http_auth_request_module \
    # --with-http_random_index_module \
    # --with-http_secure_link_module \
    # --with-http_stub_status_module \
    # --with-http_v2_module \
    # --with-stream \
    # --with-stream_ssl_module \
    # --with-stream_ssl_preread_module \
    # --with-stream_realip_module \
    # --with-threads \
    # --with-file-aio

    # 编译生成.so模块
    ./configure \
    --with-compat \
    --add-dynamic-module=../ngx_brotli \
    --add-dynamic-module=../ModSecurity-nginx \
    --add-dynamic-module=../zstd-nginx-module \
    && \
    make modules \
    # && mv /usr/src/nginx-${NGINX_VERSION} /usr/src/nginx
    && \
    # 查看未压缩前的大小
    du -sh /usr/local/modsecurity/lib && \
    strip /usr/local/modsecurity/lib/*.so* && \
    du -sh /usr/local/modsecurity/lib
    
    # && \
    # make -j$(nproc) && \
    # make install \
    # && \
    # # strip /usr/local/nginx/sbin/nginx
    # strip /usr/local/nginx/sbin/nginx && \
    # strip /usr/local/luajit/bin/luajit || true && \
    # strip /usr/local/luajit/lib/libluajit-5.1.so.2 || true && \
    # find /usr/local/nginx/modules -name '*.so' -exec strip {} \; || true && \
    # find /usr/local/lualib -name '*.so' -exec strip {} \; || true

# FROM alpine:latest
FROM bailangvvking/openresty:latest

USER root

COPY --from=builder /usr/local/modsecurity/lib/* /usr/lib/

# 环境变量指定动态库搜索路径
ENV LD_LIBRARY_PATH=/usr/local/modsecurity/lib

# 创建配置目录并下载必要文件
RUN set -eux \
    && apk add --no-cache lua5.1 lua5.1-dev pcre pcre-dev yajl yajl-dev curl \
    && mkdir -p /etc/nginx/modsec/plugins \
    && CORERULESET_VERSION=$(curl -s https://api.github.com/repos/coreruleset/coreruleset/releases/latest | grep -oE '"tag_name": "[^"]+' | cut -d'"' -f4 | sed 's/v//') \
    && wget https://github.com/coreruleset/coreruleset/archive/v${CORERULESET_VERSION}.tar.gz \
    && tar -xzf v${CORERULESET_VERSION}.tar.gz --strip-components=1 -C /etc/nginx/modsec \
    && rm -f v${CORERULESET_VERSION}.tar.gz \
    && wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/coreruleset/wordpress-rule-exclusions-plugin/master/plugins/wordpress-rule-exclusions-before.conf \
    && wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/coreruleset/wordpress-rule-exclusions-plugin/master/plugins/wordpress-rule-exclusions-config.conf \
    && wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/kejilion/nginx/main/waf/ldnmp-before.conf \
    && cp /etc/nginx/modsec/crs-setup.conf.example /etc/nginx/modsec/crs-setup.conf \
    && echo 'SecAction "id:900110, phase:1, pass, setvar:tx.inbound_anomaly_score_threshold=30, setvar:tx.outbound_anomaly_score_threshold=16"' >> /etc/nginx/modsec/crs-setup.conf \
    && wget https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended -O /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecPcreMatchLimit [0-9]\+/SecPcreMatchLimit 20000/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecPcreMatchLimitRecursion [0-9]\+/SecPcreMatchLimitRecursion 20000/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/^SecRequestBodyLimit\s\+[0-9]\+/SecRequestBodyLimit 52428800/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/^SecRequestBodyNoFilesLimit\s\+[0-9]\+/SecRequestBodyNoFilesLimit 524288/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/^SecAuditEngine RelevantOnly/SecAuditEngine Off/' /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/crs-setup.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-config.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-before.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/rules/*.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-after.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && ldconfig /usr/lib \
    && wget https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping -O /etc/nginx/modsec/unicode.mapping \
    && apk del curl \
    && rm -rf /var/cache/apk/*

EXPOSE 80 443
WORKDIR /etc/nginx
CMD ["/usr/sbin/nginx", "-g", "daemon off;"]
