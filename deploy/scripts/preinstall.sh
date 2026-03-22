#!/bin/bash
set -e

# Создание системных групп для RBAC и доступа сервиса
for grp in phantom-admin phantom-editor phantom-user; do
    if ! getent group "$grp" >/dev/null 2>&1; then
        groupadd --system "$grp"
    fi
done

if ! getent passwd phantom >/dev/null 2>&1; then
    useradd --system \
        --gid phantom-user \
        --groups phantom-admin \
        --shell /usr/sbin/nologin \
        --home-dir /var/lib/phantom \
        --no-create-home \
        --comment "Phantom Files Daemon" \
        phantom
fi
