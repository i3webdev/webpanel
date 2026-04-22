#!/bin/bash
set -euo pipefail

SITES_ROOT="/home"
VHOSTS_DIR="/usr/local/lsws/conf/vhosts"
OLS_SERVICE="lsws"
ULTRA_SCRIPT_DEFAULT="/root/web-panel/script.sh"

err() {
    echo "ERRO: $*" >&2
    exit 1
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || err "helper deve rodar como root"
}

valid_user() {
    local user="$1"
    [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]]
}

site_user_exists() {
    local user="$1"
    valid_user "$user" || return 1
    [[ "$user" != "Example" ]] || return 1
    [[ -d "${VHOSTS_DIR}/${user}" && -d "${SITES_ROOT}/${user}" ]]
}

site_public_html() {
    local user="$1"
    echo "${SITES_ROOT}/${user}/public_html"
}

site_domain() {
    local user="$1"
    local vhconf="${VHOSTS_DIR}/${user}/vhconf.conf"
    if [[ -f "$vhconf" ]]; then
        awk '$1 == "vhDomain" {print $2; exit}' "$vhconf"
    fi
}

find_ultra_script() {
    local -a candidates=(
        "$ULTRA_SCRIPT_DEFAULT"
        "/root/script.sh"
    )
    local path
    for path in "${candidates[@]}"; do
        if [[ -f "$path" && -r "$path" ]]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

run_script_api() {
    local script_path
    script_path="$(find_ultra_script)" || err "script principal não encontrado"
    bash "$script_path" "__api" "$@"
}

sanitize_relpath() {
    local rel="${1:-}"
    local part normalized
    local -a parts

    # Normaliza separadores e remove prefixos comuns.
    rel="${rel//\\//}"
    while [[ "$rel" == /* ]]; do
        rel="${rel#/}"
    done
    while [[ "$rel" == ./* ]]; do
        rel="${rel#./}"
    done

    [[ "$rel" == "." ]] && rel=""
    [[ "$rel" == *$'\n'* || "$rel" == *$'\r'* || "$rel" == *$'\t'* ]] && err "caminho inválido"

    normalized=""
    IFS='/' read -r -a parts <<< "$rel"
    for part in "${parts[@]}"; do
        [[ -z "$part" || "$part" == "." ]] && continue
        [[ "$part" == ".." ]] && err "path traversal bloqueado"
        [[ "$part" =~ [[:cntrl:]] ]] && err "caminho inválido"

        if [[ -z "$normalized" ]]; then
            normalized="$part"
        else
            normalized="${normalized}/${part}"
        fi
    done

    echo "$normalized"
}

resolve_inside() {
    local base="$1"
    local rel="${2:-}"
    local base_real target

    base_real="$(realpath -m "$base")"
    target="$(realpath -m "${base_real}/${rel}")"

    if [[ "$target" != "$base_real" && "$target" != "${base_real}/"* ]]; then
        err "acesso fora da raiz bloqueado"
    fi

    echo "$target"
}

cmd_list_sites() {
    local tmp
    tmp="$(mktemp)"

    local dir user domain root suspended tunnel kind
    for dir in "${VHOSTS_DIR}"/*; do
        [[ -d "$dir" ]] || continue
        user="$(basename "$dir")"
        [[ "$user" == "Example" ]] && continue
        valid_user "$user" || continue

        domain="$(site_domain "$user")"
        root="${SITES_ROOT}/${user}"
        suspended="0"
        [[ -f "${root}/.suspended" ]] && suspended="1"

        tunnel="inativo"
        if systemctl is-enabled "cloudflared-${user}.service" >/dev/null 2>&1; then
            tunnel="ativo"
        fi

        kind="site"
        [[ "$user" == "phpmyadmin_srv" ]] && kind="infra"
        [[ "$user" == "painel_srv" ]] && kind="infra"

        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$user" "$domain" "$root" "$suspended" "$tunnel" "$kind" >>"$tmp"
    done

    jq -R -s '
      split("\n")
      | map(select(length > 0))
      | map(split("\t") | {
          user: .[0],
          domain: .[1],
          root: .[2],
          suspended: (.[3] == "1"),
          tunnel: .[4],
          kind: .[5]
        })
      | sort_by(.user)
    ' "$tmp"

    rm -f "$tmp"
}

cmd_service_status() {
    local services=("lsws" "mariadb" "redis" "crond")
    local tmp
    tmp="$(mktemp)"

    local s status
    for s in "${services[@]}"; do
        if systemctl list-unit-files "${s}.service" --no-legend 2>/dev/null | grep -q "${s}\\.service"; then
            if systemctl is-active "${s}" >/dev/null 2>&1; then
                status="active"
            else
                status="inactive"
            fi
        else
            status="missing"
        fi

        printf '%s\t%s\n' "$s" "$status" >>"$tmp"
    done

    jq -R -s '
      split("\n")
      | map(select(length > 0))
      | map(split("\t") | {service: .[0], status: .[1]})
    ' "$tmp"

    rm -f "$tmp"
}

cmd_restart_services() {
    local services=("mariadb" "redis" "lsws" "crond")
    local s
    for s in "${services[@]}"; do
        if systemctl list-unit-files "${s}.service" --no-legend 2>/dev/null | grep -q "${s}\\.service"; then
            systemctl restart "$s" || true
        fi
    done
    echo '{"ok":true}'
}

cmd_suspend_site() {
    local user="$1"
    site_user_exists "$user" || err "site não encontrado"

    local root_dir="${SITES_ROOT}/${user}"
    touch "${root_dir}/.suspended"
    chmod 000 "${root_dir}/public_html" || true
    systemctl stop "cloudflared-${user}.service" >/dev/null 2>&1 || true

    echo '{"ok":true}'
}

cmd_reactivate_site() {
    local user="$1"
    site_user_exists "$user" || err "site não encontrado"

    local root_dir="${SITES_ROOT}/${user}"
    rm -f "${root_dir}/.suspended"
    chmod 755 "${root_dir}/public_html" || true
    systemctl restart "cloudflared-${user}.service" >/dev/null 2>&1 || true

    echo '{"ok":true}'
}

cmd_site_create() {
    local domain_raw="${1:-}"
    local php_version="${2:-8.4}"
    local install_wp="${3:-0}"
    local create_tunnel="${4:-0}"

    [[ -n "$domain_raw" ]] || err "domínio obrigatório"
    run_script_api create-site "$domain_raw" "$php_version" "$install_wp" "$create_tunnel"
}

cmd_db_create_additional() {
    local user="${1:-}"
    local suffix="${2:-}"

    site_user_exists "$user" || err "site não encontrado"
    run_script_api create-db-additional "$user" "$suffix"
}

cmd_site_clone() {
    local source_user="${1:-}"
    local dest_domain="${2:-}"
    local php_version="${3:-8.4}"
    local create_tunnel="${4:-0}"

    site_user_exists "$source_user" || err "site de origem não encontrado"
    [[ -n "$dest_domain" ]] || err "domínio de destino obrigatório"
    run_script_api clone-site "$source_user" "$dest_domain" "$php_version" "$create_tunnel"
}

cmd_site_remove() {
    local user="${1:-}"
    local with_backup="${2:-1}"

    valid_user "$user" || err "usuário inválido"
    run_script_api remove-site "$user" "$with_backup"
}

cmd_cron_add() {
    local user="${1:-}"
    local expression="${2:-}"
    local command="${3:-}"
    local run_in_public_html="${4:-1}"

    site_user_exists "$user" || err "site não encontrado"
    [[ -n "$expression" ]] || err "expressão cron obrigatória"
    [[ -n "$command" ]] || err "comando cron obrigatório"
    run_script_api cron-add "$user" "$expression" "$command" "$run_in_public_html"
}

cmd_cron_list() {
    local user="${1:-}"
    site_user_exists "$user" || err "site não encontrado"
    run_script_api cron-list "$user"
}

cmd_cron_remove() {
    local user="${1:-}"
    local line="${2:-}"

    site_user_exists "$user" || err "site não encontrado"
    [[ -n "$line" ]] || err "linha cron obrigatória"
    run_script_api cron-remove "$user" "$line"
}

cmd_file_list() {
    local user="$1"
    local rel_raw="${2:-}"
    site_user_exists "$user" || err "site não encontrado"

    local base rel dir parent
    base="$(site_public_html "$user")"
    rel="$(sanitize_relpath "$rel_raw")"
    dir="$(resolve_inside "$base" "$rel")"
    [[ -d "$dir" ]] || err "diretório não encontrado"

    parent=""
    if [[ -n "$rel" ]]; then
        parent="$(dirname "$rel")"
        [[ "$parent" == "." ]] && parent=""
    fi

    local tmp
    tmp="$(mktemp)"

    local item name type size mtime rel_item
    shopt -s nullglob dotglob
    for item in "$dir"/*; do
        name="$(basename "$item")"
        [[ "$name" == "." || "$name" == ".." ]] && continue

        if [[ -d "$item" ]]; then
            type="dir"
        elif [[ -L "$item" ]]; then
            type="link"
        else
            type="file"
        fi

        size="$(stat -c '%s' "$item" 2>/dev/null || echo 0)"
        mtime="$(stat -c '%Y' "$item" 2>/dev/null || echo 0)"
        rel_item="${item#${base}/}"
        [[ "$item" == "$base" ]] && rel_item=""

        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$name" "$type" "$size" "$mtime" "$rel_item" >>"$tmp"
    done
    shopt -u nullglob dotglob

    jq -R -s --arg current "$rel" --arg parent "$parent" '
      {
        current: $current,
        parent: $parent,
        items: (
          split("\n")
          | map(select(length > 0))
          | map(split("\t") | {
              name: .[0],
              type: .[1],
              size: (.[2] | tonumber),
              mtime: (.[3] | tonumber),
              relpath: .[4]
            })
          | sort_by(.type, .name)
        )
      }
    ' "$tmp"

    rm -f "$tmp"
}

cmd_file_read() {
    local user="$1"
    local rel_raw="${2:-}"
    site_user_exists "$user" || err "site não encontrado"

    local base rel target size max_size
    base="$(site_public_html "$user")"
    rel="$(sanitize_relpath "$rel_raw")"
    [[ -n "$rel" ]] || err "arquivo inválido"

    target="$(resolve_inside "$base" "$rel")"
    [[ -f "$target" ]] || err "arquivo não encontrado"

    max_size=$((1024 * 1024))
    size="$(stat -c '%s' "$target" 2>/dev/null || echo 0)"
    [[ "$size" -le "$max_size" ]] || err "arquivo maior que 1MB"

    cat "$target"
}

cmd_file_write() {
    local user="$1"
    local rel_raw="${2:-}"
    site_user_exists "$user" || err "site não encontrado"

    local base rel target tmp
    base="$(site_public_html "$user")"
    rel="$(sanitize_relpath "$rel_raw")"
    [[ -n "$rel" ]] || err "arquivo inválido"

    target="$(resolve_inside "$base" "$rel")"
    tmp="$(mktemp)"
    cat >"$tmp"

    mkdir -p "$(dirname "$target")"
    cat "$tmp" >"$target"
    chown "$user:$user" "$target" >/dev/null 2>&1 || true
    chmod 644 "$target" >/dev/null 2>&1 || true

    rm -f "$tmp"
    echo '{"ok":true}'
}

cmd_file_delete() {
    local user="$1"
    local rel_raw="${2:-}"
    site_user_exists "$user" || err "site não encontrado"

    local base rel target
    base="$(site_public_html "$user")"
    rel="$(sanitize_relpath "$rel_raw")"
    [[ -n "$rel" ]] || err "alvo inválido"

    target="$(resolve_inside "$base" "$rel")"
    [[ -e "$target" || -L "$target" ]] || err "alvo não encontrado"

    if [[ -d "$target" && ! -L "$target" ]]; then
        rm -rf "$target"
    else
        rm -f "$target"
    fi

    echo '{"ok":true}'
}

cmd_file_mkdir() {
    local user="$1"
    local rel_raw="${2:-}"
    site_user_exists "$user" || err "site não encontrado"

    local base rel target
    base="$(site_public_html "$user")"
    rel="$(sanitize_relpath "$rel_raw")"
    [[ -n "$rel" ]] || err "diretório inválido"

    target="$(resolve_inside "$base" "$rel")"
    mkdir -p "$target"
    chown "$user:$user" "$target" >/dev/null 2>&1 || true
    chmod 755 "$target" >/dev/null 2>&1 || true

    echo '{"ok":true}'
}

main() {
    require_root

    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        list-sites) cmd_list_sites ;;
        service-status) cmd_service_status ;;
        restart-services) cmd_restart_services ;;
        suspend-site)
            [[ $# -eq 1 ]] || err "uso: suspend-site <user>"
            cmd_suspend_site "$1"
            ;;
        reactivate-site)
            [[ $# -eq 1 ]] || err "uso: reactivate-site <user>"
            cmd_reactivate_site "$1"
            ;;
        site-create)
            [[ $# -ge 1 ]] || err "uso: site-create <dominio> [php] [instalar_wp:0|1] [criar_tunnel:0|1]"
            cmd_site_create "$1" "${2:-8.4}" "${3:-0}" "${4:-0}"
            ;;
        db-create-additional)
            [[ $# -ge 1 ]] || err "uso: db-create-additional <user> [sufixo]"
            cmd_db_create_additional "$1" "${2:-}"
            ;;
        site-clone)
            [[ $# -ge 2 ]] || err "uso: site-clone <source_user> <dest_domain> [php] [criar_tunnel:0|1]"
            cmd_site_clone "$1" "$2" "${3:-8.4}" "${4:-0}"
            ;;
        site-remove)
            [[ $# -ge 1 ]] || err "uso: site-remove <user> [backup:0|1]"
            cmd_site_remove "$1" "${2:-1}"
            ;;
        cron-add)
            [[ $# -ge 3 ]] || err "uso: cron-add <user> <expressao> <comando> [executar_em_public_html:0|1]"
            cmd_cron_add "$1" "$2" "$3" "${4:-1}"
            ;;
        cron-list)
            [[ $# -ge 1 ]] || err "uso: cron-list <user>"
            cmd_cron_list "$1"
            ;;
        cron-remove)
            [[ $# -ge 2 ]] || err "uso: cron-remove <user> <linha_exata>"
            cmd_cron_remove "$1" "$2"
            ;;
        file-list)
            [[ $# -ge 1 ]] || err "uso: file-list <user> [relpath]"
            cmd_file_list "$1" "${2:-}"
            ;;
        file-read)
            [[ $# -eq 2 ]] || err "uso: file-read <user> <relpath>"
            cmd_file_read "$1" "$2"
            ;;
        file-write)
            [[ $# -eq 2 ]] || err "uso: file-write <user> <relpath>"
            cmd_file_write "$1" "$2"
            ;;
        file-delete)
            [[ $# -eq 2 ]] || err "uso: file-delete <user> <relpath>"
            cmd_file_delete "$1" "$2"
            ;;
        file-mkdir)
            [[ $# -eq 2 ]] || err "uso: file-mkdir <user> <relpath>"
            cmd_file_mkdir "$1" "$2"
            ;;
        *)
            err "comando inválido"
            ;;
    esac
}

main "$@"
