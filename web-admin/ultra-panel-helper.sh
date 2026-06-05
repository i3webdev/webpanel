#!/bin/bash
set -euo pipefail

SITES_ROOT="/home"
VHOSTS_DIR="/usr/local/lsws/conf/vhosts"
OLS_SERVICE="lsws"
ULTRA_SCRIPT_DEFAULT="/opt/ultra-web-panel/script.sh"

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

cmd_server_metrics() {
    local mem_total_kb mem_available_kb mem_used_kb mem_percent
    mem_total_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    mem_available_kb="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
    mem_used_kb=$((mem_total_kb - mem_available_kb))
    mem_percent="0"
    if [[ "$mem_total_kb" -gt 0 ]]; then
        mem_percent="$(awk -v used="$mem_used_kb" -v total="$mem_total_kb" 'BEGIN { printf "%.1f", (used / total) * 100 }')"
    fi

    local cpu_line_a cpu_line_b cpu_percent
    read -r _ cpu_user_a cpu_nice_a cpu_system_a cpu_idle_a cpu_iowait_a cpu_irq_a cpu_softirq_a cpu_steal_a _ < /proc/stat
    sleep 0.4
    read -r _ cpu_user_b cpu_nice_b cpu_system_b cpu_idle_b cpu_iowait_b cpu_irq_b cpu_softirq_b cpu_steal_b _ < /proc/stat

    local idle_a idle_b total_a total_b delta_idle delta_total
    idle_a=$((cpu_idle_a + cpu_iowait_a))
    idle_b=$((cpu_idle_b + cpu_iowait_b))
    total_a=$((cpu_user_a + cpu_nice_a + cpu_system_a + cpu_idle_a + cpu_iowait_a + cpu_irq_a + cpu_softirq_a + cpu_steal_a))
    total_b=$((cpu_user_b + cpu_nice_b + cpu_system_b + cpu_idle_b + cpu_iowait_b + cpu_irq_b + cpu_softirq_b + cpu_steal_b))
    delta_idle=$((idle_b - idle_a))
    delta_total=$((total_b - total_a))
    cpu_percent="0"
    if [[ "$delta_total" -gt 0 ]]; then
        cpu_percent="$(awk -v idle="$delta_idle" -v total="$delta_total" 'BEGIN { printf "%.1f", (1 - (idle / total)) * 100 }')"
    fi

    local load1 load5 load15
    read -r load1 load5 load15 _ < /proc/loadavg
    local cpu_cores
    cpu_cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)"

    local uptime_seconds uptime_days uptime_hours uptime_minutes
    uptime_seconds="$(cut -d'.' -f1 /proc/uptime 2>/dev/null || echo 0)"
    uptime_days=$((uptime_seconds / 86400))
    uptime_hours=$(((uptime_seconds % 86400) / 3600))
    uptime_minutes=$(((uptime_seconds % 3600) / 60))

    local disk_root_json
    disk_root_json="$(df -B1 --output=source,size,used,avail,pcent,target / 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); printf("{\"filesystem\":\"%s\",\"size\":%s,\"used\":%s,\"available\":%s,\"percent\":%s,\"mount\":\"%s\"}", $1, $2, $3, $4, $5, $6)}')"
    [[ -n "$disk_root_json" ]] || disk_root_json='{"filesystem":"","size":0,"used":0,"available":0,"percent":0,"mount":"/"}'

    local disks_json
    disks_json="$(df -B1 --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1 {gsub(/%/,"",$5); printf("%s{\"filesystem\":\"%s\",\"size\":%s,\"used\":%s,\"available\":%s,\"percent\":%s,\"mount\":\"%s\"}", sep, $1, $2, $3, $4, $5, $6); sep="," } END { printf("") }')"

    local top_json
    top_json="$(ps -eo pid,comm,%cpu,%mem --sort=-%cpu 2>/dev/null | awk 'NR>1 && count<5 {printf("%s{\"pid\":%s,\"command\":\"%s\",\"cpu\":%s,\"mem\":%s}", sep, $1, $2, $3, $4); sep=","; count++ } END { printf("") }')"

    jq -n \
        --argjson cpu_percent "$cpu_percent" \
        --argjson cpu_cores "$cpu_cores" \
        --arg load1 "$load1" \
        --arg load5 "$load5" \
        --arg load15 "$load15" \
        --argjson mem_total "$((mem_total_kb * 1024))" \
        --argjson mem_used "$((mem_used_kb * 1024))" \
        --argjson mem_available "$((mem_available_kb * 1024))" \
        --argjson mem_percent "$mem_percent" \
        --argjson uptime_seconds "$uptime_seconds" \
        --argjson uptime_days "$uptime_days" \
        --argjson uptime_hours "$uptime_hours" \
        --argjson uptime_minutes "$uptime_minutes" \
        --argjson disk_root "$disk_root_json" \
        --argjson disks "[$disks_json]" \
        --argjson top_processes "[$top_json]" \
        '{
            ok: true,
            cpu: {
                percent: $cpu_percent,
                cores: $cpu_cores,
                load: {one: $load1, five: $load5, fifteen: $load15}
            },
            memory: {
                total: $mem_total,
                used: $mem_used,
                available: $mem_available,
                percent: $mem_percent
            },
            uptime: {
                seconds: $uptime_seconds,
                days: $uptime_days,
                hours: $uptime_hours,
                minutes: $uptime_minutes
            },
            disk: {
                root: $disk_root,
                mounts: $disks
            },
            top_processes: $top_processes
        }'
}

cmd_install_stack_base() {
    run_script_api install-stack-base
}

cmd_configure_phpmyadmin_domain() {
    local domain_raw="${1:-}"
    local remove_others="${2:-1}"
    local create_tunnel="${3:-0}"

    [[ -n "$domain_raw" ]] || err "dominio do phpMyAdmin obrigatorio"
    run_script_api configure-phpmyadmin-domain "$domain_raw" "$remove_others" "$create_tunnel"
}

cmd_configure_panel_domain() {
    local domain_raw="${1:-}"
    local create_tunnel="${2:-0}"

    [[ -n "$domain_raw" ]] || err "dominio do painel obrigatorio"
    run_script_api configure-panel-domain "$domain_raw" "$create_tunnel"
}

cmd_db_rotate_password() {
    local user="${1:-}"
    site_user_exists "$user" || err "site nao encontrado"
    run_script_api db-rotate-password "$user"
}

cmd_site_error_log() {
    local user="${1:-}"
    local lines="${2:-80}"

    site_user_exists "$user" || err "site nao encontrado"
    [[ "$lines" =~ ^[0-9]+$ ]] || err "quantidade de linhas invalida"
    run_script_api site-error-log "$user" "$lines"
}

cmd_wordpress_fix_permalink() {
    local user="${1:-}"
    site_user_exists "$user" || err "site nao encontrado"
    run_script_api wordpress-fix-permalink "$user"
}

cmd_site_fix_rewrite() {
    local user="${1:-}"
    local front_controller="${2:-index.php}"

    site_user_exists "$user" || err "site nao encontrado"
    [[ -n "$front_controller" ]] || err "front controller obrigatorio"
    run_script_api site-fix-rewrite "$user" "$front_controller"
}

cmd_htaccess_verify() {
    local user="${1:-}"
    site_user_exists "$user" || err "site nao encontrado"
    run_script_api htaccess-verify "$user"
}

cmd_ols_set_admin() {
    local admin_user="${1:-admin}"
    local admin_pass="${2:-}"

    [[ -n "$admin_pass" ]] || err "senha do OLS obrigatoria"
    run_script_api ols-set-admin "$admin_user" "$admin_pass"
}

cmd_cloudflare_status() {
    run_script_api cloudflare-status
}

cmd_cloudflare_login_start() {
    run_script_api cloudflare-login-start
}

cmd_github_config_status() {
    run_script_api github-config-status
}

cmd_github_config_set() {
    local username="${1:-}"
    local token="${2:-}"
    local author_name="${3:-}"
    local author_email="${4:-}"

    [[ -n "$username" ]] || err "usuario do GitHub obrigatorio"
    [[ -n "$token" ]] || err "token do GitHub obrigatorio"
    [[ -n "$author_name" ]] || err "nome do autor obrigatorio"
    [[ -n "$author_email" ]] || err "email do autor obrigatorio"
    run_script_api github-config-set "$username" "$token" "$author_name" "$author_email"
}

cmd_github_oauth_app_set() {
    local client_id="${1:-}"
    local scopes="${2:-repo read:user user:email}"

    [[ -n "$client_id" ]] || err "client id do GitHub obrigatorio"
    run_script_api github-oauth-app-set "$client_id" "$scopes"
}

cmd_github_config_clear() {
    run_script_api github-config-clear
}

cmd_github_device_start() {
    run_script_api github-device-start
}

cmd_github_device_poll() {
    local poll_now="${1:-0}"
    run_script_api github-device-poll "$poll_now"
}

cmd_github_site_status() {
    local user="${1:-}"
    site_user_exists "$user" || err "site nao encontrado"
    run_script_api github-site-status "$user"
}

cmd_github_repos_list() {
    run_script_api github-repos-list
}

cmd_github_site_clone_start() {
    local user="${1:-}"
    local repo_slug="${2:-}"
    local branch="${3:-}"
    local clean_target="${4:-0}"

    site_user_exists "$user" || err "site nao encontrado"
    [[ -n "$repo_slug" ]] || err "repositorio GitHub obrigatorio"
    run_script_api github-site-clone-start "$user" "$repo_slug" "$branch" "$clean_target"
}

cmd_github_site_clone_status() {
    local user="${1:-}"
    site_user_exists "$user" || err "site nao encontrado"
    run_script_api github-site-clone-status "$user"
}

cmd_github_site_clone() {
    local user="${1:-}"
    local repo_slug="${2:-}"
    local branch="${3:-}"
    local clean_target="${4:-0}"

    site_user_exists "$user" || err "site nao encontrado"
    [[ -n "$repo_slug" ]] || err "repositorio GitHub obrigatorio"
    run_script_api github-site-clone "$user" "$repo_slug" "$branch" "$clean_target"
}

cmd_github_site_pull() {
    local user="${1:-}"
    site_user_exists "$user" || err "site nao encontrado"
    run_script_api github-site-pull "$user"
}

cmd_github_site_commit_push() {
    local user="${1:-}"
    local commit_msg="${2:-}"

    site_user_exists "$user" || err "site nao encontrado"
    [[ -n "$commit_msg" ]] || err "mensagem de commit obrigatoria"
    run_script_api github-site-commit-push "$user" "$commit_msg"
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
        server-metrics) cmd_server_metrics ;;
        restart-services) cmd_restart_services ;;
        install-stack-base) cmd_install_stack_base ;;
        configure-phpmyadmin-domain)
            [[ $# -ge 1 ]] || err "uso: configure-phpmyadmin-domain <dominio> [remover_outros:0|1] [criar_tunnel:0|1]"
            cmd_configure_phpmyadmin_domain "$1" "${2:-1}" "${3:-0}"
            ;;
        configure-panel-domain)
            [[ $# -ge 1 ]] || err "uso: configure-panel-domain <dominio> [criar_tunnel:0|1]"
            cmd_configure_panel_domain "$1" "${2:-0}"
            ;;
        db-rotate-password)
            [[ $# -ge 1 ]] || err "uso: db-rotate-password <site_user>"
            cmd_db_rotate_password "$1"
            ;;
        site-error-log)
            [[ $# -ge 1 ]] || err "uso: site-error-log <site_user> [linhas]"
            cmd_site_error_log "$1" "${2:-80}"
            ;;
        wordpress-fix-permalink)
            [[ $# -ge 1 ]] || err "uso: wordpress-fix-permalink <site_user>"
            cmd_wordpress_fix_permalink "$1"
            ;;
        site-fix-rewrite)
            [[ $# -ge 1 ]] || err "uso: site-fix-rewrite <site_user> [front_controller]"
            cmd_site_fix_rewrite "$1" "${2:-index.php}"
            ;;
        htaccess-verify)
            [[ $# -ge 1 ]] || err "uso: htaccess-verify <site_user>"
            cmd_htaccess_verify "$1"
            ;;
        ols-set-admin)
            [[ $# -ge 2 ]] || err "uso: ols-set-admin <usuario> <senha>"
            cmd_ols_set_admin "$1" "$2"
            ;;
        cloudflare-status) cmd_cloudflare_status ;;
        cloudflare-login-start) cmd_cloudflare_login_start ;;
        github-config-status) cmd_github_config_status ;;
        github-config-set)
            [[ $# -ge 4 ]] || err "uso: github-config-set <usuario> <token> <autor_nome> <autor_email>"
            cmd_github_config_set "$1" "$2" "$3" "$4"
            ;;
        github-oauth-app-set)
            [[ $# -ge 1 ]] || err "uso: github-oauth-app-set <client_id> [scopes]"
            cmd_github_oauth_app_set "$1" "${2:-repo read:user user:email}"
            ;;
        github-config-clear) cmd_github_config_clear ;;
        github-device-start) cmd_github_device_start ;;
        github-device-poll) cmd_github_device_poll "${1:-0}" ;;
        github-site-status)
            [[ $# -ge 1 ]] || err "uso: github-site-status <site_user>"
            cmd_github_site_status "$1"
            ;;
        github-repos-list)
            cmd_github_repos_list
            ;;
        github-site-clone-start)
            [[ $# -ge 2 ]] || err "uso: github-site-clone-start <site_user> <owner/repo> [branch] [limpar_destino:0|1]"
            cmd_github_site_clone_start "$1" "$2" "${3:-}" "${4:-0}"
            ;;
        github-site-clone-status)
            [[ $# -ge 1 ]] || err "uso: github-site-clone-status <site_user>"
            cmd_github_site_clone_status "$1"
            ;;
        github-site-clone)
            [[ $# -ge 2 ]] || err "uso: github-site-clone <site_user> <owner/repo> [branch] [limpar_destino:0|1]"
            cmd_github_site_clone "$1" "$2" "${3:-}" "${4:-0}"
            ;;
        github-site-pull)
            [[ $# -ge 1 ]] || err "uso: github-site-pull <site_user>"
            cmd_github_site_pull "$1"
            ;;
        github-site-commit-push)
            [[ $# -ge 2 ]] || err "uso: github-site-commit-push <site_user> <mensagem_commit>"
            cmd_github_site_commit_push "$1" "$2"
            ;;
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
