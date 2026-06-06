#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PAINEL_NOME="Gerenciador Hosting WSL ULTRA"
LSWS_DIR="/usr/local/lsws"
VHOSTS_DIR="${LSWS_DIR}/conf/vhosts"
HTTPD_CONF="${LSWS_DIR}/conf/httpd_config.conf"
SITES_ROOT="/home"
BACKUP_DIR="/root/backups-sites"
CLOUDFLARE_BASE_DIR="/etc/cloudflared"
MYSQL_BIN="mysql"
# Porta HTTP do OpenLiteSpeed usada como origem do Cloudflare Tunnel.
# Em instalações padrão do OLS costuma ser 8088.
OLS_ORIGIN_HTTP_PORT="8088"
PHP_VERSOES_SUPORTADAS=("8.4" "8.3" "8.2" "8.1")
# Domínio base da sua zona no Cloudflare.
# Com FORCAR_DOMINIO_BASE=true:
# - "radio"      -> "radio.i3lab.site"
# - "radio.com"  -> "radio.i3lab.site"
DOMINIO_BASE_PADRAO="i3lab.site"
FORCAR_DOMINIO_BASE="true"
WEB_PANEL_SOURCE_DIR="${SCRIPT_DIR}/web-admin"
WEB_PANEL_INSTALL_DIR="/opt/ultra-web-panel"
WEB_PANEL_API_SCRIPT="${WEB_PANEL_INSTALL_DIR}/script.sh"
WEB_PANEL_HELPER_BIN="/usr/local/sbin/ultra-panel-helper"
WEB_PANEL_SUDOERS_FILE="/etc/sudoers.d/ultra-panel-helper"
WEB_PANEL_USER="painel_srv"
GITHUB_PANEL_CONFIG_DIR="/root/.ultra-panel"
GITHUB_PANEL_CONFIG_FILE="${GITHUB_PANEL_CONFIG_DIR}/github.env"
GITHUB_DEVICE_FLOW_FILE="${GITHUB_PANEL_CONFIG_DIR}/github-device-flow.env"
GITHUB_CLONE_JOBS_DIR="${GITHUB_PANEL_CONFIG_DIR}/clone-jobs"

mkdir -p "$BACKUP_DIR"
mkdir -p "$CLOUDFLARE_BASE_DIR"
mkdir -p "$GITHUB_PANEL_CONFIG_DIR"
mkdir -p "$GITHUB_CLONE_JOBS_DIR"

cor_verde="\033[1;32m"
cor_amarela="\033[1;33m"
cor_vermelha="\033[1;31m"
cor_azul="\033[1;34m"
cor_reset="\033[0m"

msg() { echo -e "${cor_verde}[$(date '+%H:%M:%S')] $*${cor_reset}"; }
aviso() { echo -e "${cor_amarela}[$(date '+%H:%M:%S')] $*${cor_reset}"; }
erro() { echo -e "${cor_vermelha}[$(date '+%H:%M:%S')] $*${cor_reset}"; }

habilitar_reiniciar_servico() {
    local servico="$1"

    if systemctl list-unit-files "${servico}.service" --no-legend 2>/dev/null | grep -q "${servico}\\.service"; then
        systemctl enable "$servico" || aviso "Não foi possível habilitar ${servico}.service"
        systemctl restart "$servico" || aviso "Não foi possível reiniciar ${servico}.service"
    else
        aviso "Serviço ${servico}.service não encontrado no sistema."
    fi
}

garantir_cron_disponivel() {
    if ! command -v crontab >/dev/null 2>&1; then
        aviso "crontab não encontrado. Instalando cronie..."
        if ! dnf install -y cronie; then
            erro "Falha ao instalar cronie."
            return 1
        fi
    fi

    if systemctl list-unit-files "crond.service" --no-legend 2>/dev/null | grep -q "crond\\.service"; then
        systemctl enable --now crond >/dev/null 2>&1 || aviso "Não foi possível habilitar/iniciar crond."
    elif systemctl list-unit-files "cron.service" --no-legend 2>/dev/null | grep -q "cron\\.service"; then
        systemctl enable --now cron >/dev/null 2>&1 || aviso "Não foi possível habilitar/iniciar cron."
    else
        aviso "Serviço de cron não encontrado (crond/cron)."
    fi

    command -v crontab >/dev/null 2>&1
}

titulo() {
    echo
    echo -e "${cor_azul}========================================${cor_reset}"
    echo -e "${cor_azul}${PAINEL_NOME}${cor_reset}"
    echo -e "${cor_azul}========================================${cor_reset}"
    echo
}

pausa() {
    read -rp "Pressione ENTER para continuar..."
}

checar_root() {
    if [[ $EUID -ne 0 ]]; then
        erro "Execute como root."
        exit 1
    fi
}

checar_systemd() {
    if ! pidof systemd >/dev/null 2>&1; then
        aviso "systemd não parece estar ativo."
        echo "No WSL, configure /etc/wsl.conf com:"
        echo "[boot]"
        echo "systemd=true"
        echo
        echo "Depois rode no Windows:"
        echo "wsl --shutdown"
        echo
    fi
}

nome_site_para_usuario() {
    local dominio="$1"
    local dominio_normalizado
    dominio_normalizado="$(normalizar_dominio "$dominio")"
    validar_dominio "$dominio_normalizado" || return 1

    local user
    user="${dominio_normalizado//./_}"
    user="$(echo "$user" | tr -cd 'a-z0-9_-')"
    [[ -n "$user" ]] || return 1

    if [[ ! "$user" =~ ^[a-z_] ]]; then
        user="u_${user}"
    fi

    if [[ ${#user} -gt 28 ]]; then
        local hash
        hash="$(printf '%s' "$dominio_normalizado" | sha256sum | cut -c1-8)"
        user="${user:0:19}_${hash}"
    fi

    echo "$user"
}

normalizar_dominio() {
    local dominio="$1"
    dominio="$(echo "$dominio" | tr '[:upper:]' '[:lower:]' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/\.$//')"

    if [[ -n "$dominio" && -n "$DOMINIO_BASE_PADRAO" ]]; then
        local base
        base="$(echo "$DOMINIO_BASE_PADRAO" | tr '[:upper:]' '[:lower:]' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/^\.//; s/\.$//')"
        if [[ -n "$base" ]]; then
            local forcar
            forcar="$(echo "$FORCAR_DOMINIO_BASE" | tr '[:upper:]' '[:lower:]')"
            if [[ "$forcar" == "true" ]]; then
                local host_label
                host_label="${dominio%%.*}"
                host_label="$(echo "$host_label" | tr -cd 'a-z0-9-')"
                if [[ -n "$host_label" ]]; then
                    dominio="${host_label}.${base}"
                fi
            elif [[ "$dominio" != *.* ]]; then
                dominio="${dominio}.${base}"
            fi
        fi
    fi

    echo "$dominio"
}

validar_dominio() {
    local dominio="$1"
    [[ "$dominio" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]
}

resolver_usuario_por_dominio() {
    local dominio="$1"
    dominio="$(normalizar_dominio "$dominio")"

    if ! validar_dominio "$dominio"; then
        return 1
    fi

    local user
    user="$(nome_site_para_usuario "$dominio")" || return 1

    if [[ -d "${SITES_ROOT}/${user}" || -d "${VHOSTS_DIR}/${user}" ]]; then
        echo "$user"
        return 0
    fi

    # Compatibilidade com sites antigos criados usando apenas o primeiro label do domínio.
    local user_legado
    user_legado="$(echo "$dominio" | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')"
    if [[ -n "$user_legado" ]] && [[ -d "${SITES_ROOT}/${user_legado}" || -d "${VHOSTS_DIR}/${user_legado}" ]]; then
        echo "$user_legado"
        return 0
    fi

    return 1
}

usuario_valido() {
    local user="$1"
    [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]]
}

validar_php_versao() {
    local versao="$1"
    local item
    for item in "${PHP_VERSOES_SUPORTADAS[@]}"; do
        [[ "$item" == "$versao" ]] && return 0
    done
    return 1
}

remover_diretorio_seguro() {
    local base="$1"
    local alvo="$2"

    if [[ -z "$base" || -z "$alvo" ]]; then
        erro "Falha de segurança: caminho vazio para remoção."
        return 1
    fi

    if [[ "$alvo" == "$base" || "$alvo" == "${base}/" || "$alvo" == "/" ]]; then
        erro "Falha de segurança: remoção bloqueada para caminho base (${alvo})."
        return 1
    fi

    if [[ "$alvo" != "${base}/"* ]]; then
        erro "Falha de segurança: ${alvo} não pertence a ${base}."
        return 1
    fi

    [[ -d "$alvo" ]] && rm -rf "$alvo"
}

gerar_senha() {
    openssl rand -base64 18 | tr -d "=+/" | cut -c1-16
}

bool_sim() {
    local valor
    valor="$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')"
    [[ "$valor" == "1" || "$valor" == "s" || "$valor" == "sim" || "$valor" == "true" || "$valor" == "yes" || "$valor" == "y" ]]
}

github_repo_slug_valido() {
    local slug="${1:-}"
    [[ "$slug" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]
}

github_branch_valida() {
    local branch="${1:-}"
    [[ -n "$branch" ]] || return 1
    [[ "$branch" =~ ^[A-Za-z0-9._/-]{1,120}$ ]] || return 1
    [[ "$branch" != *".."* && "$branch" != */ && "$branch" != /* ]]
}

github_username_valido() {
    local username="${1:-}"
    [[ "$username" =~ ^[A-Za-z0-9-]{1,39}$ ]]
}

github_email_valido() {
    local email="${1:-}"
    [[ "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

github_oauth_client_id_valido() {
    local client_id="${1:-}"
    [[ -n "$client_id" && ${#client_id} -le 120 && "$client_id" != *$'\n'* && "$client_id" != *$'\r'* && "$client_id" != *[[:space:]]* ]]
}

github_oauth_scopes_validos() {
    local scopes="${1:-}"
    [[ -n "$scopes" && ${#scopes} -le 120 ]] || return 1
    [[ "$scopes" =~ ^[A-Za-z0-9:_[:space:]-]+$ ]]
}

github_autor_nome_valido() {
    local name="${1:-}"
    [[ -n "$name" && ${#name} -le 80 && "$name" != *$'\n'* && "$name" != *$'\r'* ]]
}

senha_ssh_site_valida() {
    local senha="${1:-}"
    [[ -n "$senha" && ${#senha} -ge 8 && ${#senha} -le 120 ]] || return 1
    [[ "$senha" != *$'\n'* && "$senha" != *$'\r'* && "$senha" != *:* ]]
}

github_token_valido() {
    local token="${1:-}"
    [[ -n "$token" && ${#token} -ge 20 && "$token" != *$'\n'* && "$token" != *$'\r'* && "$token" != *[[:space:]]* ]]
}

github_commit_msg_valida() {
    local msg_raw="${1:-}"
    [[ -n "$msg_raw" && ${#msg_raw} -le 200 && "$msg_raw" != *$'\n'* && "$msg_raw" != *$'\r'* ]]
}

github_token_mask() {
    local token="${1:-}"
    local len="${#token}"
    if (( len <= 8 )); then
        printf '********'
        return 0
    fi
    printf '%s****%s' "${token:0:4}" "${token: -4}"
}

github_repo_url_https() {
    local slug="${1:-}"
    printf 'https://github.com/%s.git' "$slug"
}

github_repo_dir_por_usuario() {
    local user="${1:-}"
    printf '%s/%s/public_html' "$SITES_ROOT" "$user"
}

github_oauth_scopes_padrao() {
    printf 'repo read:user user:email'
}

github_config_ler() {
    [[ -f "$GITHUB_PANEL_CONFIG_FILE" ]] || return 1

    GITHUB_CFG_USERNAME=""
    GITHUB_CFG_TOKEN=""
    GITHUB_CFG_AUTHOR_NAME=""
    GITHUB_CFG_AUTHOR_EMAIL=""
    GITHUB_CFG_OAUTH_CLIENT_ID=""
    GITHUB_CFG_OAUTH_SCOPES="$(github_oauth_scopes_padrao)"

    # shellcheck disable=SC1090
    source "$GITHUB_PANEL_CONFIG_FILE"

    GITHUB_CFG_USERNAME="${GITHUB_USERNAME:-}"
    GITHUB_CFG_TOKEN="${GITHUB_TOKEN:-}"
    GITHUB_CFG_AUTHOR_NAME="${GITHUB_AUTHOR_NAME:-}"
    GITHUB_CFG_AUTHOR_EMAIL="${GITHUB_AUTHOR_EMAIL:-}"
    GITHUB_CFG_OAUTH_CLIENT_ID="${GITHUB_OAUTH_CLIENT_ID:-}"
    GITHUB_CFG_OAUTH_SCOPES="${GITHUB_OAUTH_SCOPES:-$(github_oauth_scopes_padrao)}"
}

github_config_carregar() {
    github_config_ler || return 1

    [[ -n "$GITHUB_CFG_USERNAME" && -n "$GITHUB_CFG_TOKEN" ]]
}

github_config_escrever() {
    local username="${1:-}"
    local token="${2:-}"
    local author_name="${3:-}"
    local author_email="${4:-}"
    local oauth_client_id="${5:-}"
    local oauth_scopes="${6:-$(github_oauth_scopes_padrao)}"

    mkdir -p "$GITHUB_PANEL_CONFIG_DIR"
    umask 077
    cat > "$GITHUB_PANEL_CONFIG_FILE" <<EOF
GITHUB_USERNAME=$(printf '%q' "$username")
GITHUB_TOKEN=$(printf '%q' "$token")
GITHUB_AUTHOR_NAME=$(printf '%q' "$author_name")
GITHUB_AUTHOR_EMAIL=$(printf '%q' "$author_email")
GITHUB_OAUTH_CLIENT_ID=$(printf '%q' "$oauth_client_id")
GITHUB_OAUTH_SCOPES=$(printf '%q' "$oauth_scopes")
EOF
    chmod 600 "$GITHUB_PANEL_CONFIG_FILE"
}

github_config_salvar() {
    local username="${1:-}"
    local token="${2:-}"
    local author_name="${3:-}"
    local author_email="${4:-}"

    github_config_ler || true
    github_config_escrever \
        "$username" \
        "$token" \
        "$author_name" \
        "$author_email" \
        "${GITHUB_CFG_OAUTH_CLIENT_ID:-}" \
        "${GITHUB_CFG_OAUTH_SCOPES:-$(github_oauth_scopes_padrao)}"
}

github_oauth_app_salvar() {
    local oauth_client_id="${1:-}"
    local oauth_scopes="${2:-$(github_oauth_scopes_padrao)}"

    github_config_ler || true
    github_config_escrever \
        "${GITHUB_CFG_USERNAME:-}" \
        "${GITHUB_CFG_TOKEN:-}" \
        "${GITHUB_CFG_AUTHOR_NAME:-}" \
        "${GITHUB_CFG_AUTHOR_EMAIL:-}" \
        "$oauth_client_id" \
        "$oauth_scopes"
}

github_config_remover() {
    rm -f "$GITHUB_PANEL_CONFIG_FILE"
    rm -f "$GITHUB_DEVICE_FLOW_FILE"
}

github_device_flow_salvar() {
    local device_code="${1:-}"
    local user_code="${2:-}"
    local verification_uri="${3:-}"
    local expires_at="${4:-0}"
    local interval="${5:-5}"
    local client_id="${6:-}"
    local scopes="${7:-$(github_oauth_scopes_padrao)}"

    mkdir -p "$GITHUB_PANEL_CONFIG_DIR"
    umask 077
    cat > "$GITHUB_DEVICE_FLOW_FILE" <<EOF
GITHUB_DEVICE_CODE=$(printf '%q' "$device_code")
GITHUB_DEVICE_USER_CODE=$(printf '%q' "$user_code")
GITHUB_DEVICE_VERIFICATION_URI=$(printf '%q' "$verification_uri")
GITHUB_DEVICE_EXPIRES_AT=$(printf '%q' "$expires_at")
GITHUB_DEVICE_INTERVAL=$(printf '%q' "$interval")
GITHUB_DEVICE_CLIENT_ID=$(printf '%q' "$client_id")
GITHUB_DEVICE_SCOPES=$(printf '%q' "$scopes")
EOF
    chmod 600 "$GITHUB_DEVICE_FLOW_FILE"
}

github_device_flow_ler() {
    [[ -f "$GITHUB_DEVICE_FLOW_FILE" ]] || return 1

    GITHUB_DEVICE_CODE_VALUE=""
    GITHUB_DEVICE_USER_CODE_VALUE=""
    GITHUB_DEVICE_VERIFICATION_URI_VALUE=""
    GITHUB_DEVICE_EXPIRES_AT_VALUE="0"
    GITHUB_DEVICE_INTERVAL_VALUE="5"
    GITHUB_DEVICE_CLIENT_ID_VALUE=""
    GITHUB_DEVICE_SCOPES_VALUE="$(github_oauth_scopes_padrao)"

    # shellcheck disable=SC1090
    source "$GITHUB_DEVICE_FLOW_FILE"

    GITHUB_DEVICE_CODE_VALUE="${GITHUB_DEVICE_CODE:-}"
    GITHUB_DEVICE_USER_CODE_VALUE="${GITHUB_DEVICE_USER_CODE:-}"
    GITHUB_DEVICE_VERIFICATION_URI_VALUE="${GITHUB_DEVICE_VERIFICATION_URI:-}"
    GITHUB_DEVICE_EXPIRES_AT_VALUE="${GITHUB_DEVICE_EXPIRES_AT:-0}"
    GITHUB_DEVICE_INTERVAL_VALUE="${GITHUB_DEVICE_INTERVAL:-5}"
    GITHUB_DEVICE_CLIENT_ID_VALUE="${GITHUB_DEVICE_CLIENT_ID:-}"
    GITHUB_DEVICE_SCOPES_VALUE="${GITHUB_DEVICE_SCOPES:-$(github_oauth_scopes_padrao)}"
}

github_device_flow_limpar() {
    rm -f "$GITHUB_DEVICE_FLOW_FILE"
}

github_device_flow_ativa() {
    github_device_flow_ler || return 1
    [[ "$GITHUB_DEVICE_EXPIRES_AT_VALUE" =~ ^[0-9]+$ ]] || return 1
    (( GITHUB_DEVICE_EXPIRES_AT_VALUE > $(date +%s) ))
}

github_api_user_json() {
    local token="${1:-}"
    curl -fsSL \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer ${token}" \
        https://api.github.com/user
}

github_api_user_emails_json() {
    local token="${1:-}"
    curl -fsSL \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer ${token}" \
        https://api.github.com/user/emails
}

github_api_repos_json() {
    local token="${1:-}"
    curl -fsSL \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer ${token}" \
        'https://api.github.com/user/repos?visibility=all&affiliation=owner,collaborator,organization_member&sort=updated&per_page=100'
}

github_email_primario_por_token() {
    local token="${1:-}"
    local payload
    payload="$(github_api_user_emails_json "$token" 2>/dev/null || true)"
    [[ -n "$payload" ]] || return 1
    echo "$payload" | jq -r 'map(select(.primary == true and .verified == true)) | .[0].email // empty'
}

github_api_payload_error_message() {
    local payload="${1:-}"
    local message=""

    [[ -n "$payload" ]] || return 1
    message="$(echo "$payload" | jq -r '.error_description // .message // .error // empty' 2>/dev/null)"
    [[ -n "$message" ]] || return 1
    printf '%s\n' "$message"
}

github_clone_status_file_por_usuario() {
    local user="${1:-}"
    echo "${GITHUB_CLONE_JOBS_DIR}/${user}.env"
}

github_clone_log_file_por_usuario() {
    local user="${1:-}"
    echo "${GITHUB_CLONE_JOBS_DIR}/${user}.log"
}

github_clone_job_salvar() {
    local user="${1:-}"
    local state="${2:-idle}"
    local job_id="${3:-}"
    local repo_slug="${4:-}"
    local branch="${5:-}"
    local pid="${6:-0}"
    local started_at="${7:-0}"
    local updated_at="${8:-0}"
    local completed_at="${9:-0}"
    local exit_code="${10:-0}"
    local message="${11:-}"
    local log_file="${12:-}"
    local status_file tmp_file

    status_file="$(github_clone_status_file_por_usuario "$user")"
    tmp_file="$(mktemp "${status_file}.tmp.XXXXXX")" || return 1
    cat > "$tmp_file" <<EOF
GITHUB_CLONE_SITE_USER=$(printf '%q' "$user")
GITHUB_CLONE_STATE=$(printf '%q' "$state")
GITHUB_CLONE_JOB_ID=$(printf '%q' "$job_id")
GITHUB_CLONE_REPO=$(printf '%q' "$repo_slug")
GITHUB_CLONE_BRANCH=$(printf '%q' "$branch")
GITHUB_CLONE_PID=$(printf '%q' "$pid")
GITHUB_CLONE_STARTED_AT=$(printf '%q' "$started_at")
GITHUB_CLONE_UPDATED_AT=$(printf '%q' "$updated_at")
GITHUB_CLONE_COMPLETED_AT=$(printf '%q' "$completed_at")
GITHUB_CLONE_EXIT_CODE=$(printf '%q' "$exit_code")
GITHUB_CLONE_MESSAGE=$(printf '%q' "$message")
GITHUB_CLONE_LOG_FILE=$(printf '%q' "$log_file")
EOF
    chmod 600 "$tmp_file"
    mv -f "$tmp_file" "$status_file"
}

github_clone_job_ler() {
    local user="${1:-}"
    local status_file
    status_file="$(github_clone_status_file_por_usuario "$user")"
    [[ -f "$status_file" ]] || return 1

    # shellcheck disable=SC1090
    source "$status_file"

    GITHUB_CLONE_STATE_VALUE="${GITHUB_CLONE_STATE:-idle}"
    GITHUB_CLONE_JOB_ID_VALUE="${GITHUB_CLONE_JOB_ID:-}"
    GITHUB_CLONE_REPO_VALUE="${GITHUB_CLONE_REPO:-}"
    GITHUB_CLONE_BRANCH_VALUE="${GITHUB_CLONE_BRANCH:-}"
    GITHUB_CLONE_PID_VALUE="${GITHUB_CLONE_PID:-0}"
    GITHUB_CLONE_STARTED_AT_VALUE="${GITHUB_CLONE_STARTED_AT:-0}"
    GITHUB_CLONE_UPDATED_AT_VALUE="${GITHUB_CLONE_UPDATED_AT:-0}"
    GITHUB_CLONE_COMPLETED_AT_VALUE="${GITHUB_CLONE_COMPLETED_AT:-0}"
    GITHUB_CLONE_EXIT_CODE_VALUE="${GITHUB_CLONE_EXIT_CODE:-0}"
    GITHUB_CLONE_MESSAGE_VALUE="${GITHUB_CLONE_MESSAGE:-}"
    GITHUB_CLONE_LOG_FILE_VALUE="${GITHUB_CLONE_LOG_FILE:-$(github_clone_log_file_por_usuario "$user")}"
}

github_clone_job_pid_ativo() {
    local pid="${1:-0}"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    (( pid > 0 )) || return 1
    kill -0 "$pid" >/dev/null 2>&1
}

github_clone_job_esta_rodando() {
    local user="${1:-}"
    github_clone_job_ler "$user" || return 1
    [[ "$GITHUB_CLONE_STATE_VALUE" == "running" ]] || return 1
    github_clone_job_pid_ativo "$GITHUB_CLONE_PID_VALUE"
}

github_clone_job_marcar_stale() {
    local user="${1:-}"
    github_clone_job_ler "$user" || return 1
    [[ "$GITHUB_CLONE_STATE_VALUE" == "running" ]] || return 0
    if github_clone_job_pid_ativo "$GITHUB_CLONE_PID_VALUE"; then
        return 0
    fi

    github_clone_job_salvar \
        "$user" \
        "error" \
        "$GITHUB_CLONE_JOB_ID_VALUE" \
        "$GITHUB_CLONE_REPO_VALUE" \
        "$GITHUB_CLONE_BRANCH_VALUE" \
        "$GITHUB_CLONE_PID_VALUE" \
        "$GITHUB_CLONE_STARTED_AT_VALUE" \
        "$(date +%s)" \
        "$(date +%s)" \
        "1" \
        "O processo de clone foi encerrado inesperadamente." \
        "$GITHUB_CLONE_LOG_FILE_VALUE"
}

github_clone_job_percentual_por_log() {
    local log_file="${1:-}"
    local line percent phase weight

    [[ -f "$log_file" ]] || {
        printf '0|Preparando clone|Aguardando saida do git.\n'
        return 0
    }

    line="$(grep -E 'Receiving objects:|Resolving deltas:|Updating files:|Compressing objects:|remote: Enumerating objects:' "$log_file" 2>/dev/null | tail -n 1)"
    if [[ -z "$line" ]]; then
        printf '5|Preparando clone|Iniciando conexao com o GitHub.\n'
        return 0
    fi

    if [[ "$line" =~ Receiving\ objects:[[:space:]]*([0-9]+)% ]]; then
        percent="${BASH_REMATCH[1]}"
        weight=$(( 30 + (percent * 55 / 100) ))
        printf '%s|Recebendo objetos|%s\n' "$weight" "$line"
        return 0
    fi

    if [[ "$line" =~ Resolving\ deltas:[[:space:]]*([0-9]+)% ]]; then
        percent="${BASH_REMATCH[1]}"
        weight=$(( 85 + (percent * 15 / 100) ))
        printf '%s|Resolvendo deltas|%s\n' "$weight" "$line"
        return 0
    fi

    if [[ "$line" =~ Updating\ files:[[:space:]]*([0-9]+)% ]]; then
        percent="${BASH_REMATCH[1]}"
        weight=$(( 92 + (percent * 8 / 100) ))
        printf '%s|Atualizando arquivos|%s\n' "$weight" "$line"
        return 0
    fi

    if [[ "$line" =~ Compressing\ objects:[[:space:]]*([0-9]+)% ]]; then
        percent="${BASH_REMATCH[1]}"
        weight=$(( 15 + (percent * 15 / 100) ))
        printf '%s|Comprimindo objetos|%s\n' "$weight" "$line"
        return 0
    fi

    if [[ "$line" == *"Enumerating objects:"* ]]; then
        printf '10|Enumerando objetos|%s\n' "$line"
        return 0
    fi

    printf '5|Preparando clone|%s\n' "$line"
}

github_json_int_or_zero() {
    local value="${1:-0}"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$value"
    else
        printf '0\n'
    fi
}

github_git_exec_por_usuario() {
    local user="${1:-}"
    local usar_auth="${2:-0}"
    shift 2 || true

    local home_dir="${SITES_ROOT}/${user}"
    local askpass=""
    local -a cmd
    cmd=(env "HOME=${home_dir}" "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "GIT_TERMINAL_PROMPT=0")

    if bool_sim "$usar_auth"; then
        github_config_carregar || {
            erro "Credenciais do GitHub nao configuradas."
            return 1
        }

        askpass="$(mktemp)"
        cat > "$askpass" <<'EOF'
#!/bin/sh
case "$1" in
    *Username*|*username*) printf '%s\n' "${GITHUB_USERNAME:-}" ;;
    *) printf '%s\n' "${GITHUB_TOKEN:-}" ;;
esac
EOF
        chmod 755 "$askpass"
        cmd+=("GIT_ASKPASS=${askpass}" "GITHUB_USERNAME=${GITHUB_CFG_USERNAME}" "GITHUB_TOKEN=${GITHUB_CFG_TOKEN}")
    fi

    local status=0
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$user" -- "${cmd[@]}" "$@" || status=$?
    elif command -v sudo >/dev/null 2>&1; then
        sudo -u "$user" "${cmd[@]}" "$@" || status=$?
    else
        erro "Nem runuser nem sudo estao disponiveis para executar Git como o usuario do site."
        status=1
    fi

    if [[ -n "$askpass" ]]; then
        rm -f "$askpass"
    fi

    return "$status"
}

github_repo_existe_por_usuario() {
    local user="${1:-}"
    local repo_dir
    repo_dir="$(github_repo_dir_por_usuario "$user")"
    [[ -d "${repo_dir}/.git" ]]
}

instalar_repos() {
    msg "Instalando repositórios..."
    dnf update -y
    dnf install -y epel-release curl wget nano unzip tar jq openssl git which policycoreutils-python-utils cronie

    if ! rpm -qa | grep -qi litespeed-repo; then
        msg "Configurando repositório oficial LiteSpeed..."
        if ! wget -O - https://repo.litespeed.sh | bash; then
            erro "Falha ao configurar repositório LiteSpeed via repo.litespeed.sh"
            return 1
        fi
    fi

    msg "Configurando repositório oficial do Cloudflare (cloudflared)..."
    curl -fsSL https://pkg.cloudflare.com/cloudflared.repo -o /etc/yum.repos.d/cloudflared.repo

    dnf makecache -y
}

instalar_openlitespeed_php() {
    msg "Instalando OpenLiteSpeed e versões PHP..."
    local -a sufixos_php=(
        ""
        "-common"
        "-cli"
        "-curl"
        "-gd"
        "-intl"
        "-mysqlnd"
        "-opcache"
        "-xml"
        "-mbstring"
        "-zip"
        "-bcmath"
        "-process"
        "-pecl-redis"
    )
    local -a desejados=("openlitespeed")
    local -a instalar=()
    local -a faltando=()
    local versao
    local sufixo
    local pacote

    for versao in "${PHP_VERSOES_SUPORTADAS[@]}"; do
        local major="${versao//./}"
        for sufixo in "${sufixos_php[@]}"; do
            desejados+=("lsphp${major}${sufixo}")
        done
    done

    for pacote in "${desejados[@]}"; do
        if rpm -q "$pacote" >/dev/null 2>&1 \
            || dnf -q --setopt=logfile=/tmp/gerenciador-hosting-dnf.log list --available "$pacote" >/dev/null 2>&1; then
            instalar+=("$pacote")
        else
            faltando+=("$pacote")
        fi
    done

    local ols_ok=0
    for pacote in "${instalar[@]}"; do
        if [[ "$pacote" == "openlitespeed" ]]; then
            ols_ok=1
            break
        fi
    done

    if [[ $ols_ok -ne 1 ]]; then
        erro "Pacote openlitespeed não disponível no repositório configurado."
        return 1
    fi

    msg "Instalando ${#instalar[@]} pacotes disponíveis do OpenLiteSpeed/PHP..."
    dnf install -y "${instalar[@]}"

    if [[ ${#faltando[@]} -gt 0 ]]; then
        aviso "Pacotes não encontrados e ignorados: ${faltando[*]}"
    fi
}

instalar_banco_redis_cf() {
    msg "Instalando MariaDB, Redis e cloudflared..."
    dnf install -y mariadb-server redis

    if ! dnf install -y cloudflared; then
        aviso "Falha no repositório do cloudflared. Tentando pacote direto do GitHub..."
        curl -fL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-x86_64.rpm -o /tmp/cloudflared.rpm
        dnf install -y /tmp/cloudflared.rpm
    fi

    habilitar_reiniciar_servico "mariadb"
    habilitar_reiniciar_servico "redis"
    habilitar_reiniciar_servico "lsws"
    habilitar_reiniciar_servico "crond"
}

phpmyadmin_origem_dir() {
    local -a candidatos=(
        "/usr/share/phpMyAdmin"
        "/usr/share/phpmyadmin"
    )
    local dir

    for dir in "${candidatos[@]}"; do
        if [[ -d "$dir" && -f "${dir}/index.php" ]]; then
            echo "$dir"
            return 0
        fi
    done

    return 1
}

dominio_padrao_phpmyadmin() {
    local dominio_padrao
    dominio_padrao="$(normalizar_dominio "db")"
    if validar_dominio "$dominio_padrao"; then
        echo "$dominio_padrao"
        return 0
    fi

    return 1
}

instalar_phpmyadmin() {
    msg "Instalando phpMyAdmin..."

    local -a pacotes_phpmyadmin=("phpMyAdmin" "phpmyadmin")
    local pacote
    local instalado=0

    for pacote in "${pacotes_phpmyadmin[@]}"; do
        if rpm -q "$pacote" >/dev/null 2>&1; then
            instalado=1
            break
        fi
    done

    if [[ $instalado -ne 1 ]]; then
        local instalou=0
        for pacote in "${pacotes_phpmyadmin[@]}"; do
            if dnf install -y "$pacote"; then
                instalou=1
                break
            fi
        done

        if [[ $instalou -ne 1 ]]; then
            erro "Falha ao instalar phpMyAdmin."
            return 1
        fi
    fi

    if ! phpmyadmin_origem_dir >/dev/null 2>&1; then
        erro "phpMyAdmin instalado, mas diretório web não foi encontrado."
        return 1
    fi
}

despublicar_phpmyadmin_dos_sites() {
    local user_excecao="${1:-}"
    local pma_origem
    local removidos=0
    local dir
    pma_origem="$(phpmyadmin_origem_dir || true)"

    for dir in "$VHOSTS_DIR"/*; do
        [[ -d "$dir" ]] || continue

        local user
        local alvo
        local destino

        user="$(basename "$dir")"
        [[ -n "$user_excecao" && "$user" == "$user_excecao" ]] && continue

        alvo="${SITES_ROOT}/${user}/public_html/phpmyadmin"
        [[ -L "$alvo" ]] || continue

        destino="$(readlink "$alvo" || true)"
        if [[ -n "$pma_origem" && "$destino" != "$pma_origem" ]]; then
            continue
        fi

        rm -f "$alvo"
        removidos=$((removidos + 1))
    done

    if [[ $removidos -gt 0 ]]; then
        msg "Removido /phpmyadmin de ${removidos} site(s)."
    fi
}

configurar_phpmyadmin_dominio_principal() {
    titulo

    local dominio
    local dominio_padrao
    dominio_padrao="$(dominio_padrao_phpmyadmin || true)"
    if [[ -n "$dominio_padrao" ]]; then
        read -rp "Domínio principal do phpMyAdmin (ENTER para ${dominio_padrao}): " dominio
        dominio="${dominio:-$dominio_padrao}"
    else
        read -rp "Domínio principal do phpMyAdmin (ex: db.seudominio.com): " dominio
    fi
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user="phpmyadmin_srv"
    local user_existente
    user_existente="$(resolver_usuario_por_dominio "$dominio" || true)"
    if [[ -n "$user_existente" && "$user_existente" != "$user" ]]; then
        erro "Esse domínio já está em uso por outro site: ${user_existente}"
        return
    fi

    local root_dir="${SITES_ROOT}/${user}"
    if ! usuario_valido "$user"; then
        erro "Usuário inválido para phpMyAdmin: ${user}"
        return
    fi

    instalar_phpmyadmin || return
    criar_usuario_linux "$user" "$root_dir"

    mkdir -p "${root_dir}" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"
    chown -R "${user}:${user}" "$root_dir"
    chmod 755 "${root_dir}" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"

    local pma_origem
    pma_origem="$(phpmyadmin_origem_dir)"
    local public_html="${root_dir}/public_html"

    if [[ -e "$public_html" && ! -d "$public_html" && ! -L "$public_html" ]]; then
        erro "Caminho inválido: ${public_html}"
        return
    fi

    if [[ -L "$public_html" ]]; then
        rm -f "$public_html"
    elif [[ -d "$public_html" ]]; then
        rm -rf "$public_html"
    fi

    ln -s "$pma_origem" "$public_html"
    chown -h "${user}:${user}" "$public_html" >/dev/null 2>&1 || true

    local php_versao="8.4"
    criar_vhconf "$user" "$dominio" "$root_dir" "$php_versao"
    adicionar_vhost_httpd_conf "$user" "$dominio" "$root_dir"
    gerar_cert_local_selfsigned "$user" "$root_dir" "$dominio"

    local remover_outros
    read -rp "Remover /phpmyadmin dos demais sites? (s/n) [s]: " remover_outros
    remover_outros="${remover_outros:-s}"
    if [[ "$remover_outros" =~ ^[Ss]$ ]]; then
        despublicar_phpmyadmin_dos_sites "$user"
    fi

    local criar_cf
    read -rp "Criar tunnel individual do Cloudflare para esse domínio? (s/n): " criar_cf
    if [[ "$criar_cf" =~ ^[Ss]$ ]]; then
        criar_tunnel_site "$user" "$dominio"
    fi

    systemctl restart lsws || true

    msg "Domínio principal do phpMyAdmin configurado."
    echo "Acesso: https://${dominio}"
    echo "Usuário Linux dedicado: ${user}"
}

instalar_arquivos_painel_web() {
    if [[ ! -d "${WEB_PANEL_SOURCE_DIR}/public" || ! -f "${WEB_PANEL_SOURCE_DIR}/public/index.php" ]]; then
        erro "Arquivos do painel web não encontrados em ${WEB_PANEL_SOURCE_DIR}."
        return 1
    fi

    if [[ ! -f "${WEB_PANEL_SOURCE_DIR}/ultra-panel-helper.sh" ]]; then
        erro "Helper do painel web não encontrado em ${WEB_PANEL_SOURCE_DIR}/ultra-panel-helper.sh."
        return 1
    fi

    if ! command -v sudo >/dev/null 2>&1; then
        aviso "sudo não encontrado. Instalando..."
        if ! dnf install -y sudo; then
            erro "Falha ao instalar sudo."
            return 1
        fi
    fi

    mkdir -p "$WEB_PANEL_INSTALL_DIR"
    rm -rf "${WEB_PANEL_INSTALL_DIR:?}/public" "${WEB_PANEL_INSTALL_DIR:?}/config" "${WEB_PANEL_INSTALL_DIR:?}/README.md"
    cp -a "${WEB_PANEL_SOURCE_DIR}/." "$WEB_PANEL_INSTALL_DIR/"
    chmod -R a+rX "$WEB_PANEL_INSTALL_DIR"
    install -m 700 -o root -g root "$0" "$WEB_PANEL_API_SCRIPT"

    install -m 750 -o root -g root "${WEB_PANEL_SOURCE_DIR}/ultra-panel-helper.sh" "$WEB_PANEL_HELPER_BIN"

    cat > "$WEB_PANEL_SUDOERS_FILE" <<EOF
Defaults:${WEB_PANEL_USER} !requiretty
${WEB_PANEL_USER} ALL=(root) NOPASSWD: ${WEB_PANEL_HELPER_BIN} *
EOF
    chmod 440 "$WEB_PANEL_SUDOERS_FILE"

    if ! visudo -cf "$WEB_PANEL_SUDOERS_FILE" >/dev/null 2>&1; then
        rm -f "$WEB_PANEL_SUDOERS_FILE"
        erro "Arquivo sudoers do painel web inválido; configuração revertida."
        return 1
    fi
}

sincronizar_public_html_painel_web() {
    local user="${1:-$WEB_PANEL_USER}"
    local root_dir="${2:-${SITES_ROOT}/${user}}"
    local public_html="${root_dir}/public_html"

    if [[ ! -d "${WEB_PANEL_INSTALL_DIR}/public" || ! -f "${WEB_PANEL_INSTALL_DIR}/public/index.php" ]]; then
        erro "Arquivos instalados do painel web nao encontrados em ${WEB_PANEL_INSTALL_DIR}/public."
        return 1
    fi
    if ! usuario_valido "$user"; then
        erro "Usuario invalido para sincronizar painel web: ${user}"
        return 1
    fi
    if [[ -e "$public_html" && ! -d "$public_html" && ! -L "$public_html" ]]; then
        erro "Caminho invalido: ${public_html}"
        return 1
    fi

    if [[ -L "$public_html" ]]; then
        rm -f "$public_html"
    fi
    if [[ ! -d "$public_html" ]]; then
        mkdir -p "$public_html"
    fi

    find "$public_html" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    cp -a "${WEB_PANEL_INSTALL_DIR}/public/." "$public_html/"
    chown -R "${user}:${user}" "$public_html"
    chmod -R u+rwX,go+rX "$public_html"
}

atualizar_painel_web_instalado() {
    titulo

    local user="$WEB_PANEL_USER"
    local root_dir="${SITES_ROOT}/${user}"
    local dominio_atual=""

    msg "Atualizando arquivos internos do painel web..."
    instalar_arquivos_painel_web || return
    garantir_comando_php_cli >/dev/null 2>&1 || true

    if [[ -d "$root_dir" && -d "${VHOSTS_DIR}/${user}" ]]; then
        msg "Sincronizando public_html publicado do painel..."
        sincronizar_public_html_painel_web "$user" "$root_dir" || return
        dominio_atual="$(api_dominio_por_usuario "$user" || true)"
        systemctl restart lsws >/dev/null 2>&1 || true

        msg "Painel web atualizado com sucesso."
        if [[ -n "$dominio_atual" ]]; then
            echo "Dominio atual: https://${dominio_atual}"
        fi
        echo "Arquivos publicados: ${root_dir}/public_html"
        echo "Helper atualizado em: ${WEB_PANEL_HELPER_BIN}"
        echo "Script API atualizado em: ${WEB_PANEL_API_SCRIPT}"
    else
        aviso "Painel web ainda nao esta publicado em dominio proprio."
        echo "Os arquivos base foram atualizados em ${WEB_PANEL_INSTALL_DIR}."
        echo "Depois use a opcao 20 para publicar/configurar o dominio do painel."
    fi
}

configurar_painel_web_dominio_principal() {
    titulo

    local dominio
    read -rp "Domínio principal do painel web (ex: painel.seudominio.com): " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user="$WEB_PANEL_USER"
    local user_existente
    user_existente="$(resolver_usuario_por_dominio "$dominio" || true)"
    if [[ -n "$user_existente" && "$user_existente" != "$user" ]] \
        && [[ -d "${SITES_ROOT}/${user_existente}" || -d "${VHOSTS_DIR}/${user_existente}" ]]; then
        erro "Esse domínio já está em uso por outro site: ${user_existente}"
        return
    fi

    if ! usuario_valido "$user"; then
        erro "Usuário inválido para painel web: ${user}"
        return
    fi

    local root_dir="${SITES_ROOT}/${user}"
    instalar_arquivos_painel_web || return
    garantir_comando_php_cli || true

    criar_usuario_linux "$user" "$root_dir"
    mkdir -p "${root_dir}" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"
    chown -R "${user}:${user}" "$root_dir"
    chmod 755 "${root_dir}" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"

    local public_html="${root_dir}/public_html"
    if [[ -e "$public_html" && ! -d "$public_html" && ! -L "$public_html" ]]; then
        erro "Caminho inválido: ${public_html}"
        return
    fi

    if [[ -L "$public_html" ]]; then
        rm -f "$public_html"
    fi
    if [[ ! -d "$public_html" ]]; then
        mkdir -p "$public_html"
    fi

    find "$public_html" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    cp -a "${WEB_PANEL_INSTALL_DIR}/public/." "$public_html/"
    chown -R "${user}:${user}" "$public_html"
    chmod -R u+rwX,go+rX "$public_html"

    local panel_pass panel_hash
    panel_pass="$(gerar_senha)"
    local hash_script
    hash_script="$(mktemp)"
    cat > "$hash_script" <<'EOF'
<?php
if (!isset($argv[1])) {
    exit(1);
}
echo password_hash($argv[1], PASSWORD_DEFAULT);
EOF
    panel_hash="$(php "$hash_script" "$panel_pass" 2>/dev/null || true)"
    rm -f "$hash_script"
    if [[ -z "$panel_hash" || "$panel_hash" != \$2* && "$panel_hash" != \$argon2* ]]; then
        erro "Não foi possível gerar hash da senha do painel."
        return
    fi

    local panel_config_dir="${root_dir}/.ultra-panel"
    mkdir -p "$panel_config_dir"
    chown "${user}:${user}" "$panel_config_dir"
    chmod 700 "$panel_config_dir"

    cat > "${panel_config_dir}/panel.env" <<EOF
PANEL_TITLE=ULTRA Web Panel
PANEL_USER=admin
PANEL_PASS_HASH=${panel_hash}
EOF
    chown "${user}:${user}" "${panel_config_dir}/panel.env"
    chmod 600 "${panel_config_dir}/panel.env"

    local cred_file="/root/${user}_credenciais.txt"
    cat > "$cred_file" <<EOF
DOMINIO=${dominio}
URL=https://${dominio}
USUARIO=admin
SENHA=${panel_pass}
EOF
    chmod 600 "$cred_file"

    local php_versao="8.4"
    criar_vhconf "$user" "$dominio" "$root_dir" "$php_versao"
    adicionar_vhost_httpd_conf "$user" "$dominio" "$root_dir"
    gerar_cert_local_selfsigned "$user" "$root_dir" "$dominio"

    local criar_cf
    read -rp "Criar tunnel individual do Cloudflare para o painel? (s/n): " criar_cf
    if [[ "$criar_cf" =~ ^[Ss]$ ]]; then
        criar_tunnel_site "$user" "$dominio"
    fi

    systemctl restart lsws || true

    msg "Painel web configurado com sucesso."
    echo "Acesso: https://${dominio}"
    echo "Credenciais salvas em: ${cred_file}"
}

inicializar_ols() {
    mkdir -p "$VHOSTS_DIR"

    if [[ ! -f "$HTTPD_CONF" ]]; then
        erro "Arquivo $HTTPD_CONF não encontrado."
        exit 1
    fi
}

instalar_stack_completa() {
    titulo
    instalar_repos
    instalar_openlitespeed_php
    garantir_comando_php_cli || true
    instalar_banco_redis_cf
    instalar_phpmyadmin || aviso "phpMyAdmin não foi instalado automaticamente."
    inicializar_ols
    msg "Stack base instalada com sucesso."
    echo "Painel OpenLiteSpeed: http://localhost:7080"
    echo "Definir senha admin: /usr/local/lsws/admin/misc/admpass.sh"
    echo

    local fazer_login_cf
    read -rp "Fazer login no Cloudflare agora? (s/n) [s]: " fazer_login_cf
    fazer_login_cf="${fazer_login_cf:-s}"
    if [[ "$fazer_login_cf" =~ ^[Ss]$ ]]; then
        cloudflared tunnel login || aviso "Login no Cloudflare não concluído."
    else
        aviso "Login no Cloudflare ignorado nesta etapa."
    fi

    local configurar_painel
    read -rp "Configurar domínio principal do painel web agora? (s/n) [s]: " configurar_painel
    configurar_painel="${configurar_painel:-s}"
    if [[ "$configurar_painel" =~ ^[Ss]$ ]]; then
        configurar_painel_web_dominio_principal || aviso "Falha ao configurar domínio do painel web."
    fi

    local configurar_phpmyadmin
    read -rp "Configurar domínio principal do phpMyAdmin agora? (s/n) [s]: " configurar_phpmyadmin
    configurar_phpmyadmin="${configurar_phpmyadmin:-s}"
    if [[ "$configurar_phpmyadmin" =~ ^[Ss]$ ]]; then
        configurar_phpmyadmin_dominio_principal || aviso "Falha ao configurar domínio do phpMyAdmin."
    fi

    echo
    msg "Instalação guiada concluída."
    echo "Operação diária recomendada: usar o painel web para criar/gerenciar sites e bancos."
}

login_cloudflare() {
    titulo
    cloudflared tunnel login
    msg "Login no Cloudflare concluído."
}

php_bin_por_versao() {
    local versao="$1"
    case "$versao" in
        8.4) echo "/usr/local/lsws/lsphp84/bin/lsphp" ;;
        8.3) echo "/usr/local/lsws/lsphp83/bin/lsphp" ;;
        8.2) echo "/usr/local/lsws/lsphp82/bin/lsphp" ;;
        8.1) echo "/usr/local/lsws/lsphp81/bin/lsphp" ;;
        *) echo "/usr/local/lsws/lsphp84/bin/lsphp" ;;
    esac
}

lsphp_handler_nome() {
    local versao="$1"
    echo "lsphp$(echo "$versao" | tr -d '.')"
}

php_bin_site() {
    local user="$1"
    local vhconf="${VHOSTS_DIR}/${user}/vhconf.conf"
    local php_bin=""

    if [[ -f "$vhconf" ]]; then
        php_bin="$(awk '$1 == "path" {print $2; exit}' "$vhconf")"
    fi

    if [[ -z "$php_bin" ]]; then
        php_bin="$(php_bin_por_versao "8.4")"
    fi

    if [[ -n "$php_bin" && -x "$php_bin" ]]; then
        echo "$php_bin"
        return 0
    fi

    if command -v php >/dev/null 2>&1; then
        command -v php
        return 0
    fi

    return 1
}

garantir_comando_php_cli() {
    local profile_file="/etc/profile.d/ultra-path.sh"
    cat > "$profile_file" <<'EOF'
# Garante /usr/local/bin no PATH de shells de login.
case ":$PATH:" in
    *:/usr/local/bin:*) ;;
    *) export PATH="/usr/local/bin:$PATH" ;;
esac
EOF
    chmod 644 "$profile_file"

    if command -v php >/dev/null 2>&1; then
        return 0
    fi

    local php_padrao=""
    local versao
    for versao in "${PHP_VERSOES_SUPORTADAS[@]}"; do
        local candidato
        candidato="$(php_bin_por_versao "$versao")"
        if [[ -x "$candidato" ]]; then
            php_padrao="$candidato"
            break
        fi
    done

    [[ -n "$php_padrao" ]] || return 0

    local wrapper_bin="/usr/local/bin/php-ultra"
    cat > "$wrapper_bin" <<EOF
#!/bin/bash
set -euo pipefail

user="\${SUDO_USER:-\${LOGNAME:-\${USER:-\$(id -un)}}}"
if [[ -n "\${user}" && "\${user}" =~ ^[a-z_][a-z0-9_-]*\$ ]]; then
    vhconf="${VHOSTS_DIR}/\${user}/vhconf.conf"
    if [[ -r "\${vhconf}" ]]; then
        php_bin="\$(awk '\$1 == "path" {print \$2; exit}' "\${vhconf}")"
        if [[ -n "\${php_bin}" && -x "\${php_bin}" ]]; then
            exec "\${php_bin}" "\$@"
        fi
    fi
fi

exec "${php_padrao}" "\$@"
EOF
    chmod 755 "$wrapper_bin"

    if [[ ! -e /usr/local/bin/php ]]; then
        ln -s "$wrapper_bin" /usr/local/bin/php
    fi
    if [[ ! -e /usr/bin/php ]]; then
        ln -s /usr/local/bin/php /usr/bin/php
    fi
}

criar_usuario_linux() {
    local user="$1"
    local root_dir="$2"

    if ! id "$user" >/dev/null 2>&1; then
        useradd -m -d "$root_dir" -s /bin/bash "$user"
        passwd -l "$user" >/dev/null 2>&1 || true
    fi

    usermod -d "$root_dir" "$user" >/dev/null 2>&1 || true
}

configurar_estrutura_site() {
    local user="$1"
    local root_dir="$2"

    mkdir -p "${root_dir}/public_html" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"
    chown -R "${user}:${user}" "$root_dir"
    chmod 755 "$root_dir" "${root_dir}/public_html" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"
}

criar_env_site() {
    local user="$1"
    local root_dir="$2"
    local db="$3"
    local dbuser="$4"
    local dbpass="$5"
    local dominio="$6"

    cat > "${root_dir}/public_html/.env" <<EOF
APP_NAME=${dominio}
APP_ENV=production
APP_DEBUG=false
APP_URL=https://${dominio}

DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=${db}
DB_USERNAME=${dbuser}
DB_PASSWORD=${dbpass}

REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=
EOF

    chown "${user}:${user}" "${root_dir}/public_html/.env"
    chmod 600 "${root_dir}/public_html/.env"
}

criar_index_padrao() {
    local user="$1"
    local root_dir="$2"
    local dominio="$3"

    if [[ ! -f "${root_dir}/public_html/index.php" ]]; then
        cat > "${root_dir}/public_html/index.php" <<EOF
<?php
echo "<h1>${dominio}</h1>";
echo "<p>Site criado com sucesso.</p>";
echo "<p>Usuário Linux: ${user}</p>";
echo "<p>Servidor: OpenLiteSpeed</p>";
EOF
        chown "${user}:${user}" "${root_dir}/public_html/index.php"
        chmod 644 "${root_dir}/public_html/index.php"
    fi
}

criar_banco() {
    local user="$1"
    local db="${user}_db"
    local dbuser="${user}_user"
    local dbpass
    dbpass="$(gerar_senha)"

    $MYSQL_BIN -e "CREATE DATABASE IF NOT EXISTS \`${db}\`;"
    $MYSQL_BIN -e "CREATE USER IF NOT EXISTS '${dbuser}'@'localhost' IDENTIFIED BY '${dbpass}';"
    $MYSQL_BIN -e "GRANT ALL PRIVILEGES ON \`${db}\`.* TO '${dbuser}'@'localhost'; FLUSH PRIVILEGES;"

    cat > "/root/${user}_db.txt" <<EOF
BANCO=${db}
USUARIO=${dbuser}
SENHA=${dbpass}
EOF
    chmod 600 "/root/${user}_db.txt"

    echo "${db}|${dbuser}|${dbpass}"
}

proximo_sufixo_banco_adicional() {
    local user="$1"
    local idx=1
    local candidato=""

    while [[ $idx -le 999 ]]; do
        candidato="${user}_extra${idx}_db"
        if ! $MYSQL_BIN -Nse "SHOW DATABASES LIKE '${candidato}';" | grep -qx "$candidato"; then
            echo "extra${idx}"
            return 0
        fi
        idx=$((idx + 1))
    done

    return 1
}

criar_banco_adicional_site() {
    titulo

    local dominio
    read -rp "Host/Subdomínio do site (ex: radio): " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }
    if ! usuario_valido "$user"; then
        erro "Usuário inválido para domínio: ${user}"
        return
    fi

    local sufixo_padrao
    sufixo_padrao="$(proximo_sufixo_banco_adicional "$user" || true)"
    sufixo_padrao="${sufixo_padrao:-extra1}"

    local sufixo
    read -rp "Sufixo do banco adicional [${sufixo_padrao}]: " sufixo
    sufixo="${sufixo:-$sufixo_padrao}"
    sufixo="$(echo "$sufixo" | tr '[:upper:]-' '[:lower:]_' | tr -cd 'a-z0-9_' | sed -E 's/^_+//; s/_+$//')"

    if [[ -z "$sufixo" ]]; then
        erro "Sufixo inválido. Use apenas letras, números, '_' ou '-'."
        return
    fi

    if [[ ${#sufixo} -gt 20 ]]; then
        aviso "Sufixo maior que 20 caracteres; será truncado."
        sufixo="${sufixo:0:20}"
    fi

    local db="${user}_${sufixo}_db"
    local dbuser="${user}_${sufixo}_user"

    if $MYSQL_BIN -Nse "SHOW DATABASES LIKE '${db}';" | grep -qx "$db"; then
        erro "Banco já existe: ${db}"
        return
    fi

    if $MYSQL_BIN -Nse "SELECT User FROM mysql.user WHERE User='${dbuser}' AND Host='localhost';" | grep -qx "$dbuser"; then
        erro "Usuário de banco já existe: ${dbuser}"
        return
    fi

    local dbpass
    dbpass="$(gerar_senha)"

    $MYSQL_BIN -e "CREATE DATABASE \`${db}\`;"
    $MYSQL_BIN -e "CREATE USER '${dbuser}'@'localhost' IDENTIFIED BY '${dbpass}';"
    $MYSQL_BIN -e "GRANT ALL PRIVILEGES ON \`${db}\`.* TO '${dbuser}'@'localhost'; FLUSH PRIVILEGES;"

    local arquivo_db_extra="/root/${user}_db_extra.txt"
    cat >> "$arquivo_db_extra" <<EOF
CRIADO_EM=$(date '+%Y-%m-%d %H:%M:%S')
DOMINIO=${dominio}
BANCO=${db}
USUARIO=${dbuser}
SENHA=${dbpass}
---
EOF
    chmod 600 "$arquivo_db_extra"

    msg "Banco adicional criado com sucesso."
    echo "Domínio: ${dominio}"
    echo "Banco: ${db}"
    echo "Usuário banco: ${dbuser}"
    echo "Senha banco: ${dbpass}"
    echo "Credenciais adicionais: ${arquivo_db_extra}"
}

gerar_cert_local_selfsigned() {
    local user="$1"
    local root_dir="$2"
    local dominio="$3"

    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "${root_dir}/ssl/${dominio}.key" \
        -out "${root_dir}/ssl/${dominio}.crt" \
        -subj "/C=BR/ST=Local/L=Local/O=Dev/CN=${dominio}" >/dev/null 2>&1

    chown "${user}:${user}" "${root_dir}/ssl/${dominio}.key" "${root_dir}/ssl/${dominio}.crt"
    chmod 600 "${root_dir}/ssl/${dominio}.key"
    chmod 644 "${root_dir}/ssl/${dominio}.crt"
}

criar_vhconf() {
    local user="$1"
    local dominio="$2"
    local root_dir="$3"
    local php_versao="$4"
    local handler
    local php_bin

    handler="$(lsphp_handler_nome "$php_versao")"
    php_bin="$(php_bin_por_versao "$php_versao")"

    mkdir -p "${VHOSTS_DIR}/${user}"

    cat > "${VHOSTS_DIR}/${user}/vhconf.conf" <<EOF
docRoot                   ${root_dir}/public_html/
vhDomain                  ${dominio}
vhAliases                 www.${dominio}
adminEmails               admin@${dominio}

index  {
  useServer               0
  indexFiles              index.php, index.html
}

errorlog ${root_dir}/logs/error.log {
  useServer               0
  logLevel                ERROR
  rollingSize             10M
}

accesslog ${root_dir}/logs/access.log {
  useServer               0
  logFormat               "%h %l %u %t \\"%r\\" %>s %b"
  rollingSize             10M
  keepDays                10
  compressArchive         1
}

extprocessor ${handler} {
  type                    lsapi
  address                 uds://tmp/lshttpd/${user}-${handler}.sock
  maxConns                10
  env                     PHP_LSAPI_CHILDREN=10
  initTimeout             60
  retryTimeout            0
  respBuffer              0
  autoStart               1
  path                    ${php_bin}
  backlog                 100
  instances               1
  extUser                 ${user}
  extGroup                ${user}
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           400
  procHardLimit           500
}

scripthandler  {
  add                     lsapi:${handler} php
}

context / {
  allowBrowse             1
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}
EOF
}

adicionar_map_listener_default() {
    local user="$1"
    local dominio="$2"
    local map_line="  map                     ${user} ${dominio},www.${dominio}"

    if grep -Eq "map[[:space:]]+${user}[[:space:]]+" "$HTTPD_CONF"; then
        return 0
    fi

    if grep -Eq '^listener[[:space:]]+Default[[:space:]]*\{' "$HTTPD_CONF"; then
        if ! awk -v map_line="$map_line" '
        BEGIN {in_listener=0; inserted=0}
        {
            if ($0 ~ /^listener[[:space:]]+Default[[:space:]]*\{/) {
                in_listener=1
            }
            if (in_listener==1 && $0 ~ /^[[:space:]]*\}/) {
                print map_line
                inserted=1
                in_listener=0
            }
            print
        }
        END { if (inserted==0) exit 1 }
        ' "$HTTPD_CONF" > "${HTTPD_CONF}.tmp"; then
            rm -f "${HTTPD_CONF}.tmp"
            erro "Não foi possível inserir o map no listener Default."
            return 1
        fi

        mv "${HTTPD_CONF}.tmp" "$HTTPD_CONF"
        return 0
    fi

    cat >>"$HTTPD_CONF" <<EOF

listener Default {
${map_line}
}
EOF
}

adicionar_vhost_httpd_conf() {
    local user="$1"
    local dominio="$2"
    local root_dir="$3"

    if grep -Eq "^virtualhost[[:space:]]+${user}[[:space:]]*\\{" "$HTTPD_CONF"; then
        aviso "Vhost ${user} já existe no httpd_config.conf"
    else
        cat >>"$HTTPD_CONF" <<EOF

virtualhost ${user} {
  vhRoot                  ${root_dir}/
  configFile              ${VHOSTS_DIR}/${user}/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
  setUIDMode              2
}
EOF
    fi

    adicionar_map_listener_default "$user" "$dominio"
}

remover_vhost_httpd_conf() {
    local user="$1"
    cp "$HTTPD_CONF" "${HTTPD_CONF}.bak.$(date +%s)"

    awk -v user="$user" '
    BEGIN {skip=0}
    $0 ~ "^virtualhost "user" \\{" {skip=1}
    skip==1 && $0 ~ "^\\}" {skip=0; next}
    skip==1 {next}
    $0 ~ "map[[:space:]]+"user"[[:space:]]+" {next}
    {print}
    ' "$HTTPD_CONF" > "${HTTPD_CONF}.tmp"

    mv "${HTTPD_CONF}.tmp" "$HTTPD_CONF"
}

baixar_wp_cli() {
    if ! command -v wp >/dev/null 2>&1; then
        curl -L https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
        chmod +x /usr/local/bin/wp
    fi
}

executar_wp_site() {
    local user="$1"
    local root_dir="$2"
    shift 2

    local wp_bin
    local php_bin
    wp_bin="$(command -v wp || true)"
    php_bin="$(php_bin_site "$user" || true)"

    if [[ -n "$wp_bin" && -f "$wp_bin" && -n "$php_bin" && -x "$php_bin" ]]; then
        sudo -u "$user" "$php_bin" "$wp_bin" --path="${root_dir}/public_html" "$@" --allow-root
    else
        sudo -u "$user" wp --path="${root_dir}/public_html" "$@" --allow-root
    fi
}

garantir_rewrite_wordpress_site() {
    local user="$1"
    local root_dir="$2"
    local public_html="${root_dir}/public_html"
    local htaccess_file="${public_html}/.htaccess"

    if [[ ! -f "${public_html}/wp-config.php" ]]; then
        aviso "WordPress não detectado em ${public_html}; pulando correção de permalink."
        return 0
    fi

    local bloco_wp
    bloco_wp="$(mktemp)"
    cat > "$bloco_wp" <<'EOF'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOF

    if [[ -f "$htaccess_file" ]]; then
        if ! grep -q "^# BEGIN WordPress" "$htaccess_file"; then
            echo >> "$htaccess_file"
            cat "$bloco_wp" >> "$htaccess_file"
        fi
    else
        cp "$bloco_wp" "$htaccess_file"
    fi

    rm -f "$bloco_wp"
    chown "${user}:${user}" "$htaccess_file"
    chmod 644 "$htaccess_file"

    if ! executar_wp_site "$user" "$root_dir" rewrite structure "/%postname%/" --hard; then
        aviso "Falha ao definir estrutura de permalink no WordPress."
    fi
    if ! executar_wp_site "$user" "$root_dir" rewrite flush --hard; then
        aviso "Falha ao executar flush de rewrite no WordPress."
    fi
}

instalar_wordpress_nao_interativo() {
    local user="$1"
    local dominio="$2"
    local root_dir="$3"
    local db="$4"
    local dbuser="$5"
    local dbpass="$6"

    baixar_wp_cli

    local wp_title="Site ${dominio}"
    local wp_admin_user="admin"
    local wp_admin_pass
    local wp_admin_email="admin@${dominio}"
    wp_admin_pass="$(gerar_senha)"

    rm -f "${root_dir}/public_html/index.php"

    executar_wp_site "$user" "$root_dir" core download
    executar_wp_site "$user" "$root_dir" config create \
        --dbname="$db" \
        --dbuser="$dbuser" \
        --dbpass="$dbpass" \
        --dbhost="localhost" \
        --skip-check

    executar_wp_site "$user" "$root_dir" core install \
        --url="https://${dominio}" \
        --title="${wp_title}" \
        --admin_user="${wp_admin_user}" \
        --admin_password="${wp_admin_pass}" \
        --admin_email="${wp_admin_email}" \
        --skip-email

    garantir_rewrite_wordpress_site "$user" "$root_dir"

    cat > "/root/${user}_wp.txt" <<EOF
URL=https://${dominio}
ADMIN_USER=${wp_admin_user}
ADMIN_PASS=${wp_admin_pass}
ADMIN_EMAIL=${wp_admin_email}
EOF
    chmod 600 "/root/${user}_wp.txt"

    chown -R "${user}:${user}" "${root_dir}/public_html"
}

cloudflare_cert_existe() {
    [[ -f /root/.cloudflared/cert.pem ]]
}

cf_site_dir() {
    local user="$1"
    echo "${CLOUDFLARE_BASE_DIR}/${user}"
}

cf_site_config_file() {
    local user="$1"
    echo "${CLOUDFLARE_BASE_DIR}/${user}/config.yml"
}

cf_tunnel_id_por_nome() {
    local tunnel_name="$1"

    if command -v jq >/dev/null 2>&1; then
        cloudflared tunnel list --output json 2>/dev/null \
            | jq -r --arg name "$tunnel_name" '((if type == "array" then . else [] end) | .[] | select(.name == $name) | .id)' 2>/dev/null \
            | head -n1
    else
        cloudflared tunnel list 2>/dev/null | awk -v name="$tunnel_name" '$2 == name {print $1; exit}'
    fi
}

criar_tunnel_site() {
    local user="$1"
    local dominio="$2"
    local tunnel_id
    dominio="$(normalizar_dominio "$dominio")"

    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido para criação de tunnel."
        return 1
    fi

    if ! cloudflare_cert_existe; then
        erro "Cloudflare não autenticado. Use a opção de login primeiro."
        return 1
    fi

    if ! usuario_valido "$user"; then
        erro "Usuário inválido para tunnel: ${user}"
        return 1
    fi

    local site_cf_dir
    site_cf_dir="$(cf_site_dir "$user")"
    mkdir -p "$site_cf_dir"

    tunnel_id="$(cf_tunnel_id_por_nome "$user")"
    if [[ -z "$tunnel_id" ]]; then
        msg "Criando tunnel individual para ${dominio}..."
        if ! cloudflared tunnel create "$user" >"/tmp/cloudflared-create-${user}.log" 2>&1; then
            erro "Falha ao criar tunnel ${user}. Verifique: /tmp/cloudflared-create-${user}.log"
            return 1
        fi
        tunnel_id="$(cf_tunnel_id_por_nome "$user")"
    fi

    if [[ -z "$tunnel_id" ]]; then
        erro "Não foi possível obter o ID do tunnel ${user}."
        return 1
    fi

    local cred_source="/root/.cloudflared/${tunnel_id}.json"
    local cred_file="${site_cf_dir}/${tunnel_id}.json"

    if [[ ! -f "$cred_source" ]]; then
        erro "Credencial do tunnel não encontrada em ${cred_source}."
        return 1
    fi

    cp "$cred_source" "$cred_file"

    cat > "$(cf_site_config_file "$user")" <<EOF
tunnel: ${tunnel_id}
credentials-file: ${cred_file}

ingress:
  - hostname: ${dominio}
    service: http://127.0.0.1:${OLS_ORIGIN_HTTP_PORT}
  - hostname: www.${dominio}
    service: http://127.0.0.1:${OLS_ORIGIN_HTTP_PORT}
  - service: http_status:404
EOF

    if ! cloudflared tunnel route dns "$tunnel_id" "$dominio"; then
        aviso "Não foi possível criar/validar DNS para ${dominio}."
    fi
    if ! cloudflared tunnel route dns "$tunnel_id" "www.${dominio}"; then
        aviso "Não foi possível criar/validar DNS para www.${dominio}."
    fi

    cat > "/etc/systemd/system/cloudflared-${user}.service" <<EOF
[Unit]
Description=Cloudflare Tunnel ${user}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/cloudflared --config $(cf_site_config_file "$user") tunnel run
Restart=always
RestartSec=5
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    if ! systemctl enable "cloudflared-${user}.service"; then
        aviso "Não foi possível habilitar cloudflared-${user}.service"
    fi
    if ! systemctl restart "cloudflared-${user}.service"; then
        aviso "Não foi possível reiniciar cloudflared-${user}.service"
    fi
}

remover_tunnel_site() {
    local user="$1"
    local tunnel_id

    if ! usuario_valido "$user"; then
        aviso "Usuário inválido para remover tunnel: ${user}"
        return 0
    fi

    systemctl stop "cloudflared-${user}.service" >/dev/null 2>&1 || true
    systemctl disable "cloudflared-${user}.service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/cloudflared-${user}.service"
    systemctl daemon-reload || true

    tunnel_id="$(cf_tunnel_id_por_nome "$user" || true)"
    if [[ -n "$tunnel_id" ]]; then
        cloudflared tunnel delete "$tunnel_id" -f >/dev/null 2>&1 || true
    else
        cloudflared tunnel delete "$user" -f >/dev/null 2>&1 || true
    fi

    remover_diretorio_seguro "$CLOUDFLARE_BASE_DIR" "$(cf_site_dir "$user")" || true
}

cloudflare_login_log_file() {
    echo "/tmp/ultra-cloudflare-login.log"
}

cloudflare_login_pid_file() {
    echo "/tmp/ultra-cloudflare-login.pid"
}

cloudflare_login_url_from_log() {
    local log_file="${1:-$(cloudflare_login_log_file)}"
    [[ -f "$log_file" ]] || return 0
    grep -Eo 'https://[^[:space:]]+' "$log_file" 2>/dev/null | head -n1 || true
}

cloudflare_login_pid_running() {
    local pid_file
    local pid
    pid_file="$(cloudflare_login_pid_file)"
    [[ -f "$pid_file" ]] || return 1

    pid="$(cat "$pid_file" 2>/dev/null || true)"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$pid" 2>/dev/null
}

cloudflare_login_pid_cleanup() {
    local pid_file
    pid_file="$(cloudflare_login_pid_file)"
    if ! cloudflare_login_pid_running; then
        rm -f "$pid_file"
    fi
}

criar_cron_usuario() {
    local user="$1"
    local root_dir="$2"
    local php_bin
    php_bin="$(php_bin_site "$user" || true)"
    php_bin="${php_bin:-php}"
    local cron_cmd="cd ${root_dir}/public_html && ${php_bin} -v >/dev/null 2>&1"
    local cron_line="*/5 * * * * ${cron_cmd}"

    gravar_cron_usuario "$user" "$cron_line" "$cron_cmd"
}

gravar_cron_usuario() {
    local user="$1"
    local nova_linha="$2"
    local remover_pattern="${3:-}"
    local cabecalho_shell="SHELL=/bin/bash"
    local cabecalho_path="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    local linhas_existentes=""

    if ! garantir_cron_disponivel; then
        erro "Não foi possível configurar cron no sistema."
        return 1
    fi

    if command -v crontab >/dev/null 2>&1; then
        local tmp_cron
        tmp_cron="$(mktemp)"
        linhas_existentes="$(crontab -u "$user" -l 2>/dev/null | grep -Ev '^(SHELL=|PATH=)' || true)"
        if [[ -n "$remover_pattern" ]]; then
            linhas_existentes="$(echo "$linhas_existentes" | grep -v -F "$remover_pattern" || true)"
        fi

        {
            echo "$cabecalho_shell"
            echo "$cabecalho_path"
            echo
            if [[ -n "$linhas_existentes" ]]; then
                echo "$linhas_existentes" | sed '/^[[:space:]]*$/d' || true
            fi
            if ! echo "$linhas_existentes" | grep -Fqx "$nova_linha"; then
                echo "$nova_linha"
            fi
        } > "$tmp_cron"

        if crontab -u "$user" "$tmp_cron"; then
            rm -f "$tmp_cron"
            return 0
        fi

        rm -f "$tmp_cron"
        aviso "Falha ao aplicar crontab para ${user}. Tentando fallback em /var/spool/cron."
    fi

    local cron_dir="/var/spool/cron"
    local cron_file="${cron_dir}/${user}"
    mkdir -p "$cron_dir"
    if [[ -f "$cron_file" ]]; then
        linhas_existentes="$(grep -Ev '^(SHELL=|PATH=)' "$cron_file" || true)"
    else
        linhas_existentes=""
    fi
    if [[ -n "$remover_pattern" ]]; then
        linhas_existentes="$(echo "$linhas_existentes" | grep -v -F "$remover_pattern" || true)"
    fi

    cat > "$cron_file" <<EOF
$cabecalho_shell
$cabecalho_path

$(echo "$linhas_existentes" | sed '/^[[:space:]]*$/d' || true)
$(if ! echo "$linhas_existentes" | grep -Fqx "$nova_linha"; then echo "$nova_linha"; fi)
EOF
    chown "${user}:${user}" "$cron_file"
    chmod 600 "$cron_file"
}

expressao_cron_valida() {
    local expr="$1"
    local expr_normalizada
    expr_normalizada="$(echo "$expr" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"

    [[ "$expr_normalizada" =~ ^@[a-zA-Z]+$ ]] && return 0
    [[ "$(awk '{print NF}' <<<"$expr_normalizada")" -eq 5 ]]
}

adicionar_entrada_cron_site() {
    titulo

    local dominio
    read -rp "Host/Subdomínio ou domínio do site: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }

    local root_dir="${SITES_ROOT}/${user}"
    if [[ ! -d "$root_dir" ]]; then
        erro "Site não encontrado."
        return
    fi
    local php_bin_detectado
    php_bin_detectado="$(php_bin_site "$user" || true)"

    local entrada_cron
    local expressao
    local comando=""
    local comando_detectado="false"

    read -rp "Expressão cron (ou linha completa): " entrada_cron
    entrada_cron="$(echo "$entrada_cron" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
    [[ -n "$entrada_cron" ]] || { erro "Entrada cron vazia."; return; }

    if [[ "$entrada_cron" =~ ^@[a-zA-Z]+[[:space:]]+.+$ ]]; then
        expressao="$(awk '{print $1}' <<<"$entrada_cron")"
        comando="$(awk '{for(i=2;i<=NF;i++) printf "%s%s",$i,(i==NF?"":" ")}' <<<"$entrada_cron")"
        comando_detectado="true"
    elif [[ "$(awk '{print NF}' <<<"$entrada_cron")" -ge 6 ]]; then
        expressao="$(awk '{print $1" "$2" "$3" "$4" "$5}' <<<"$entrada_cron")"
        comando="$(awk '{for(i=6;i<=NF;i++) printf "%s%s",$i,(i==NF?"":" ")}' <<<"$entrada_cron")"
        comando_detectado="true"
    else
        expressao="$entrada_cron"
    fi

    if ! expressao_cron_valida "$expressao"; then
        erro "Expressão cron inválida. Use 5 campos ou formato @daily/@hourly."
        return
    fi

    if [[ "$comando_detectado" != "true" ]]; then
        read -rp "Comando (ex: ${php_bin_detectado:-php} artisan schedule:run): " comando
        comando="$(echo "$comando" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    fi
    [[ -n "$comando" ]] || { erro "Comando inválido."; return; }

    if [[ -n "$php_bin_detectado" && -x "$php_bin_detectado" ]]; then
        if [[ "$comando" == /usr/bin/php* ]] && [[ ! -x /usr/bin/php ]]; then
            comando="${comando/#\/usr\/bin\/php/$php_bin_detectado}"
            aviso "Substituído /usr/bin/php por ${php_bin_detectado}."
        elif [[ "$comando" == php\ * ]]; then
            comando="${php_bin_detectado}${comando#php}"
            aviso "Substituído php por ${php_bin_detectado}."
        fi
    fi

    local executar_em_public_html
    local padrao_execucao="s"
    if [[ "$comando_detectado" == "true" ]]; then
        padrao_execucao="n"
    fi
    read -rp "Executar dentro de ${root_dir}/public_html? (s/n) [${padrao_execucao}]: " executar_em_public_html
    executar_em_public_html="${executar_em_public_html:-$padrao_execucao}"

    local linha_cron
    if [[ "$executar_em_public_html" =~ ^[Ss]$ ]]; then
        linha_cron="${expressao} cd ${root_dir}/public_html && ${comando}"
    else
        linha_cron="${expressao} ${comando}"
    fi

    gravar_cron_usuario "$user" "$linha_cron"
    msg "Entrada cron adicionada para ${dominio} (${user})."
    echo "Cron: ${linha_cron}"
}

fazer_backup_site() {
    local user="$1"
    local root_dir="$2"
    local stamp
    stamp="$(date +%Y%m%d_%H%M%S)"
    local arq="${BACKUP_DIR}/${user}_${stamp}.tar.gz"

    if [[ -d "$root_dir" ]]; then
        tar -czf "$arq" -C "$root_dir" .
        echo "$arq"
    fi
}

clonar_site() {
    titulo

    local dominio_origem dominio_destino
    read -rp "Domínio origem: " dominio_origem
    read -rp "Domínio destino: " dominio_destino
    dominio_origem="$(normalizar_dominio "$dominio_origem")"
    dominio_destino="$(normalizar_dominio "$dominio_destino")"

    if ! validar_dominio "$dominio_origem"; then
        erro "Domínio de origem inválido."
        return
    fi
    if ! validar_dominio "$dominio_destino"; then
        erro "Domínio de destino inválido."
        return
    fi

    local user_origem user_destino
    user_origem="$(resolver_usuario_por_dominio "$dominio_origem")" || {
        erro "Não foi possível resolver usuário de origem."
        return
    }
    user_destino="$(nome_site_para_usuario "$dominio_destino")" || {
        erro "Não foi possível gerar usuário para o destino."
        return
    }

    if ! usuario_valido "$user_destino"; then
        erro "Usuário de destino inválido: ${user_destino}"
        return
    fi

    local root_origem="${SITES_ROOT}/${user_origem}"
    local root_destino="${SITES_ROOT}/${user_destino}"
    local user_destino_existente
    user_destino_existente="$(resolver_usuario_por_dominio "$dominio_destino" || true)"

    if [[ ! -d "$root_origem" ]]; then
        erro "Site de origem não encontrado."
        return
    fi

    if [[ -n "$user_destino_existente" && -d "${SITES_ROOT}/${user_destino_existente}" ]]; then
        erro "Destino já existe."
        return
    fi

    criar_usuario_linux "$user_destino" "$root_destino"
    mkdir -p "$root_destino"
    cp -a "$root_origem/." "$root_destino/"
    chown -R "${user_destino}:${user_destino}" "$root_destino"

    local dados_db
    dados_db="$(criar_banco "$user_destino")"

    local db dbuser dbpass
    db="$(echo "$dados_db" | cut -d'|' -f1)"
    dbuser="$(echo "$dados_db" | cut -d'|' -f2)"
    dbpass="$(echo "$dados_db" | cut -d'|' -f3)"

    local db_origem="${user_origem}_db"
    if [[ -f "/root/${user_origem}_db.txt" ]]; then
        local db_origem_file
        db_origem_file="$(grep -E '^BANCO=' "/root/${user_origem}_db.txt" | head -n1 | cut -d'=' -f2- || true)"
        if [[ -n "$db_origem_file" ]]; then
            db_origem="$db_origem_file"
        fi
    fi

    if [[ "$db_origem" =~ ^[a-zA-Z0-9_]+$ ]] \
        && $MYSQL_BIN -Nse "SHOW DATABASES LIKE '${db_origem}';" | grep -qx "$db_origem"; then
        if command -v mysqldump >/dev/null 2>&1; then
            msg "Clonando conteúdo do banco ${db_origem} para ${db}..."
            if ! mysqldump --single-transaction --routines --triggers "$db_origem" | $MYSQL_BIN "$db"; then
                aviso "Falha ao importar dump do banco de origem. Banco destino criado, porém sem dados."
            fi
        else
            aviso "mysqldump não encontrado; banco destino foi criado sem dados."
        fi
    else
        aviso "Banco da origem não encontrado; banco destino foi criado sem dados."
    fi

    criar_env_site "$user_destino" "$root_destino" "$db" "$dbuser" "$dbpass" "$dominio_destino"

    local php_versao="8.4"
    criar_vhconf "$user_destino" "$dominio_destino" "$root_destino" "$php_versao"
    adicionar_vhost_httpd_conf "$user_destino" "$dominio_destino" "$root_destino"
    garantir_comando_php_cli || true

    systemctl restart lsws || true

    local criar_cf
    read -rp "Criar tunnel individual para o clone? (s/n): " criar_cf
    if [[ "$criar_cf" =~ ^[Ss]$ ]]; then
        criar_tunnel_site "$user_destino" "$dominio_destino"
    fi

    msg "Clone concluído."
}

suspender_site() {
    titulo
    local dominio
    read -rp "Domínio para suspender: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }
    local root_dir="${SITES_ROOT}/${user}"

    if [[ ! -d "$root_dir" ]]; then
        erro "Site não encontrado."
        return
    fi

    touch "${root_dir}/.suspended"
    chmod 000 "${root_dir}/public_html" || true
    systemctl stop "cloudflared-${user}.service" >/dev/null 2>&1 || true
    msg "Site suspenso."
}

reativar_site() {
    titulo
    local dominio
    read -rp "Domínio para reativar: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }
    local root_dir="${SITES_ROOT}/${user}"

    if [[ ! -d "$root_dir" ]]; then
        erro "Site não encontrado."
        return
    fi

    rm -f "${root_dir}/.suspended"
    chmod 755 "${root_dir}/public_html" || true
    systemctl restart "cloudflared-${user}.service" >/dev/null 2>&1 || true
    msg "Site reativado."
}

trocar_senha_banco() {
    titulo
    local dominio
    read -rp "Host/Subdomínio do site (ex: radio): " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }

    local dbuser="${user}_user"
    local nova_senha
    nova_senha="$(gerar_senha)"

    $MYSQL_BIN -e "ALTER USER '${dbuser}'@'localhost' IDENTIFIED BY '${nova_senha}'; FLUSH PRIVILEGES;"

    if [[ -f "/root/${user}_db.txt" ]]; then
        sed -i "s/^SENHA=.*/SENHA=${nova_senha}/" "/root/${user}_db.txt"
    fi

    local env_file="${SITES_ROOT}/${user}/public_html/.env"
    if [[ -f "$env_file" ]]; then
        sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=${nova_senha}/" "$env_file" || true
    fi

    msg "Senha do banco alterada."
    echo "Nova senha: ${nova_senha}"
}

criar_site_ultra() {
    titulo

    local dominio
    read -rp "Domínio do site: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(nome_site_para_usuario "$dominio")" || {
        erro "Não foi possível gerar usuário para o domínio."
        return
    }
    if ! usuario_valido "$user"; then
        erro "Usuário inválido gerado para o domínio: ${user}"
        return
    fi

    local root_dir="${SITES_ROOT}/${user}"
    local user_existente
    user_existente="$(resolver_usuario_por_dominio "$dominio" || true)"
    if [[ -n "$user_existente" && -d "${SITES_ROOT}/${user_existente}" ]]; then
        erro "Esse domínio já possui site configurado (${user_existente})."
        return
    fi

    if [[ -d "$root_dir" ]]; then
        erro "Esse site já existe."
        return
    fi

    echo "Versões PHP disponíveis: ${PHP_VERSOES_SUPORTADAS[*]}"
    local php_versao
    read -rp "Escolha a versão do PHP [8.4]: " php_versao
    php_versao="${php_versao:-8.4}"
    if ! validar_php_versao "$php_versao"; then
        erro "Versão PHP inválida. Use uma das opções: ${PHP_VERSOES_SUPORTADAS[*]}"
        return
    fi

    criar_usuario_linux "$user" "$root_dir"
    configurar_estrutura_site "$user" "$root_dir"

    local dados_db
    dados_db="$(criar_banco "$user")"

    local db dbuser dbpass
    db="$(echo "$dados_db" | cut -d'|' -f1)"
    dbuser="$(echo "$dados_db" | cut -d'|' -f2)"
    dbpass="$(echo "$dados_db" | cut -d'|' -f3)"

    criar_env_site "$user" "$root_dir" "$db" "$dbuser" "$dbpass" "$dominio"
    criar_index_padrao "$user" "$root_dir" "$dominio"
    gerar_cert_local_selfsigned "$user" "$root_dir" "$dominio"
    criar_vhconf "$user" "$dominio" "$root_dir" "$php_versao"
    adicionar_vhost_httpd_conf "$user" "$dominio" "$root_dir"
    garantir_comando_php_cli || true
    criar_cron_usuario "$user" "$root_dir" || aviso "Não foi possível criar cron padrão para o site."

    local instalar_wp
    read -rp "Instalar WordPress automático? (s/n): " instalar_wp
    if [[ "$instalar_wp" =~ ^[Ss]$ ]]; then
        instalar_wordpress_nao_interativo "$user" "$dominio" "$root_dir" "$db" "$dbuser" "$dbpass"
    fi

    local criar_cf
    read -rp "Criar tunnel individual do Cloudflare para esse site? (s/n): " criar_cf
    if [[ "$criar_cf" =~ ^[Ss]$ ]]; then
        criar_tunnel_site "$user" "$dominio"
    fi

    chown -R "${user}:${user}" "$root_dir"
    systemctl restart lsws || true

    msg "Site criado com sucesso."
    echo "Domínio: $dominio"
    echo "Usuário Linux: $user"
    echo "PHP: $php_versao"
    echo "Raiz: ${root_dir}/public_html"
    echo "Banco: $db"
    echo "Usuário banco: $dbuser"
    echo "Senha banco: $dbpass"
}

remover_site() {
    titulo

    local dominio
    read -rp "Domínio a remover: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }
    if ! usuario_valido "$user"; then
        erro "Usuário inválido para remoção: ${user}"
        return
    fi

    local root_dir="${SITES_ROOT}/${user}"
    if [[ "$root_dir" == "$SITES_ROOT" || "$root_dir" == "${SITES_ROOT}/" ]]; then
        erro "Falha de segurança: diretório raiz inválido para remoção."
        return
    fi
    if [[ ! -d "$root_dir" && ! -d "${VHOSTS_DIR}/${user}" ]]; then
        erro "Site não encontrado."
        return
    fi

    echo
    aviso "Essa ação vai remover:"
    echo "- arquivos do site"
    echo "- usuário Linux"
    echo "- banco e usuário do banco"
    echo "- vhost do OpenLiteSpeed"
    echo "- tunnel individual do Cloudflare"
    echo
    read -rp "Digite REMOVER para confirmar: " confirma

    [[ "$confirma" == "REMOVER" ]] || { aviso "Operação cancelada."; return; }

    local backup_file=""
    backup_file="$(fazer_backup_site "$user" "$root_dir" || true)"

    remover_tunnel_site "$user" || true

    $MYSQL_BIN -e "DROP DATABASE IF EXISTS \`${user}_db\`;"
    $MYSQL_BIN -e "DROP USER IF EXISTS '${user}_user'@'localhost';"

    local arquivo_db_extra="/root/${user}_db_extra.txt"
    if [[ -f "$arquivo_db_extra" ]]; then
        while IFS= read -r db_extra; do
            [[ -n "$db_extra" ]] || continue
            if [[ "$db_extra" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                $MYSQL_BIN -e "DROP DATABASE IF EXISTS \`${db_extra}\`;" || true
            fi
        done < <(grep -E '^BANCO=' "$arquivo_db_extra" | cut -d'=' -f2- || true)

        while IFS= read -r dbuser_extra; do
            [[ -n "$dbuser_extra" ]] || continue
            if [[ "$dbuser_extra" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                $MYSQL_BIN -e "DROP USER IF EXISTS '${dbuser_extra}'@'localhost';" || true
            fi
        done < <(grep -E '^USUARIO=' "$arquivo_db_extra" | cut -d'=' -f2- || true)
    fi

    $MYSQL_BIN -e "FLUSH PRIVILEGES;"

    remover_diretorio_seguro "$VHOSTS_DIR" "${VHOSTS_DIR}/${user}" || return
    remover_vhost_httpd_conf "$user"

    remover_diretorio_seguro "$SITES_ROOT" "$root_dir" || return
    if id "$user" >/dev/null 2>&1; then
        userdel -r "$user" >/dev/null 2>&1 || userdel "$user" || true
    fi

    rm -f "/root/${user}_db.txt" "/root/${user}_db_extra.txt" "/root/${user}_wp.txt"

    systemctl restart lsws || true

    msg "Site removido."
    [[ -n "$backup_file" ]] && echo "Backup salvo em: $backup_file"
}

listar_sites() {
    titulo
    local achou=0

    for dir in "$VHOSTS_DIR"/*; do
        [[ -d "$dir" ]] || continue
        achou=1
        local user
        user="$(basename "$dir")"
        echo "----------------------------------------"
        echo "Usuário: $user"
        echo "Home: ${SITES_ROOT}/${user}"
        [[ -f "/root/${user}_db.txt" ]] && cat "/root/${user}_db.txt"
        [[ -f "/root/${user}_db_extra.txt" ]] && cat "/root/${user}_db_extra.txt"
        [[ -f "/root/${user}_wp.txt" ]] && cat "/root/${user}_wp.txt"
        if systemctl is-enabled "cloudflared-${user}.service" >/dev/null 2>&1; then
            echo "CLOUDFLARE_TUNNEL=ativo"
        else
            echo "CLOUDFLARE_TUNNEL=inativo"
        fi
    done

    [[ $achou -eq 0 ]] && aviso "Nenhum site encontrado."
}

reiniciar_servicos() {
    titulo
    garantir_comando_php_cli || true
    habilitar_reiniciar_servico "mariadb"
    habilitar_reiniciar_servico "redis"
    habilitar_reiniciar_servico "lsws"
    habilitar_reiniciar_servico "crond"
    msg "Serviços reiniciados."
}

definir_senha_admin_ols() {
    titulo
    "${LSWS_DIR}/admin/misc/admpass.sh"
}

mostrar_status() {
    titulo
    echo "OpenLiteSpeed:"
    systemctl status lsws --no-pager -l | sed -n '1,8p' || true
    echo
    echo "MariaDB:"
    systemctl status mariadb --no-pager -l | sed -n '1,8p' || true
    echo
    echo "Redis:"
    systemctl status redis --no-pager -l | sed -n '1,8p' || true
    echo
    echo "cloudflared:"
    cloudflared --version || true
    echo
    echo "Origem tunnel HTTP: http://127.0.0.1:${OLS_ORIGIN_HTTP_PORT}"
    echo
    echo "Painel OLS: http://localhost:7080"
}

ver_logs_erro_site() {
    titulo

    local dominio
    read -rp "Host/Subdomínio ou domínio do site: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }

    local root_dir="${SITES_ROOT}/${user}"
    local log_file="${root_dir}/logs/error.log"
    if [[ ! -f "$log_file" ]]; then
        aviso "Log de erro não encontrado em: ${log_file}"
        return
    fi

    local linhas
    read -rp "Quantidade de linhas para exibir [80]: " linhas
    linhas="${linhas:-80}"
    if [[ ! "$linhas" =~ ^[0-9]+$ ]]; then
        erro "Quantidade inválida."
        return
    fi

    echo "Arquivo: ${log_file}"
    echo "----------------------------------------"
    tail -n "$linhas" "$log_file" || true
}

corrigir_permalink_wordpress_site() {
    titulo

    local dominio
    read -rp "Host/Subdomínio ou domínio do site: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }

    local root_dir="${SITES_ROOT}/${user}"
    if [[ ! -f "${root_dir}/public_html/wp-config.php" ]]; then
        erro "WordPress não detectado nesse site."
        return
    fi

    baixar_wp_cli
    garantir_rewrite_wordpress_site "$user" "$root_dir"
    systemctl restart lsws || true

    msg "Permalinks do WordPress corrigidos para ${dominio}."
}

corrigir_rewrite_site_nao_wordpress() {
    titulo

    local dominio
    read -rp "Host/Subdomínio ou domínio do site: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }

    local root_dir="${SITES_ROOT}/${user}"
    local public_html="${root_dir}/public_html"
    local htaccess_file="${public_html}/.htaccess"
    if [[ ! -d "$public_html" ]]; then
        erro "Diretório public_html não encontrado."
        return
    fi

    if [[ -f "${public_html}/wp-config.php" ]]; then
        aviso "WordPress detectado neste site. Para WP, use a opção 18."
        return
    fi

    local front_controller
    read -rp "Arquivo front controller [index.php]: " front_controller
    front_controller="${front_controller:-index.php}"
    if [[ ! "$front_controller" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
        erro "Nome de front controller inválido."
        return
    fi

    local tmp_sem_bloco
    tmp_sem_bloco="$(mktemp)"
    if [[ -f "$htaccess_file" ]]; then
        cp "$htaccess_file" "${htaccess_file}.bak.$(date +%s)"
        awk '
        BEGIN {skip=0}
        $0 == "# BEGIN ULTRA_REWRITE" {skip=1; next}
        $0 == "# END ULTRA_REWRITE" {skip=0; next}
        skip==1 {next}
        {print}
        ' "$htaccess_file" > "$tmp_sem_bloco"
    else
        : > "$tmp_sem_bloco"
    fi

    cat >> "$tmp_sem_bloco" <<EOF

# BEGIN ULTRA_REWRITE
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^ ${front_controller} [L]
</IfModule>
# END ULTRA_REWRITE
EOF

    mv "$tmp_sem_bloco" "$htaccess_file"
    chown "${user}:${user}" "$htaccess_file"
    chmod 644 "$htaccess_file"

    systemctl restart lsws || true
    msg "Rewrite padrão (não WordPress) aplicado para ${dominio}."
}

verificar_htaccess_site() {
    titulo

    local dominio
    read -rp "Host/Subdomínio ou domínio do site: " dominio
    dominio="$(normalizar_dominio "$dominio")"
    if ! validar_dominio "$dominio"; then
        erro "Domínio inválido."
        return
    fi

    local user
    user="$(resolver_usuario_por_dominio "$dominio")" || {
        erro "Não foi possível resolver o usuário do domínio."
        return
    }

    local root_dir="${SITES_ROOT}/${user}"
    local public_html="${root_dir}/public_html"
    local htaccess_file="${public_html}/.htaccess"
    local vhconf_file="${VHOSTS_DIR}/${user}/vhconf.conf"
    local status_ok=1

    echo "Domínio: ${dominio}"
    echo "Usuário: ${user}"
    echo "Vhost conf: ${vhconf_file}"
    echo "Public HTML: ${public_html}"
    echo

    if [[ ! -f "$vhconf_file" ]]; then
        erro "Arquivo de vhost não encontrado."
        return
    fi

    local rewrite_enable
    local autoload_htaccess
    rewrite_enable="$(awk '
        BEGIN {in_rewrite=0; val=""}
        $1 == "rewrite" {in_rewrite=1; next}
        in_rewrite && $1 == "enable" {val=$2}
        in_rewrite && /^[[:space:]]*}/ {in_rewrite=0}
        END {print val}
    ' "$vhconf_file")"
    autoload_htaccess="$(awk '
        BEGIN {in_rewrite=0; val=""}
        $1 == "rewrite" {in_rewrite=1; next}
        in_rewrite && $1 == "autoLoadHtaccess" {val=$2}
        in_rewrite && /^[[:space:]]*}/ {in_rewrite=0}
        END {print val}
    ' "$vhconf_file")"

    if [[ "$rewrite_enable" == "1" ]]; then
        echo "rewrite.enable: OK (1)"
    else
        echo "rewrite.enable: FALHA (${rewrite_enable:-ausente})"
        status_ok=0
    fi

    if [[ "$autoload_htaccess" == "1" ]]; then
        echo "rewrite.autoLoadHtaccess: OK (1)"
    else
        echo "rewrite.autoLoadHtaccess: FALHA (${autoload_htaccess:-ausente})"
        status_ok=0
    fi

    if [[ -d "$public_html" ]]; then
        echo "Diretório public_html: OK"
    else
        echo "Diretório public_html: FALHA (não encontrado)"
        status_ok=0
    fi

    if [[ -f "$htaccess_file" ]]; then
        local dono_h
        local grupo_h
        local perm_h
        dono_h="$(stat -c '%U' "$htaccess_file" 2>/dev/null || echo '?')"
        grupo_h="$(stat -c '%G' "$htaccess_file" 2>/dev/null || echo '?')"
        perm_h="$(stat -c '%a' "$htaccess_file" 2>/dev/null || echo '?')"
        echo ".htaccess: OK (${htaccess_file})"
        echo ".htaccess owner: ${dono_h}:${grupo_h}"
        echo ".htaccess perms: ${perm_h}"
    else
        echo ".htaccess: AUSENTE (${htaccess_file})"
        status_ok=0
    fi

    if systemctl is-active lsws >/dev/null 2>&1; then
        echo "lsws: ativo"
    else
        echo "lsws: inativo"
        status_ok=0
    fi

    echo
    if [[ $status_ok -eq 1 ]]; then
        msg "Validação concluída: .htaccess pronto para leitura."
    else
        aviso "Validação concluída com pendências."
    fi
}

# API não interativa (uso pelo painel web)
api_json_erro() {
    local mensagem="$1"
    if command -v jq >/dev/null 2>&1; then
        jq -n --arg erro "$mensagem" '{ok:false,error:$erro}'
    else
        mensagem="${mensagem//\"/\\\"}"
        echo "{\"ok\":false,\"error\":\"${mensagem}\"}"
    fi
}

api_criar_site() {
    local dominio_raw="${1:-}"
    local php_versao="${2:-8.4}"
    local instalar_wp="${3:-0}"
    local criar_cf="${4:-0}"

    local dominio
    dominio="$(normalizar_dominio "$dominio_raw")"
    if ! validar_dominio "$dominio"; then
        api_json_erro "Domínio inválido."
        return 1
    fi

    local user
    user="$(nome_site_para_usuario "$dominio")" || {
        api_json_erro "Não foi possível gerar usuário para o domínio."
        return 1
    }
    if ! usuario_valido "$user"; then
        api_json_erro "Usuário inválido gerado para o domínio."
        return 1
    fi

    if ! validar_php_versao "$php_versao"; then
        api_json_erro "Versão PHP inválida. Use: ${PHP_VERSOES_SUPORTADAS[*]}."
        return 1
    fi

    local user_existente
    user_existente="$(resolver_usuario_por_dominio "$dominio" || true)"
    if [[ -n "$user_existente" && -d "${SITES_ROOT}/${user_existente}" ]]; then
        api_json_erro "Esse domínio já possui site configurado (${user_existente})."
        return 1
    fi

    local root_dir="${SITES_ROOT}/${user}"
    if [[ -d "$root_dir" ]]; then
        api_json_erro "Esse site já existe."
        return 1
    fi

    if ! criar_usuario_linux "$user" "$root_dir"; then
        api_json_erro "Falha ao criar usuário Linux do site."
        return 1
    fi
    if ! configurar_estrutura_site "$user" "$root_dir"; then
        api_json_erro "Falha ao configurar estrutura do site."
        return 1
    fi

    local dados_db db dbuser dbpass
    dados_db="$(criar_banco "$user")" || {
        api_json_erro "Falha ao criar banco principal."
        return 1
    }
    db="$(echo "$dados_db" | cut -d'|' -f1)"
    dbuser="$(echo "$dados_db" | cut -d'|' -f2)"
    dbpass="$(echo "$dados_db" | cut -d'|' -f3)"

    if ! criar_env_site "$user" "$root_dir" "$db" "$dbuser" "$dbpass" "$dominio"; then
        api_json_erro "Falha ao criar arquivo .env do site."
        return 1
    fi
    criar_index_padrao "$user" "$root_dir" "$dominio" >/dev/null 2>&1 || true
    gerar_cert_local_selfsigned "$user" "$root_dir" "$dominio" >/dev/null 2>&1 || true

    if ! criar_vhconf "$user" "$dominio" "$root_dir" "$php_versao"; then
        api_json_erro "Falha ao criar configuração do vhost."
        return 1
    fi
    if ! adicionar_vhost_httpd_conf "$user" "$dominio" "$root_dir"; then
        api_json_erro "Falha ao registrar vhost no OpenLiteSpeed."
        return 1
    fi

    garantir_comando_php_cli >/dev/null 2>&1 || true
    criar_cron_usuario "$user" "$root_dir" >/dev/null 2>&1 || true

    local wp_admin_file=""
    if bool_sim "$instalar_wp"; then
        if ! instalar_wordpress_nao_interativo "$user" "$dominio" "$root_dir" "$db" "$dbuser" "$dbpass" >/tmp/ultra-api-wp-${user}.log 2>&1; then
            api_json_erro "Falha ao instalar WordPress automaticamente."
            return 1
        fi
        wp_admin_file="/root/${user}_wp.txt"
    fi

    local tunnel_status="nao_solicitado"
    if bool_sim "$criar_cf"; then
        if cloudflare_cert_existe; then
            if criar_tunnel_site "$user" "$dominio" >/tmp/ultra-api-tunnel-${user}.log 2>&1; then
                tunnel_status="ativo"
            else
                tunnel_status="falha"
            fi
        else
            tunnel_status="cloudflare_nao_autenticado"
        fi
    fi

    chown -R "${user}:${user}" "$root_dir"
    systemctl restart lsws >/dev/null 2>&1 || true

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg domain "$dominio" \
            --arg user "$user" \
            --arg php "$php_versao" \
            --arg db "$db" \
            --arg dbuser "$dbuser" \
            --arg dbpass "$dbpass" \
            --arg tunnel "$tunnel_status" \
            --arg wp_file "$wp_admin_file" \
            '{ok:true,domain:$domain,user:$user,php:$php,db:{name:$db,user:$dbuser,pass:$dbpass},tunnel:$tunnel,wp_credentials_file:$wp_file}'
    else
        echo "{\"ok\":true,\"domain\":\"${dominio}\",\"user\":\"${user}\",\"php\":\"${php_versao}\",\"tunnel\":\"${tunnel_status}\"}"
    fi
}

api_criar_banco_adicional() {
    local user="${1:-}"
    local sufixo_raw="${2:-}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuário do site inválido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site não encontrado para o usuário informado."
        return 1
    fi

    local sufixo
    if [[ -z "$sufixo_raw" ]]; then
        sufixo="$(proximo_sufixo_banco_adicional "$user" || true)"
        sufixo="${sufixo:-extra1}"
    else
        sufixo="$(echo "$sufixo_raw" | tr '[:upper:]-' '[:lower:]_' | tr -cd 'a-z0-9_' | sed -E 's/^_+//; s/_+$//')"
    fi

    if [[ -z "$sufixo" ]]; then
        api_json_erro "Sufixo inválido para banco adicional."
        return 1
    fi
    if [[ ${#sufixo} -gt 20 ]]; then
        sufixo="${sufixo:0:20}"
    fi

    local db="${user}_${sufixo}_db"
    local dbuser="${user}_${sufixo}_user"
    if $MYSQL_BIN -Nse "SHOW DATABASES LIKE '${db}';" | grep -qx "$db"; then
        api_json_erro "Banco já existe: ${db}"
        return 1
    fi
    if $MYSQL_BIN -Nse "SELECT User FROM mysql.user WHERE User='${dbuser}' AND Host='localhost';" | grep -qx "$dbuser"; then
        api_json_erro "Usuário de banco já existe: ${dbuser}"
        return 1
    fi

    local dbpass
    dbpass="$(gerar_senha)"
    $MYSQL_BIN -e "CREATE DATABASE \`${db}\`;"
    $MYSQL_BIN -e "CREATE USER '${dbuser}'@'localhost' IDENTIFIED BY '${dbpass}';"
    $MYSQL_BIN -e "GRANT ALL PRIVILEGES ON \`${db}\`.* TO '${dbuser}'@'localhost'; FLUSH PRIVILEGES;"

    local arquivo_db_extra="/root/${user}_db_extra.txt"
    cat >> "$arquivo_db_extra" <<EOF
CRIADO_EM=$(date '+%Y-%m-%d %H:%M:%S')
BANCO=${db}
USUARIO=${dbuser}
SENHA=${dbpass}
---
EOF
    chmod 600 "$arquivo_db_extra"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg site_user "$user" \
            --arg db "$db" \
            --arg dbuser "$dbuser" \
            --arg dbpass "$dbpass" \
            --arg cred_file "$arquivo_db_extra" \
            '{ok:true,site_user:$site_user,db:{name:$db,user:$dbuser,pass:$dbpass},credentials_file:$cred_file}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\",\"db\":\"${db}\",\"db_user\":\"${dbuser}\"}"
    fi
}

api_dominio_por_usuario() {
    local user="$1"
    local vhconf="${VHOSTS_DIR}/${user}/vhconf.conf"
    if [[ -f "$vhconf" ]]; then
        awk '$1 == "vhDomain" {print $2; exit}' "$vhconf"
    fi
}

api_clonar_site() {
    local user_origem="${1:-}"
    local dominio_destino_raw="${2:-}"
    local php_versao="${3:-8.4}"
    local criar_cf="${4:-0}"

    if ! usuario_valido "$user_origem"; then
        api_json_erro "Usuário de origem inválido."
        return 1
    fi

    local root_origem="${SITES_ROOT}/${user_origem}"
    if [[ ! -d "$root_origem" || ! -d "${VHOSTS_DIR}/${user_origem}" ]]; then
        api_json_erro "Site de origem não encontrado."
        return 1
    fi

    local dominio_destino
    dominio_destino="$(normalizar_dominio "$dominio_destino_raw")"
    if ! validar_dominio "$dominio_destino"; then
        api_json_erro "Domínio de destino inválido."
        return 1
    fi

    if ! validar_php_versao "$php_versao"; then
        api_json_erro "Versão PHP inválida. Use: ${PHP_VERSOES_SUPORTADAS[*]}."
        return 1
    fi

    local user_destino
    user_destino="$(nome_site_para_usuario "$dominio_destino")" || {
        api_json_erro "Não foi possível gerar usuário para o destino."
        return 1
    }
    if ! usuario_valido "$user_destino"; then
        api_json_erro "Usuário de destino inválido."
        return 1
    fi

    local user_destino_existente
    user_destino_existente="$(resolver_usuario_por_dominio "$dominio_destino" || true)"
    if [[ -n "$user_destino_existente" && -d "${SITES_ROOT}/${user_destino_existente}" ]]; then
        api_json_erro "Domínio de destino já existe (${user_destino_existente})."
        return 1
    fi

    local root_destino="${SITES_ROOT}/${user_destino}"
    if [[ -d "$root_destino" || -d "${VHOSTS_DIR}/${user_destino}" ]]; then
        api_json_erro "Usuário de destino já existe."
        return 1
    fi

    criar_usuario_linux "$user_destino" "$root_destino"
    mkdir -p "$root_destino"
    cp -a "$root_origem/." "$root_destino/"
    chown -R "${user_destino}:${user_destino}" "$root_destino"

    local dados_db db dbuser dbpass
    dados_db="$(criar_banco "$user_destino")" || {
        api_json_erro "Falha ao criar banco no destino."
        return 1
    }
    db="$(echo "$dados_db" | cut -d'|' -f1)"
    dbuser="$(echo "$dados_db" | cut -d'|' -f2)"
    dbpass="$(echo "$dados_db" | cut -d'|' -f3)"

    local db_origem="${user_origem}_db"
    if [[ -f "/root/${user_origem}_db.txt" ]]; then
        local db_origem_file
        db_origem_file="$(grep -E '^BANCO=' "/root/${user_origem}_db.txt" | head -n1 | cut -d'=' -f2- || true)"
        [[ -n "$db_origem_file" ]] && db_origem="$db_origem_file"
    fi

    local import_status="nao_importado"
    if [[ "$db_origem" =~ ^[a-zA-Z0-9_]+$ ]] \
        && $MYSQL_BIN -Nse "SHOW DATABASES LIKE '${db_origem}';" | grep -qx "$db_origem"; then
        if command -v mysqldump >/dev/null 2>&1; then
            if mysqldump --single-transaction --routines --triggers "$db_origem" | $MYSQL_BIN "$db"; then
                import_status="ok"
            else
                import_status="falha_importacao"
            fi
        else
            import_status="mysqldump_ausente"
        fi
    else
        import_status="banco_origem_nao_encontrado"
    fi

    criar_env_site "$user_destino" "$root_destino" "$db" "$dbuser" "$dbpass" "$dominio_destino"
    criar_vhconf "$user_destino" "$dominio_destino" "$root_destino" "$php_versao"
    adicionar_vhost_httpd_conf "$user_destino" "$dominio_destino" "$root_destino"
    garantir_comando_php_cli >/dev/null 2>&1 || true
    systemctl restart lsws >/dev/null 2>&1 || true

    local tunnel_status="nao_solicitado"
    if bool_sim "$criar_cf"; then
        if cloudflare_cert_existe; then
            if criar_tunnel_site "$user_destino" "$dominio_destino" >/tmp/ultra-api-tunnel-clone-${user_destino}.log 2>&1; then
                tunnel_status="ativo"
            else
                tunnel_status="falha"
            fi
        else
            tunnel_status="cloudflare_nao_autenticado"
        fi
    fi

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg source_user "$user_origem" \
            --arg dest_domain "$dominio_destino" \
            --arg dest_user "$user_destino" \
            --arg php "$php_versao" \
            --arg db "$db" \
            --arg dbuser "$dbuser" \
            --arg dbpass "$dbpass" \
            --arg import_status "$import_status" \
            --arg tunnel "$tunnel_status" \
            '{ok:true,source_user:$source_user,destination:{domain:$dest_domain,user:$dest_user,php:$php},db:{name:$db,user:$dbuser,pass:$dbpass,import:$import_status},tunnel:$tunnel}'
    else
        echo "{\"ok\":true,\"source_user\":\"${user_origem}\",\"destination_user\":\"${user_destino}\",\"destination_domain\":\"${dominio_destino}\"}"
    fi
}

api_remover_site_por_usuario() {
    local user="${1:-}"
    local backup_enabled="${2:-1}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuário inválido para remoção."
        return 1
    fi

    local root_dir="${SITES_ROOT}/${user}"
    if [[ "$root_dir" == "$SITES_ROOT" || "$root_dir" == "${SITES_ROOT}/" ]]; then
        api_json_erro "Falha de segurança: diretório raiz inválido."
        return 1
    fi

    if [[ ! -d "$root_dir" && ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site não encontrado."
        return 1
    fi

    local dominio
    dominio="$(api_dominio_por_usuario "$user" || true)"

    local backup_file=""
    if bool_sim "$backup_enabled"; then
        backup_file="$(fazer_backup_site "$user" "$root_dir" || true)"
    fi

    remover_tunnel_site "$user" || true

    $MYSQL_BIN -e "DROP DATABASE IF EXISTS \`${user}_db\`;" || true
    $MYSQL_BIN -e "DROP USER IF EXISTS '${user}_user'@'localhost';" || true

    local arquivo_db_extra="/root/${user}_db_extra.txt"
    if [[ -f "$arquivo_db_extra" ]]; then
        while IFS= read -r db_extra; do
            [[ -n "$db_extra" ]] || continue
            if [[ "$db_extra" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                $MYSQL_BIN -e "DROP DATABASE IF EXISTS \`${db_extra}\`;" || true
            fi
        done < <(grep -E '^BANCO=' "$arquivo_db_extra" | cut -d'=' -f2- || true)

        while IFS= read -r dbuser_extra; do
            [[ -n "$dbuser_extra" ]] || continue
            if [[ "$dbuser_extra" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                $MYSQL_BIN -e "DROP USER IF EXISTS '${dbuser_extra}'@'localhost';" || true
            fi
        done < <(grep -E '^USUARIO=' "$arquivo_db_extra" | cut -d'=' -f2- || true)
    fi

    $MYSQL_BIN -e "FLUSH PRIVILEGES;" || true

    remover_diretorio_seguro "$VHOSTS_DIR" "${VHOSTS_DIR}/${user}" || true
    remover_vhost_httpd_conf "$user" || true

    remover_diretorio_seguro "$SITES_ROOT" "$root_dir" || true
    if id "$user" >/dev/null 2>&1; then
        userdel -f "$user" >/dev/null 2>&1 || userdel "$user" >/dev/null 2>&1 || true
    fi
    groupdel "$user" >/dev/null 2>&1 || true

    rm -f "/root/${user}_db.txt" "/root/${user}_db_extra.txt" "/root/${user}_wp.txt"

    systemctl restart lsws >/dev/null 2>&1 || true

    if command -v jq >/dev/null 2>&1; then
        jq -n --arg user "$user" --arg domain "$dominio" --arg backup "$backup_file" '{ok:true,user:$user,domain:$domain,backup:$backup}'
    else
        echo "{\"ok\":true,\"user\":\"${user}\",\"backup\":\"${backup_file}\"}"
    fi
}

api_cron_listar() {
    local user="${1:-}"
    if ! usuario_valido "$user"; then
        api_json_erro "Usuário do site inválido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" ]]; then
        api_json_erro "Site não encontrado."
        return 1
    fi

    local linhas
    linhas="$(crontab -u "$user" -l 2>/dev/null | grep -Ev '^(SHELL=|PATH=)' | sed '/^[[:space:]]*$/d' || true)"

    if command -v jq >/dev/null 2>&1; then
        printf '%s\n' "$linhas" \
            | jq -R -s --arg user "$user" '{ok:true,site_user:$user,items:(split("\n")|map(select(length>0)))}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_cron_adicionar() {
    local user="${1:-}"
    local expressao="${2:-}"
    local comando_raw="${3:-}"
    local executar_em_public_html="${4:-1}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuário do site inválido."
        return 1
    fi
    local root_dir="${SITES_ROOT}/${user}"
    if [[ ! -d "$root_dir" ]]; then
        api_json_erro "Site não encontrado."
        return 1
    fi

    expressao="$(echo "$expressao" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
    comando_raw="$(echo "$comando_raw" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    if ! expressao_cron_valida "$expressao"; then
        api_json_erro "Expressão cron inválida."
        return 1
    fi
    if [[ -z "$comando_raw" || "$comando_raw" == *$'\n'* ]]; then
        api_json_erro "Comando cron inválido."
        return 1
    fi

    local php_bin_detectado
    php_bin_detectado="$(php_bin_site "$user" || true)"
    local comando="$comando_raw"
    if [[ -n "$php_bin_detectado" && -x "$php_bin_detectado" ]]; then
        if [[ "$comando" == /usr/bin/php* ]] && [[ ! -x /usr/bin/php ]]; then
            comando="${comando/#\/usr\/bin\/php/$php_bin_detectado}"
        elif [[ "$comando" == php\ * ]]; then
            comando="${php_bin_detectado}${comando#php}"
        fi
    fi

    local linha_cron
    if bool_sim "$executar_em_public_html"; then
        linha_cron="${expressao} cd ${root_dir}/public_html && ${comando}"
    else
        linha_cron="${expressao} ${comando}"
    fi

    gravar_cron_usuario "$user" "$linha_cron"

    if command -v jq >/dev/null 2>&1; then
        jq -n --arg user "$user" --arg line "$linha_cron" '{ok:true,site_user:$user,line:$line}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_cron_remover_linha() {
    local user="${1:-}"
    local linha_alvo="${2:-}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuário do site inválido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" ]]; then
        api_json_erro "Site não encontrado."
        return 1
    fi
    if [[ -z "$linha_alvo" ]]; then
        api_json_erro "Linha cron obrigatória."
        return 1
    fi

    local cabecalho_shell="SHELL=/bin/bash"
    local cabecalho_path="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    local existentes novos
    existentes="$(crontab -u "$user" -l 2>/dev/null | grep -Ev '^(SHELL=|PATH=)' || true)"
    novos="$(printf '%s\n' "$existentes" | grep -Fvx "$linha_alvo" || true)"

    local tmp_cron
    tmp_cron="$(mktemp)"
    {
        echo "$cabecalho_shell"
        echo "$cabecalho_path"
        echo
        printf '%s\n' "$novos" | sed '/^[[:space:]]*$/d' || true
    } > "$tmp_cron"

    if ! crontab -u "$user" "$tmp_cron"; then
        rm -f "$tmp_cron"
        api_json_erro "Falha ao atualizar crontab do site."
        return 1
    fi
    rm -f "$tmp_cron"

    if command -v jq >/dev/null 2>&1; then
        jq -n --arg user "$user" --arg line "$linha_alvo" '{ok:true,site_user:$user,removed:$line}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_instalar_stack_base() {
    local phpmyadmin_status="ok"

    instalar_repos || {
        api_json_erro "Falha ao instalar repositorios."
        return 1
    }
    instalar_openlitespeed_php || {
        api_json_erro "Falha ao instalar OpenLiteSpeed e PHP."
        return 1
    }
    garantir_comando_php_cli >/dev/null 2>&1 || true
    instalar_banco_redis_cf || {
        api_json_erro "Falha ao instalar MariaDB/Redis/cloudflared."
        return 1
    }

    if ! instalar_phpmyadmin; then
        phpmyadmin_status="warning"
    fi

    mkdir -p "$VHOSTS_DIR"
    if [[ ! -f "$HTTPD_CONF" ]]; then
        api_json_erro "Arquivo principal do OpenLiteSpeed nao encontrado."
        return 1
    fi

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg phpmyadmin "$phpmyadmin_status" \
            --arg panel_url "http://localhost:7080" \
            '{ok:true,phpmyadmin:$phpmyadmin,panel_url:$panel_url}'
    else
        echo "{\"ok\":true}"
    fi
}

api_configurar_phpmyadmin_principal() {
    local dominio_raw="${1:-}"
    local remover_outros="${2:-1}"
    local criar_cf="${3:-0}"

    local dominio
    dominio="$(normalizar_dominio "$dominio_raw")"
    if ! validar_dominio "$dominio"; then
        api_json_erro "Dominio invalido."
        return 1
    fi

    local user="phpmyadmin_srv"
    local user_existente
    user_existente="$(resolver_usuario_por_dominio "$dominio" || true)"
    if [[ -n "$user_existente" && "$user_existente" != "$user" ]] \
        && [[ -d "${SITES_ROOT}/${user_existente}" || -d "${VHOSTS_DIR}/${user_existente}" ]]; then
        api_json_erro "Dominio ja esta em uso por outro site (${user_existente})."
        return 1
    fi

    local root_dir="${SITES_ROOT}/${user}"
    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido para phpMyAdmin."
        return 1
    fi

    instalar_phpmyadmin || {
        api_json_erro "Falha ao instalar phpMyAdmin."
        return 1
    }
    criar_usuario_linux "$user" "$root_dir"

    mkdir -p "${root_dir}" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"
    chown -R "${user}:${user}" "$root_dir"
    chmod 755 "${root_dir}" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"

    local pma_origem
    pma_origem="$(phpmyadmin_origem_dir)" || {
        api_json_erro "Diretorio do phpMyAdmin nao encontrado."
        return 1
    }

    local public_html="${root_dir}/public_html"
    if [[ -e "$public_html" && ! -d "$public_html" && ! -L "$public_html" ]]; then
        api_json_erro "Caminho public_html invalido."
        return 1
    fi

    if [[ -L "$public_html" ]]; then
        rm -f "$public_html"
    elif [[ -d "$public_html" ]]; then
        rm -rf "$public_html"
    fi

    ln -s "$pma_origem" "$public_html"
    chown -h "${user}:${user}" "$public_html" >/dev/null 2>&1 || true

    criar_vhconf "$user" "$dominio" "$root_dir" "8.4" || {
        api_json_erro "Falha ao criar vhost do phpMyAdmin."
        return 1
    }
    adicionar_vhost_httpd_conf "$user" "$dominio" "$root_dir" || {
        api_json_erro "Falha ao registrar vhost do phpMyAdmin."
        return 1
    }
    gerar_cert_local_selfsigned "$user" "$root_dir" "$dominio"

    local removed_links="false"
    if bool_sim "$remover_outros"; then
        despublicar_phpmyadmin_dos_sites "$user"
        removed_links="true"
    fi

    local tunnel_status="nao_solicitado"
    if bool_sim "$criar_cf"; then
        if cloudflare_cert_existe; then
            if criar_tunnel_site "$user" "$dominio" >/tmp/ultra-api-phpmyadmin-tunnel.log 2>&1; then
                tunnel_status="ativo"
            else
                tunnel_status="falha"
            fi
        else
            tunnel_status="cloudflare_nao_autenticado"
        fi
    fi

    systemctl restart lsws >/dev/null 2>&1 || true

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg domain "$dominio" \
            --arg user "$user" \
            --arg source "$pma_origem" \
            --arg tunnel "$tunnel_status" \
            --argjson removed_links "$removed_links" \
            '{ok:true,domain:$domain,user:$user,source:$source,tunnel:$tunnel,removed_links:$removed_links}'
    else
        echo "{\"ok\":true,\"domain\":\"${dominio}\",\"user\":\"${user}\"}"
    fi
}

api_configurar_painel_web_principal() {
    local dominio_raw="${1:-}"
    local criar_cf="${2:-0}"

    local dominio
    dominio="$(normalizar_dominio "$dominio_raw")"
    if ! validar_dominio "$dominio"; then
        api_json_erro "Dominio invalido."
        return 1
    fi

    local user="$WEB_PANEL_USER"
    local user_existente
    user_existente="$(resolver_usuario_por_dominio "$dominio" || true)"
    if [[ -n "$user_existente" && "$user_existente" != "$user" ]] \
        && [[ -d "${SITES_ROOT}/${user_existente}" || -d "${VHOSTS_DIR}/${user_existente}" ]]; then
        api_json_erro "Dominio ja esta em uso por outro site (${user_existente})."
        return 1
    fi

    local root_dir="${SITES_ROOT}/${user}"
    instalar_arquivos_painel_web || {
        api_json_erro "Falha ao instalar arquivos do painel."
        return 1
    }
    garantir_comando_php_cli >/dev/null 2>&1 || true
    criar_usuario_linux "$user" "$root_dir"

    mkdir -p "${root_dir}" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"
    chown -R "${user}:${user}" "$root_dir"
    chmod 755 "${root_dir}" "${root_dir}/logs" "${root_dir}/tmp" "${root_dir}/ssl" "${root_dir}/backups"

    local public_html="${root_dir}/public_html"
    if [[ -e "$public_html" && ! -d "$public_html" && ! -L "$public_html" ]]; then
        api_json_erro "Caminho public_html invalido."
        return 1
    fi

    if [[ -L "$public_html" ]]; then
        rm -f "$public_html"
    fi
    if [[ ! -d "$public_html" ]]; then
        mkdir -p "$public_html"
    fi

    find "$public_html" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    cp -a "${WEB_PANEL_INSTALL_DIR}/public/." "$public_html/"
    chown -R "${user}:${user}" "$public_html"
    chmod -R u+rwX,go+rX "$public_html"

    local panel_pass
    local panel_hash
    local hash_script
    panel_pass="$(gerar_senha)"
    hash_script="$(mktemp)"
    cat > "$hash_script" <<'EOF'
<?php
if (!isset($argv[1])) {
    exit(1);
}
echo password_hash($argv[1], PASSWORD_DEFAULT);
EOF
    panel_hash="$(php "$hash_script" "$panel_pass" 2>/dev/null || true)"
    rm -f "$hash_script"
    if [[ -z "$panel_hash" || "$panel_hash" != \$2* && "$panel_hash" != \$argon2* ]]; then
        api_json_erro "Falha ao gerar hash da senha do painel."
        return 1
    fi

    local panel_config_dir="${root_dir}/.ultra-panel"
    mkdir -p "$panel_config_dir"
    chown "${user}:${user}" "$panel_config_dir"
    chmod 700 "$panel_config_dir"

    cat > "${panel_config_dir}/panel.env" <<EOF
PANEL_TITLE=ULTRA Web Panel
PANEL_USER=admin
PANEL_PASS_HASH=${panel_hash}
EOF
    chown "${user}:${user}" "${panel_config_dir}/panel.env"
    chmod 600 "${panel_config_dir}/panel.env"

    local cred_file="/root/${user}_credenciais.txt"
    cat > "$cred_file" <<EOF
DOMINIO=${dominio}
URL=https://${dominio}
USUARIO=admin
SENHA=${panel_pass}
EOF
    chmod 600 "$cred_file"

    criar_vhconf "$user" "$dominio" "$root_dir" "8.4" || {
        api_json_erro "Falha ao criar vhost do painel."
        return 1
    }
    adicionar_vhost_httpd_conf "$user" "$dominio" "$root_dir" || {
        api_json_erro "Falha ao registrar vhost do painel."
        return 1
    }
    gerar_cert_local_selfsigned "$user" "$root_dir" "$dominio"

    local tunnel_status="nao_solicitado"
    if bool_sim "$criar_cf"; then
        if cloudflare_cert_existe; then
            if criar_tunnel_site "$user" "$dominio" >/tmp/ultra-api-panel-tunnel.log 2>&1; then
                tunnel_status="ativo"
            else
                tunnel_status="falha"
            fi
        else
            tunnel_status="cloudflare_nao_autenticado"
        fi
    fi

    systemctl restart lsws >/dev/null 2>&1 || true

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg domain "$dominio" \
            --arg user "$user" \
            --arg panel_user "admin" \
            --arg panel_pass "$panel_pass" \
            --arg cred_file "$cred_file" \
            --arg tunnel "$tunnel_status" \
            '{ok:true,domain:$domain,user:$user,login:{user:$panel_user,pass:$panel_pass},credentials_file:$cred_file,tunnel:$tunnel}'
    else
        echo "{\"ok\":true,\"domain\":\"${dominio}\",\"user\":\"${user}\"}"
    fi
}

api_trocar_senha_banco_por_usuario() {
    local user="${1:-}"
    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site nao encontrado."
        return 1
    fi

    local dbuser="${user}_user"
    local nova_senha
    nova_senha="$(gerar_senha)"
    $MYSQL_BIN -e "ALTER USER '${dbuser}'@'localhost' IDENTIFIED BY '${nova_senha}'; FLUSH PRIVILEGES;" || {
        api_json_erro "Falha ao alterar senha do banco."
        return 1
    }

    if [[ -f "/root/${user}_db.txt" ]]; then
        sed -i "s/^SENHA=.*/SENHA=${nova_senha}/" "/root/${user}_db.txt"
    fi

    local env_file="${SITES_ROOT}/${user}/public_html/.env"
    if [[ -f "$env_file" ]]; then
        sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=${nova_senha}/" "$env_file" || true
    fi

    local domain
    domain="$(api_dominio_por_usuario "$user" || true)"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg domain "$domain" \
            --arg dbuser "$dbuser" \
            --arg pass "$nova_senha" \
            '{ok:true,site_user:$user,domain:$domain,db_user:$dbuser,new_password:$pass}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_trocar_senha_ssh_por_usuario() {
    local user="${1:-}"
    local nova_senha="${2:-}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site nao encontrado."
        return 1
    fi
    if ! senha_ssh_site_valida "$nova_senha"; then
        api_json_erro "Senha SSH invalida. Use entre 8 e 120 caracteres, sem quebra de linha nem dois-pontos."
        return 1
    fi

    printf '%s:%s\n' "$user" "$nova_senha" | chpasswd || {
        api_json_erro "Falha ao atualizar a senha SSH do usuario do site."
        return 1
    }

    local domain
    domain="$(api_dominio_por_usuario "$user" || true)"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg domain "$domain" \
            '{ok:true,site_user:$user,domain:$domain}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_ver_logs_erro_por_usuario() {
    local user="${1:-}"
    local linhas="${2:-80}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! "$linhas" =~ ^[0-9]+$ ]]; then
        api_json_erro "Quantidade de linhas invalida."
        return 1
    fi

    local log_file="${SITES_ROOT}/${user}/logs/error.log"
    if [[ ! -f "$log_file" ]]; then
        api_json_erro "Log de erro nao encontrado."
        return 1
    fi

    local domain
    local content
    domain="$(api_dominio_por_usuario "$user" || true)"
    content="$(tail -n "$linhas" "$log_file" 2>/dev/null || true)"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg domain "$domain" \
            --arg file "$log_file" \
            --arg content "$content" \
            '{ok:true,site_user:$user,domain:$domain,file:$file,content:$content}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_corrigir_permalink_wordpress_por_usuario() {
    local user="${1:-}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi

    local root_dir="${SITES_ROOT}/${user}"
    if [[ ! -f "${root_dir}/public_html/wp-config.php" ]]; then
        api_json_erro "WordPress nao detectado nesse site."
        return 1
    fi

    baixar_wp_cli || {
        api_json_erro "Falha ao preparar WP-CLI."
        return 1
    }
    garantir_rewrite_wordpress_site "$user" "$root_dir" || {
        api_json_erro "Falha ao corrigir rewrite do WordPress."
        return 1
    }
    systemctl restart lsws >/dev/null 2>&1 || true

    local domain
    domain="$(api_dominio_por_usuario "$user" || true)"

    if command -v jq >/dev/null 2>&1; then
        jq -n --arg user "$user" --arg domain "$domain" '{ok:true,site_user:$user,domain:$domain}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_corrigir_rewrite_por_usuario() {
    local user="${1:-}"
    local front_controller="${2:-index.php}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! "$front_controller" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
        api_json_erro "Front controller invalido."
        return 1
    fi

    local root_dir="${SITES_ROOT}/${user}"
    local public_html="${root_dir}/public_html"
    local htaccess_file="${public_html}/.htaccess"
    if [[ ! -d "$public_html" ]]; then
        api_json_erro "Diretorio public_html nao encontrado."
        return 1
    fi
    if [[ -f "${public_html}/wp-config.php" ]]; then
        api_json_erro "WordPress detectado nesse site. Use a correcao de permalink."
        return 1
    fi

    local tmp_sem_bloco
    tmp_sem_bloco="$(mktemp)"
    if [[ -f "$htaccess_file" ]]; then
        cp "$htaccess_file" "${htaccess_file}.bak.$(date +%s)"
        awk '
        BEGIN {skip=0}
        $0 == "# BEGIN ULTRA_REWRITE" {skip=1; next}
        $0 == "# END ULTRA_REWRITE" {skip=0; next}
        skip==1 {next}
        {print}
        ' "$htaccess_file" > "$tmp_sem_bloco"
    else
        : > "$tmp_sem_bloco"
    fi

    cat >> "$tmp_sem_bloco" <<EOF

# BEGIN ULTRA_REWRITE
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^ ${front_controller} [L]
</IfModule>
# END ULTRA_REWRITE
EOF

    mv "$tmp_sem_bloco" "$htaccess_file"
    chown "${user}:${user}" "$htaccess_file"
    chmod 644 "$htaccess_file"
    systemctl restart lsws >/dev/null 2>&1 || true

    local domain
    domain="$(api_dominio_por_usuario "$user" || true)"
    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg domain "$domain" \
            --arg front_controller "$front_controller" \
            --arg htaccess "$htaccess_file" \
            '{ok:true,site_user:$user,domain:$domain,front_controller:$front_controller,htaccess:$htaccess}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_verificar_htaccess_por_usuario() {
    local user="${1:-}"

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site nao encontrado."
        return 1
    fi

    local root_dir="${SITES_ROOT}/${user}"
    local public_html="${root_dir}/public_html"
    local htaccess_file="${public_html}/.htaccess"
    local vhconf_file="${VHOSTS_DIR}/${user}/vhconf.conf"
    local status_ok="true"
    local report_file
    local domain
    report_file="$(mktemp)"
    domain="$(api_dominio_por_usuario "$user" || true)"

    {
        echo "Domain: ${domain}"
        echo "User: ${user}"
        echo "Vhost conf: ${vhconf_file}"
        echo "Public HTML: ${public_html}"
        echo
    } > "$report_file"

    if [[ ! -f "$vhconf_file" ]]; then
        echo "Vhost conf: MISSING" >> "$report_file"
        status_ok="false"
    else
        local rewrite_enable
        local autoload_htaccess
        rewrite_enable="$(awk '
            BEGIN {in_rewrite=0; val=""}
            $1 == "rewrite" {in_rewrite=1; next}
            in_rewrite && $1 == "enable" {val=$2}
            in_rewrite && /^[[:space:]]*}/ {in_rewrite=0}
            END {print val}
        ' "$vhconf_file")"
        autoload_htaccess="$(awk '
            BEGIN {in_rewrite=0; val=""}
            $1 == "rewrite" {in_rewrite=1; next}
            in_rewrite && $1 == "autoLoadHtaccess" {val=$2}
            in_rewrite && /^[[:space:]]*}/ {in_rewrite=0}
            END {print val}
        ' "$vhconf_file")"

        if [[ "$rewrite_enable" == "1" ]]; then
            echo "rewrite.enable: OK (1)" >> "$report_file"
        else
            echo "rewrite.enable: FAIL (${rewrite_enable:-missing})" >> "$report_file"
            status_ok="false"
        fi

        if [[ "$autoload_htaccess" == "1" ]]; then
            echo "rewrite.autoLoadHtaccess: OK (1)" >> "$report_file"
        else
            echo "rewrite.autoLoadHtaccess: FAIL (${autoload_htaccess:-missing})" >> "$report_file"
            status_ok="false"
        fi
    fi

    if [[ -d "$public_html" ]]; then
        echo "public_html: OK" >> "$report_file"
    else
        echo "public_html: FAIL (missing)" >> "$report_file"
        status_ok="false"
    fi

    if [[ -f "$htaccess_file" ]]; then
        local dono_h
        local grupo_h
        local perm_h
        dono_h="$(stat -c '%U' "$htaccess_file" 2>/dev/null || echo '?')"
        grupo_h="$(stat -c '%G' "$htaccess_file" 2>/dev/null || echo '?')"
        perm_h="$(stat -c '%a' "$htaccess_file" 2>/dev/null || echo '?')"
        {
            echo ".htaccess: OK (${htaccess_file})"
            echo ".htaccess owner: ${dono_h}:${grupo_h}"
            echo ".htaccess perms: ${perm_h}"
        } >> "$report_file"
    else
        echo ".htaccess: MISSING (${htaccess_file})" >> "$report_file"
        status_ok="false"
    fi

    if systemctl is-active lsws >/dev/null 2>&1; then
        echo "lsws: active" >> "$report_file"
    else
        echo "lsws: inactive" >> "$report_file"
        status_ok="false"
    fi

    local content
    content="$(cat "$report_file")"
    rm -f "$report_file"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg domain "$domain" \
            --arg content "$content" \
            --argjson healthy "$status_ok" \
            '{ok:true,site_user:$user,domain:$domain,healthy:$healthy,content:$content}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_definir_credenciais_ols_admin() {
    local admin_user="${1:-admin}"
    local admin_pass="${2:-}"
    local admin_script="${LSWS_DIR}/admin/misc/admpass.sh"

    if [[ ! "$admin_user" =~ ^[a-zA-Z0-9._-]{1,32}$ ]]; then
        api_json_erro "Usuario admin do OLS invalido."
        return 1
    fi
    if [[ ${#admin_pass} -lt 8 ]]; then
        api_json_erro "Senha do OLS deve ter ao menos 8 caracteres."
        return 1
    fi
    if [[ ! -x "$admin_script" ]]; then
        api_json_erro "Script do OpenLiteSpeed admin nao encontrado."
        return 1
    fi

    local output
    output="$(printf '%s\n%s\n%s\n' "$admin_user" "$admin_pass" "$admin_pass" | "$admin_script" 2>&1)" || {
        api_json_erro "Falha ao atualizar credenciais do OLS admin."
        return 1
    }

    if command -v jq >/dev/null 2>&1; then
        jq -n --arg user "$admin_user" --arg output "$output" '{ok:true,user:$user,output:$output}'
    else
        echo "{\"ok\":true,\"user\":\"${admin_user}\"}"
    fi
}

api_cloudflare_status() {
    local authenticated="false"
    local login_running="false"
    local cert_file="/root/.cloudflared/cert.pem"
    local log_file
    local login_url=""
    local log_excerpt=""

    log_file="$(cloudflare_login_log_file)"
    cloudflare_cert_existe && authenticated="true"
    if cloudflare_login_pid_running; then
        login_running="true"
    else
        cloudflare_login_pid_cleanup
    fi
    login_url="$(cloudflare_login_url_from_log "$log_file")"
    if [[ -f "$log_file" ]]; then
        log_excerpt="$(tail -n 20 "$log_file" 2>/dev/null || true)"
    fi

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --argjson authenticated "$authenticated" \
            --argjson login_running "$login_running" \
            --arg cert_file "$cert_file" \
            --arg log_file "$log_file" \
            --arg login_url "$login_url" \
            --arg log_excerpt "$log_excerpt" \
            '{ok:true,authenticated:$authenticated,login_running:$login_running,cert_file:$cert_file,log_file:$log_file,login_url:$login_url,log_excerpt:$log_excerpt}'
    else
        echo "{\"ok\":true}"
    fi
}

api_cloudflare_login_start() {
    if cloudflare_cert_existe; then
        api_cloudflare_status
        return 0
    fi

    if ! command -v cloudflared >/dev/null 2>&1; then
        api_json_erro "cloudflared nao encontrado."
        return 1
    fi

    if cloudflare_login_pid_running; then
        api_cloudflare_status
        return 0
    fi

    local log_file
    local pid_file
    log_file="$(cloudflare_login_log_file)"
    pid_file="$(cloudflare_login_pid_file)"
    rm -f "$log_file" "$pid_file"
    nohup cloudflared tunnel login >"$log_file" 2>&1 < /dev/null &
    echo "$!" > "$pid_file"
    sleep 2

    api_cloudflare_status
}

api_github_config_status() {
    local configured="false"
    local username=""
    local author_name=""
    local author_email=""
    local token_masked=""
    local oauth_client_id=""
    local oauth_scopes
    local oauth_app_configured="false"
    local device_pending="false"
    local device_user_code=""
    local device_verification_uri=""
    local device_interval="0"
    local device_expires_at="0"
    local device_seconds_left="0"

    oauth_scopes="$(github_oauth_scopes_padrao)"

    if github_config_ler; then
        oauth_client_id="${GITHUB_CFG_OAUTH_CLIENT_ID:-}"
        oauth_scopes="${GITHUB_CFG_OAUTH_SCOPES:-$(github_oauth_scopes_padrao)}"
        [[ -n "$oauth_client_id" ]] && oauth_app_configured="true"
    fi

    if github_config_carregar; then
        configured="true"
        username="$GITHUB_CFG_USERNAME"
        author_name="$GITHUB_CFG_AUTHOR_NAME"
        author_email="$GITHUB_CFG_AUTHOR_EMAIL"
        token_masked="$(github_token_mask "$GITHUB_CFG_TOKEN")"
    fi

    if github_device_flow_ativa; then
        device_pending="true"
        device_user_code="$GITHUB_DEVICE_USER_CODE_VALUE"
        device_verification_uri="$GITHUB_DEVICE_VERIFICATION_URI_VALUE"
        device_interval="$GITHUB_DEVICE_INTERVAL_VALUE"
        device_expires_at="$GITHUB_DEVICE_EXPIRES_AT_VALUE"
        device_seconds_left="$(( GITHUB_DEVICE_EXPIRES_AT_VALUE - $(date +%s) ))"
    else
        github_device_flow_limpar
    fi

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --argjson configured "$configured" \
            --argjson oauth_app_configured "$oauth_app_configured" \
            --arg username "$username" \
            --arg author_name "$author_name" \
            --arg author_email "$author_email" \
            --arg token_masked "$token_masked" \
            --arg oauth_client_id "$oauth_client_id" \
            --arg oauth_scopes "$oauth_scopes" \
            --arg config_file "$GITHUB_PANEL_CONFIG_FILE" \
            --argjson device_pending "$device_pending" \
            --arg device_user_code "$device_user_code" \
            --arg device_verification_uri "$device_verification_uri" \
            --argjson device_interval "$device_interval" \
            --argjson device_expires_at "$device_expires_at" \
            --argjson device_seconds_left "$device_seconds_left" \
            '{ok:true,configured:$configured,oauth_app_configured:$oauth_app_configured,username:$username,author_name:$author_name,author_email:$author_email,token_masked:$token_masked,oauth_client_id:$oauth_client_id,oauth_scopes:$oauth_scopes,config_file:$config_file,device_flow:{pending:$device_pending,user_code:$device_user_code,verification_uri:$device_verification_uri,interval:$device_interval,expires_at:$device_expires_at,seconds_left:$device_seconds_left}}'
    else
        echo "{\"ok\":true}"
    fi
}

api_github_config_salvar() {
    local username="${1:-}"
    local token="${2:-}"
    local author_name="${3:-}"
    local author_email="${4:-}"

    if ! github_username_valido "$username"; then
        api_json_erro "Usuario do GitHub invalido."
        return 1
    fi
    if ! github_token_valido "$token"; then
        api_json_erro "Token do GitHub invalido."
        return 1
    fi
    if ! github_autor_nome_valido "$author_name"; then
        api_json_erro "Nome do autor Git invalido."
        return 1
    fi
    if ! github_email_valido "$author_email"; then
        api_json_erro "Email do autor Git invalido."
        return 1
    fi

    github_config_salvar "$username" "$token" "$author_name" "$author_email" || {
        api_json_erro "Falha ao salvar configuracao do GitHub."
        return 1
    }

    api_github_config_status
}

api_github_oauth_app_salvar() {
    local client_id="${1:-}"
    local scopes="${2:-$(github_oauth_scopes_padrao)}"

    if ! github_oauth_client_id_valido "$client_id"; then
        api_json_erro "Client ID do GitHub invalido."
        return 1
    fi
    if ! github_oauth_scopes_validos "$scopes"; then
        api_json_erro "Scopes do GitHub invalidos."
        return 1
    fi

    github_oauth_app_salvar "$client_id" "$scopes" || {
        api_json_erro "Falha ao salvar configuracao OAuth do GitHub."
        return 1
    }

    api_github_config_status
}

api_github_config_remover() {
    github_config_remover
    if command -v jq >/dev/null 2>&1; then
        jq -n '{ok:true,configured:false}'
    else
        echo "{\"ok\":true}"
    fi
}

api_github_listar_repositorios() {
    local payload repos_json

    github_config_carregar || {
        api_json_erro "Credenciais do GitHub nao configuradas."
        return 1
    }

    payload="$(github_api_repos_json "$GITHUB_CFG_TOKEN" 2>/dev/null || true)"
    [[ -n "$payload" ]] || {
        api_json_erro "Falha ao listar repositorios da conta conectada."
        return 1
    }

    if [[ "$(echo "$payload" | jq -r '.error // empty' 2>/dev/null)" != "" ]]; then
        api_json_erro "$(github_api_payload_error_message "$payload" || echo 'Falha ao listar repositorios do GitHub.')"
        return 1
    fi

    repos_json="$(echo "$payload" | jq -c 'map({
        slug: (.full_name // ""),
        name: (.name // ""),
        private: (.private // false),
        archived: (.archived // false),
        owner: (.owner.login // ""),
        default_branch: (.default_branch // ""),
        updated_at: (.updated_at // ""),
        html_url: (.html_url // "")
    })' 2>/dev/null)"
    [[ -n "$repos_json" ]] || repos_json='[]'

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --argjson repos "$repos_json" \
            '{ok:true,count:($repos | length),repos:$repos}'
    else
        echo "{\"ok\":true}"
    fi
}

api_github_device_flow_iniciar() {
    local client_id=""
    local scopes
    local payload device_code user_code verification_uri expires_in interval expires_at
    local http_code tmp_body payload_error

    scopes="$(github_oauth_scopes_padrao)"
    github_config_ler || true
    client_id="${GITHUB_CFG_OAUTH_CLIENT_ID:-}"
    [[ -n "${GITHUB_CFG_OAUTH_SCOPES:-}" ]] && scopes="$GITHUB_CFG_OAUTH_SCOPES"

    if ! github_oauth_client_id_valido "$client_id"; then
        api_json_erro "Configure primeiro o Client ID do OAuth App do GitHub."
        return 1
    fi

    tmp_body="$(mktemp)" || {
        api_json_erro "Falha ao preparar requisicao para o GitHub."
        return 1
    }

    http_code="$(curl -sS -L \
        -H 'Accept: application/json' \
        -o "$tmp_body" \
        -w '%{http_code}' \
        -d "client_id=${client_id}" \
        --data-urlencode "scope=${scopes}" \
        https://github.com/login/device/code 2>/dev/null)" || {
        rm -f "$tmp_body"
        api_json_erro "Falha ao iniciar autorizacao com o GitHub."
        return 1
    }
    payload="$(cat "$tmp_body" 2>/dev/null || true)"
    rm -f "$tmp_body"

    if [[ ! "$http_code" =~ ^2 ]]; then
        payload_error="$(github_api_payload_error_message "$payload" || true)"
        if [[ -n "$payload_error" ]]; then
            api_json_erro "$payload_error"
        else
            api_json_erro "GitHub retornou HTTP ${http_code} ao iniciar autorizacao."
        fi
        return 1
    fi

    if [[ "$(echo "$payload" | jq -r '.error // empty' 2>/dev/null)" != "" ]]; then
        api_json_erro "$(github_api_payload_error_message "$payload" || echo 'Falha ao iniciar autorizacao com o GitHub.')"
        return 1
    fi

    device_code="$(echo "$payload" | jq -r '.device_code // empty')"
    user_code="$(echo "$payload" | jq -r '.user_code // empty')"
    verification_uri="$(echo "$payload" | jq -r '.verification_uri // empty')"
    expires_in="$(echo "$payload" | jq -r '.expires_in // 900')"
    interval="$(echo "$payload" | jq -r '.interval // 5')"
    expires_at="$(( $(date +%s) + expires_in ))"

    if [[ -z "$device_code" || -z "$user_code" || -z "$verification_uri" ]]; then
        api_json_erro "Resposta invalida do GitHub ao iniciar autorizacao."
        return 1
    fi

    github_device_flow_salvar "$device_code" "$user_code" "$verification_uri" "$expires_at" "$interval" "$client_id" "$scopes" || {
        api_json_erro "Falha ao persistir estado da autorizacao do GitHub."
        return 1
    }

    api_github_config_status
}

api_github_device_flow_verificar() {
    local poll_now="${1:-0}"
    local payload error_code access_token user_payload username author_name author_email
    local http_code tmp_body payload_error

    if ! github_device_flow_ler; then
        api_json_erro "Nenhuma autorizacao pendente do GitHub encontrada."
        return 1
    fi
    if ! github_device_flow_ativa; then
        github_device_flow_limpar
        api_json_erro "A autorizacao pendente do GitHub expirou. Inicie novamente."
        return 1
    fi

    if ! bool_sim "$poll_now"; then
        api_github_config_status
        return 0
    fi

    tmp_body="$(mktemp)" || {
        api_json_erro "Falha ao preparar verificacao da autorizacao do GitHub."
        return 1
    }

    http_code="$(curl -sS -L \
        -H 'Accept: application/json' \
        -o "$tmp_body" \
        -w '%{http_code}' \
        -d "client_id=${GITHUB_DEVICE_CLIENT_ID_VALUE}" \
        -d "device_code=${GITHUB_DEVICE_CODE_VALUE}" \
        -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
        https://github.com/login/oauth/access_token 2>/dev/null)" || {
        rm -f "$tmp_body"
        api_json_erro "Falha ao consultar autorizacao pendente do GitHub."
        return 1
    }
    payload="$(cat "$tmp_body" 2>/dev/null || true)"
    rm -f "$tmp_body"

    if [[ ! "$http_code" =~ ^2 ]]; then
        payload_error="$(github_api_payload_error_message "$payload" || true)"
        if [[ -n "$payload_error" ]]; then
            api_json_erro "$payload_error"
        else
            api_json_erro "GitHub retornou HTTP ${http_code} ao verificar autorizacao."
        fi
        return 1
    fi

    error_code="$(echo "$payload" | jq -r '.error // empty' 2>/dev/null)"
    if [[ -n "$error_code" ]]; then
        case "$error_code" in
            authorization_pending|slow_down)
                api_github_config_status
                return 0
                ;;
            access_denied|expired_token|device_flow_disabled|incorrect_client_credentials|incorrect_device_code)
                github_device_flow_limpar
                api_json_erro "$(echo "$payload" | jq -r '.error_description // .error')"
                return 1
                ;;
            *)
                api_json_erro "$(echo "$payload" | jq -r '.error_description // .error')"
                return 1
                ;;
        esac
    fi

    access_token="$(echo "$payload" | jq -r '.access_token // empty')"
    if [[ -z "$access_token" ]]; then
        api_json_erro "O GitHub nao retornou um token de acesso."
        return 1
    fi

    user_payload="$(github_api_user_json "$access_token" 2>/dev/null || true)"
    username="$(echo "$user_payload" | jq -r '.login // empty' 2>/dev/null)"
    author_name="$(echo "$user_payload" | jq -r '.name // empty' 2>/dev/null)"
    author_email="$(echo "$user_payload" | jq -r '.email // empty' 2>/dev/null)"

    if [[ -z "$username" ]]; then
        api_json_erro "Falha ao identificar a conta do GitHub autorizada."
        return 1
    fi
    if [[ -z "$author_name" ]]; then
        author_name="$username"
    fi
    if [[ -z "$author_email" ]]; then
        author_email="$(github_email_primario_por_token "$access_token" || true)"
    fi
    if [[ -z "$author_email" ]]; then
        author_email="${username}@users.noreply.github.com"
    fi

    github_config_escrever \
        "$username" \
        "$access_token" \
        "$author_name" \
        "$author_email" \
        "$GITHUB_DEVICE_CLIENT_ID_VALUE" \
        "$GITHUB_DEVICE_SCOPES_VALUE" || {
        api_json_erro "Falha ao salvar token conectado do GitHub."
        return 1
    }

    github_device_flow_limpar
    api_github_config_status
}

api_github_clone_status_usuario() {
    local user="${1:-}"
    local repo_dir status_exists="false" repo_exists="false" running="false" finished="false"
    local state="idle" job_id="" repo_slug="" branch="" pid="0" started_at="0" updated_at="0" completed_at="0" exit_code="0" message=""
    local log_file="" progress_raw percent="0" phase="Pronto" detail="" log_tail=""
    local started_at_json updated_at_json completed_at_json percent_json

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site nao encontrado."
        return 1
    fi

    repo_dir="$(github_repo_dir_por_usuario "$user")"
    [[ -d "${repo_dir}/.git" ]] && repo_exists="true"

    if github_clone_job_ler "$user"; then
        status_exists="true"
        github_clone_job_marcar_stale "$user" || true
        github_clone_job_ler "$user" || true

        state="$GITHUB_CLONE_STATE_VALUE"
        job_id="$GITHUB_CLONE_JOB_ID_VALUE"
        repo_slug="$GITHUB_CLONE_REPO_VALUE"
        branch="$GITHUB_CLONE_BRANCH_VALUE"
        pid="$GITHUB_CLONE_PID_VALUE"
        started_at="$GITHUB_CLONE_STARTED_AT_VALUE"
        updated_at="$GITHUB_CLONE_UPDATED_AT_VALUE"
        completed_at="$GITHUB_CLONE_COMPLETED_AT_VALUE"
        exit_code="$GITHUB_CLONE_EXIT_CODE_VALUE"
        message="$GITHUB_CLONE_MESSAGE_VALUE"
        log_file="$GITHUB_CLONE_LOG_FILE_VALUE"

        if [[ "$state" == "running" ]]; then
            running="true"
            progress_raw="$(github_clone_job_percentual_por_log "$log_file")"
            percent="${progress_raw%%|*}"
            progress_raw="${progress_raw#*|}"
            phase="${progress_raw%%|*}"
            detail="${progress_raw#*|}"
        elif [[ "$state" == "completed" ]]; then
            finished="true"
            percent="100"
            phase="Clone concluido"
            detail="${message:-Clone concluido com sucesso.}"
        elif [[ "$state" == "error" ]]; then
            finished="true"
            percent="100"
            phase="Clone interrompido"
            detail="${message:-Falha ao clonar repositorio.}"
        fi

        if [[ -f "$log_file" ]]; then
            log_tail="$(tail -n 12 "$log_file" 2>/dev/null || true)"
        fi
    fi

    started_at_json="$(github_json_int_or_zero "$started_at")"
    updated_at_json="$(github_json_int_or_zero "$updated_at")"
    completed_at_json="$(github_json_int_or_zero "$completed_at")"
    percent_json="$(github_json_int_or_zero "$percent")"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg path "$repo_dir" \
            --argjson status_exists "$status_exists" \
            --argjson repo_exists "$repo_exists" \
            --argjson running "$running" \
            --argjson finished "$finished" \
            --arg state "$state" \
            --arg job_id "$job_id" \
            --arg repo "$repo_slug" \
            --arg branch "$branch" \
            --arg pid "$pid" \
            --argjson started_at "$started_at_json" \
            --argjson updated_at "$updated_at_json" \
            --argjson completed_at "$completed_at_json" \
            --arg exit_code "$exit_code" \
            --arg message "$message" \
            --argjson percent "$percent_json" \
            --arg phase "$phase" \
            --arg detail "$detail" \
            --arg log_tail "$log_tail" \
            '{ok:true,site_user:$user,path:$path,status_exists:$status_exists,repo_exists:$repo_exists,running:$running,finished:$finished,state:$state,job_id:$job_id,repo:$repo,branch:$branch,pid:$pid,started_at:$started_at,updated_at:$updated_at,completed_at:$completed_at,exit_code:$exit_code,message:$message,percent:$percent,phase:$phase,detail:$detail,log_tail:$log_tail}'
    else
        echo "{\"ok\":true}"
    fi
}

api_github_clone_iniciar_usuario() {
    local user="${1:-}"
    local repo_slug="${2:-}"
    local branch="${3:-}"
    local limpar_destino="${4:-0}"
    local repo_dir repo_url job_id started_at pid log_file

    if ! command -v git >/dev/null 2>&1; then
        api_json_erro "Git nao encontrado no servidor."
        return 1
    fi
    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site nao encontrado."
        return 1
    fi
    if ! github_repo_slug_valido "$repo_slug"; then
        api_json_erro "Repositorio GitHub invalido."
        return 1
    fi
    if [[ -n "$branch" ]] && ! github_branch_valida "$branch"; then
        api_json_erro "Branch invalida."
        return 1
    fi
    github_config_carregar || {
        api_json_erro "Credenciais do GitHub nao configuradas."
        return 1
    }
    if github_clone_job_esta_rodando "$user"; then
        api_json_erro "Ja existe um clone em andamento para esse site."
        return 1
    fi

    repo_dir="$(github_repo_dir_por_usuario "$user")"
    repo_url="$(github_repo_url_https "$repo_slug")"

    mkdir -p "$repo_dir"
    chown "${user}:${user}" "$repo_dir" >/dev/null 2>&1 || true

    if [[ -d "${repo_dir}/.git" ]]; then
        api_json_erro "Esse site ja possui um repositorio Git inicializado."
        return 1
    fi

    if find "$repo_dir" -mindepth 1 -maxdepth 1 | read -r _; then
        if ! bool_sim "$limpar_destino"; then
            api_json_erro "public_html nao esta vazio. Marque a opcao para limpar antes do clone."
            return 1
        fi
    fi

    job_id="$(date +%s)-${RANDOM}"
    started_at="$(date +%s)"
    log_file="$(github_clone_log_file_por_usuario "$user")"
    : > "$log_file"
    chmod 600 "$log_file"

    nohup bash "$WEB_PANEL_API_SCRIPT" __api github-site-clone-runner "$user" "$repo_slug" "$branch" "$limpar_destino" "$job_id" >/dev/null 2>&1 &
    pid="$!"

    github_clone_job_salvar \
        "$user" \
        "running" \
        "$job_id" \
        "$repo_slug" \
        "$branch" \
        "$pid" \
        "$started_at" \
        "$started_at" \
        "0" \
        "0" \
        "Clone iniciado em background." \
        "$log_file"

    api_github_clone_status_usuario "$user"
}

api_github_clone_runner_usuario() {
    local user="${1:-}"
    local repo_slug="${2:-}"
    local branch="${3:-}"
    local limpar_destino="${4:-0}"
    local job_id="${5:-}"
    local repo_dir repo_url log_file started_at pid current_branch failure_reason

    pid="$$"
    log_file="$(github_clone_log_file_por_usuario "$user")"
    started_at="$(date +%s)"
    if github_clone_job_ler "$user" && [[ "$GITHUB_CLONE_JOB_ID_VALUE" == "$job_id" ]]; then
        started_at="$GITHUB_CLONE_STARTED_AT_VALUE"
        log_file="$GITHUB_CLONE_LOG_FILE_VALUE"
        pid="$GITHUB_CLONE_PID_VALUE"
    fi

    github_clone_job_salvar \
        "$user" \
        "running" \
        "$job_id" \
        "$repo_slug" \
        "$branch" \
        "$pid" \
        "$started_at" \
        "$(date +%s)" \
        "0" \
        "0" \
        "Preparando clone do repositorio." \
        "$log_file"

    if ! command -v git >/dev/null 2>&1; then
        failure_reason="Git nao encontrado no servidor."
    elif ! usuario_valido "$user"; then
        failure_reason="Usuario invalido."
    elif [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        failure_reason="Site nao encontrado."
    elif ! github_repo_slug_valido "$repo_slug"; then
        failure_reason="Repositorio GitHub invalido."
    elif [[ -n "$branch" ]] && ! github_branch_valida "$branch"; then
        failure_reason="Branch invalida."
    elif ! github_config_carregar; then
        failure_reason="Credenciais do GitHub nao configuradas."
    else
        repo_dir="$(github_repo_dir_por_usuario "$user")"
        repo_url="$(github_repo_url_https "$repo_slug")"

        mkdir -p "$repo_dir"
        chown "${user}:${user}" "$repo_dir" >/dev/null 2>&1 || true

        if [[ -d "${repo_dir}/.git" ]]; then
            failure_reason="Esse site ja possui um repositorio Git inicializado."
        elif find "$repo_dir" -mindepth 1 -maxdepth 1 | read -r _; then
            if bool_sim "$limpar_destino"; then
                find "$repo_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
            else
                failure_reason="public_html nao esta vazio. Marque a opcao para limpar antes do clone."
            fi
        fi
    fi

    if [[ -n "${failure_reason:-}" ]]; then
        printf '%s\n' "$failure_reason" >> "$log_file"
        github_clone_job_salvar \
            "$user" \
            "error" \
            "$job_id" \
            "$repo_slug" \
            "$branch" \
            "$pid" \
            "$started_at" \
            "$(date +%s)" \
            "$(date +%s)" \
            "1" \
            "$failure_reason" \
            "$log_file"
        return 1
    fi

    github_clone_job_salvar \
        "$user" \
        "running" \
        "$job_id" \
        "$repo_slug" \
        "$branch" \
        "$pid" \
        "$started_at" \
        "$(date +%s)" \
        "0" \
        "0" \
        "Clonando repositorio em public_html." \
        "$log_file"

    if [[ -n "$branch" ]]; then
        github_git_exec_por_usuario "$user" 1 git clone --progress --depth 1 --no-tags --branch "$branch" --single-branch "$repo_url" "$repo_dir" >"$log_file" 2>&1
    else
        github_git_exec_por_usuario "$user" 1 git clone --progress --depth 1 --no-tags "$repo_url" "$repo_dir" >"$log_file" 2>&1
    fi

    if [[ $? -ne 0 ]]; then
        failure_reason="$(tail -n 1 "$log_file" 2>/dev/null || true)"
        [[ -n "$failure_reason" ]] || failure_reason="Falha ao clonar repositorio."
        github_clone_job_salvar \
            "$user" \
            "error" \
            "$job_id" \
            "$repo_slug" \
            "$branch" \
            "$pid" \
            "$started_at" \
            "$(date +%s)" \
            "$(date +%s)" \
            "1" \
            "$failure_reason" \
            "$log_file"
        return 1
    fi

    if [[ -n "$GITHUB_CFG_AUTHOR_NAME" ]]; then
        github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" config user.name "$GITHUB_CFG_AUTHOR_NAME" >/dev/null 2>&1 || true
    fi
    if [[ -n "$GITHUB_CFG_AUTHOR_EMAIL" ]]; then
        github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" config user.email "$GITHUB_CFG_AUTHOR_EMAIL" >/dev/null 2>&1 || true
    fi

    current_branch="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    [[ -n "$current_branch" ]] || current_branch="$branch"

    github_clone_job_salvar \
        "$user" \
        "completed" \
        "$job_id" \
        "$repo_slug" \
        "$current_branch" \
        "$pid" \
        "$started_at" \
        "$(date +%s)" \
        "$(date +%s)" \
        "0" \
        "Clone concluido com sucesso." \
        "$log_file"
}

api_github_status_repositorio_usuario() {
    local user="${1:-}"

    if ! command -v git >/dev/null 2>&1; then
        api_json_erro "Git nao encontrado no servidor."
        return 1
    fi

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site nao encontrado."
        return 1
    fi

    local repo_dir
    repo_dir="$(github_repo_dir_por_usuario "$user")"
    local configured="false"
    github_config_carregar && configured="true"

    if [[ ! -d "${repo_dir}/.git" ]]; then
        if command -v jq >/dev/null 2>&1; then
            jq -n \
                --arg user "$user" \
                --arg path "$repo_dir" \
                --argjson configured "$configured" \
                '{ok:true,site_user:$user,path:$path,configured:$configured,repo_exists:false}'
        else
            echo "{\"ok\":true,\"site_user\":\"${user}\"}"
        fi
        return 0
    fi

    local branch remote_url last_commit dirty_status counts ahead behind
    branch="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    remote_url="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" remote get-url origin 2>/dev/null || true)"
    last_commit="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" log -1 --pretty=format:%h\ %s 2>/dev/null || true)"
    dirty_status="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" status --porcelain 2>/dev/null || true)"
    counts="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" rev-list --left-right --count @{upstream}...HEAD 2>/dev/null || true)"

    ahead="0"
    behind="0"
    if [[ "$counts" =~ ^[0-9]+[[:space:]][0-9]+$ ]]; then
        behind="${counts%% *}"
        ahead="${counts##* }"
    fi

    local dirty="false"
    [[ -n "$dirty_status" ]] && dirty="true"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg path "$repo_dir" \
            --arg branch "$branch" \
            --arg remote "$remote_url" \
            --arg last_commit "$last_commit" \
            --argjson configured "$configured" \
            --argjson dirty "$dirty" \
            --argjson ahead "$ahead" \
            --argjson behind "$behind" \
            '{ok:true,site_user:$user,path:$path,configured:$configured,repo_exists:true,branch:$branch,remote:$remote,dirty:$dirty,ahead:$ahead,behind:$behind,last_commit:$last_commit}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_github_clonar_repositorio_usuario() {
    local user="${1:-}"
    local repo_slug="${2:-}"
    local branch="${3:-}"
    local limpar_destino="${4:-0}"

    if ! command -v git >/dev/null 2>&1; then
        api_json_erro "Git nao encontrado no servidor."
        return 1
    fi

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if [[ ! -d "${SITES_ROOT}/${user}" || ! -d "${VHOSTS_DIR}/${user}" ]]; then
        api_json_erro "Site nao encontrado."
        return 1
    fi
    if ! github_repo_slug_valido "$repo_slug"; then
        api_json_erro "Repositorio GitHub invalido."
        return 1
    fi
    if [[ -n "$branch" ]] && ! github_branch_valida "$branch"; then
        api_json_erro "Branch invalida."
        return 1
    fi
    github_config_carregar || {
        api_json_erro "Credenciais do GitHub nao configuradas."
        return 1
    }

    local repo_dir
    local repo_url
    repo_dir="$(github_repo_dir_por_usuario "$user")"
    repo_url="$(github_repo_url_https "$repo_slug")"

    mkdir -p "$repo_dir"
    chown "${user}:${user}" "$repo_dir" >/dev/null 2>&1 || true

    if [[ -d "${repo_dir}/.git" ]]; then
        api_json_erro "Esse site ja possui um repositorio Git inicializado."
        return 1
    fi

    if find "$repo_dir" -mindepth 1 -maxdepth 1 | read -r _; then
        if bool_sim "$limpar_destino"; then
            find "$repo_dir" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
        else
            api_json_erro "public_html nao esta vazio. Marque a opcao para limpar antes do clone."
            return 1
        fi
    fi

    local output
    if [[ -n "$branch" ]]; then
        output="$(github_git_exec_por_usuario "$user" 1 git clone --branch "$branch" --single-branch "$repo_url" "$repo_dir" 2>&1)" || {
            api_json_erro "$output"
            return 1
        }
    else
        output="$(github_git_exec_por_usuario "$user" 1 git clone "$repo_url" "$repo_dir" 2>&1)" || {
            api_json_erro "$output"
            return 1
        }
    fi

    if [[ -n "$GITHUB_CFG_AUTHOR_NAME" ]]; then
        github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" config user.name "$GITHUB_CFG_AUTHOR_NAME" >/dev/null 2>&1 || true
    fi
    if [[ -n "$GITHUB_CFG_AUTHOR_EMAIL" ]]; then
        github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" config user.email "$GITHUB_CFG_AUTHOR_EMAIL" >/dev/null 2>&1 || true
    fi

    local current_branch
    current_branch="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg repo "$repo_slug" \
            --arg path "$repo_dir" \
            --arg branch "$current_branch" \
            --arg output "$output" \
            '{ok:true,site_user:$user,repo:$repo,path:$path,branch:$branch,output:$output}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_github_pull_repositorio_usuario() {
    local user="${1:-}"

    if ! command -v git >/dev/null 2>&1; then
        api_json_erro "Git nao encontrado no servidor."
        return 1
    fi

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if ! github_repo_existe_por_usuario "$user"; then
        api_json_erro "Repositorio Git nao encontrado nesse site."
        return 1
    fi
    github_config_carregar || {
        api_json_erro "Credenciais do GitHub nao configuradas."
        return 1
    }

    local repo_dir branch output
    repo_dir="$(github_repo_dir_por_usuario "$user")"
    branch="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    [[ -n "$branch" ]] || branch="main"

    output="$(github_git_exec_por_usuario "$user" 1 git -C "$repo_dir" pull --ff-only origin "$branch" 2>&1)" || {
        api_json_erro "$output"
        return 1
    }

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg path "$repo_dir" \
            --arg branch "$branch" \
            --arg output "$output" \
            '{ok:true,site_user:$user,path:$path,branch:$branch,output:$output}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_github_commit_push_usuario() {
    local user="${1:-}"
    local commit_msg="${2:-}"

    if ! command -v git >/dev/null 2>&1; then
        api_json_erro "Git nao encontrado no servidor."
        return 1
    fi

    if ! usuario_valido "$user"; then
        api_json_erro "Usuario invalido."
        return 1
    fi
    if ! github_repo_existe_por_usuario "$user"; then
        api_json_erro "Repositorio Git nao encontrado nesse site."
        return 1
    fi
    if ! github_commit_msg_valida "$commit_msg"; then
        api_json_erro "Mensagem de commit invalida."
        return 1
    fi
    github_config_carregar || {
        api_json_erro "Credenciais do GitHub nao configuradas."
        return 1
    }

    local repo_dir branch current_name current_email commit_output push_output
    repo_dir="$(github_repo_dir_por_usuario "$user")"

    current_name="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" config --get user.name 2>/dev/null || true)"
    current_email="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" config --get user.email 2>/dev/null || true)"

    if [[ -n "$GITHUB_CFG_AUTHOR_NAME" ]]; then
        github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" config user.name "$GITHUB_CFG_AUTHOR_NAME" >/dev/null 2>&1 || true
        current_name="$GITHUB_CFG_AUTHOR_NAME"
    fi
    if [[ -n "$GITHUB_CFG_AUTHOR_EMAIL" ]]; then
        github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" config user.email "$GITHUB_CFG_AUTHOR_EMAIL" >/dev/null 2>&1 || true
        current_email="$GITHUB_CFG_AUTHOR_EMAIL"
    fi

    if [[ -z "$current_name" || -z "$current_email" ]]; then
        api_json_erro "Autor Git nao configurado. Salve nome e email do autor nas credenciais do GitHub."
        return 1
    fi

    github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" add -A >/dev/null 2>&1 || {
        api_json_erro "Falha ao preparar alteracoes para commit."
        return 1
    }

    if github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" diff --cached --quiet --ignore-submodules -- >/dev/null 2>&1; then
        if command -v jq >/dev/null 2>&1; then
            jq -n \
                --arg user "$user" \
                --arg path "$repo_dir" \
                '{ok:true,site_user:$user,path:$path,no_changes:true}'
        else
            echo "{\"ok\":true,\"site_user\":\"${user}\"}"
        fi
        return 0
    fi

    commit_output="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" commit -m "$commit_msg" 2>&1)" || {
        api_json_erro "$commit_output"
        return 1
    }

    branch="$(github_git_exec_por_usuario "$user" 0 git -C "$repo_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    [[ -n "$branch" ]] || branch="main"

    push_output="$(github_git_exec_por_usuario "$user" 1 git -C "$repo_dir" push origin "$branch" 2>&1)" || {
        api_json_erro "$push_output"
        return 1
    }

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg user "$user" \
            --arg path "$repo_dir" \
            --arg branch "$branch" \
            --arg commit_output "$commit_output" \
            --arg push_output "$push_output" \
            '{ok:true,site_user:$user,path:$path,branch:$branch,commit_output:$commit_output,push_output:$push_output,no_changes:false}'
    else
        echo "{\"ok\":true,\"site_user\":\"${user}\"}"
    fi
}

api_main() {
    local cmd="${1:-}"
    shift || true

    case "$cmd" in
        create-site)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api create-site <dominio> [php] [instalar_wp:0|1] [criar_tunnel:0|1]"; return 1; }
            api_criar_site "$1" "${2:-8.4}" "${3:-0}" "${4:-0}"
            ;;
        create-db-additional)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api create-db-additional <site_user> [sufixo]"; return 1; }
            api_criar_banco_adicional "$1" "${2:-}"
            ;;
        clone-site)
            [[ $# -ge 2 ]] || { api_json_erro "uso: __api clone-site <source_user> <dest_domain> [php] [criar_tunnel:0|1]"; return 1; }
            api_clonar_site "$1" "$2" "${3:-8.4}" "${4:-0}"
            ;;
        remove-site)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api remove-site <site_user> [backup:0|1]"; return 1; }
            api_remover_site_por_usuario "$1" "${2:-1}"
            ;;
        cron-add)
            [[ $# -ge 3 ]] || { api_json_erro "uso: __api cron-add <site_user> <expressao> <comando> [executar_em_public_html:0|1]"; return 1; }
            api_cron_adicionar "$1" "$2" "$3" "${4:-1}"
            ;;
        cron-list)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api cron-list <site_user>"; return 1; }
            api_cron_listar "$1"
            ;;
        cron-remove)
            [[ $# -ge 2 ]] || { api_json_erro "uso: __api cron-remove <site_user> <linha_exata>"; return 1; }
            api_cron_remover_linha "$1" "$2"
            ;;
        install-stack-base)
            api_instalar_stack_base
            ;;
        configure-phpmyadmin-domain)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api configure-phpmyadmin-domain <dominio> [remover_outros:0|1] [criar_tunnel:0|1]"; return 1; }
            api_configurar_phpmyadmin_principal "$1" "${2:-1}" "${3:-0}"
            ;;
        configure-panel-domain)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api configure-panel-domain <dominio> [criar_tunnel:0|1]"; return 1; }
            api_configurar_painel_web_principal "$1" "${2:-0}"
            ;;
        db-rotate-password)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api db-rotate-password <site_user>"; return 1; }
            api_trocar_senha_banco_por_usuario "$1"
            ;;
        site-set-ssh-password)
            [[ $# -ge 2 ]] || { api_json_erro "uso: __api site-set-ssh-password <site_user> <nova_senha>"; return 1; }
            api_trocar_senha_ssh_por_usuario "$1" "$2"
            ;;
        site-error-log)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api site-error-log <site_user> [linhas]"; return 1; }
            api_ver_logs_erro_por_usuario "$1" "${2:-80}"
            ;;
        wordpress-fix-permalink)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api wordpress-fix-permalink <site_user>"; return 1; }
            api_corrigir_permalink_wordpress_por_usuario "$1"
            ;;
        site-fix-rewrite)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api site-fix-rewrite <site_user> [front_controller]"; return 1; }
            api_corrigir_rewrite_por_usuario "$1" "${2:-index.php}"
            ;;
        htaccess-verify)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api htaccess-verify <site_user>"; return 1; }
            api_verificar_htaccess_por_usuario "$1"
            ;;
        ols-set-admin)
            [[ $# -ge 2 ]] || { api_json_erro "uso: __api ols-set-admin <usuario> <senha>"; return 1; }
            api_definir_credenciais_ols_admin "$1" "$2"
            ;;
        cloudflare-status)
            api_cloudflare_status
            ;;
        cloudflare-login-start)
            api_cloudflare_login_start
            ;;
        github-config-status)
            api_github_config_status
            ;;
        github-config-set)
            [[ $# -ge 4 ]] || { api_json_erro "uso: __api github-config-set <usuario> <token> <autor_nome> <autor_email>"; return 1; }
            api_github_config_salvar "$1" "$2" "$3" "$4"
            ;;
        github-oauth-app-set)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api github-oauth-app-set <client_id> [scopes]"; return 1; }
            api_github_oauth_app_salvar "$1" "${2:-$(github_oauth_scopes_padrao)}"
            ;;
        github-config-clear)
            api_github_config_remover
            ;;
        github-repos-list)
            api_github_listar_repositorios
            ;;
        github-device-start)
            api_github_device_flow_iniciar
            ;;
        github-device-poll)
            api_github_device_flow_verificar "${1:-0}"
            ;;
        github-site-status)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api github-site-status <site_user>"; return 1; }
            api_github_status_repositorio_usuario "$1"
            ;;
        github-site-clone-start)
            [[ $# -ge 2 ]] || { api_json_erro "uso: __api github-site-clone-start <site_user> <owner/repo> [branch] [limpar_destino:0|1]"; return 1; }
            api_github_clone_iniciar_usuario "$1" "$2" "${3:-}" "${4:-0}"
            ;;
        github-site-clone-status)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api github-site-clone-status <site_user>"; return 1; }
            api_github_clone_status_usuario "$1"
            ;;
        github-site-clone-runner)
            [[ $# -ge 5 ]] || { api_json_erro "uso: __api github-site-clone-runner <site_user> <owner/repo> <branch> <limpar_destino:0|1> <job_id>"; return 1; }
            api_github_clone_runner_usuario "$1" "$2" "${3:-}" "${4:-0}" "$5"
            ;;
        github-site-clone)
            [[ $# -ge 2 ]] || { api_json_erro "uso: __api github-site-clone <site_user> <owner/repo> [branch] [limpar_destino:0|1]"; return 1; }
            api_github_clonar_repositorio_usuario "$1" "$2" "${3:-}" "${4:-0}"
            ;;
        github-site-pull)
            [[ $# -ge 1 ]] || { api_json_erro "uso: __api github-site-pull <site_user>"; return 1; }
            api_github_pull_repositorio_usuario "$1"
            ;;
        github-site-commit-push)
            [[ $# -ge 2 ]] || { api_json_erro "uso: __api github-site-commit-push <site_user> <mensagem_commit>"; return 1; }
            api_github_commit_push_usuario "$1" "$2"
            ;;
        *)
            api_json_erro "comando api inválido"
            return 1
            ;;
    esac
}

# Acoes do menu organizadas por secao
# Setup e servicos
acao_setup_instalar_stack() { instalar_stack_completa; }
acao_setup_login_cloudflare() { login_cloudflare; }
acao_setup_mostrar_status() { mostrar_status; }
acao_setup_reiniciar_servicos() { reiniciar_servicos; }
acao_setup_definir_senha_ols() { definir_senha_admin_ols; }
acao_setup_configurar_painel_web() { configurar_painel_web_dominio_principal; }
acao_setup_atualizar_painel_web() { atualizar_painel_web_instalado; }

# Sites
acao_site_criar_ultra() { criar_site_ultra; }
acao_site_listar() { listar_sites; }
acao_site_clonar() { clonar_site; }
acao_site_remover() { remover_site; }
acao_site_suspender() { suspender_site; }
acao_site_reativar() { reativar_site; }
acao_site_configurar_phpmyadmin_principal() { configurar_phpmyadmin_dominio_principal; }

# Banco e cron
acao_db_trocar_senha() { trocar_senha_banco; }
acao_db_criar_banco_adicional() { criar_banco_adicional_site; }
acao_cron_adicionar_entrada() { adicionar_entrada_cron_site; }

# Diagnostico e rewrite
acao_diag_ver_logs_erro() { ver_logs_erro_site; }
acao_diag_verificar_htaccess() { verificar_htaccess_site; }
acao_rewrite_corrigir_permalink_wp() { corrigir_permalink_wordpress_site; }
acao_rewrite_corrigir_site_nao_wp() { corrigir_rewrite_site_nao_wordpress; }

mostrar_ajuda_detalhada_menu() {
    titulo
    cat <<'EOF'
========== AJUDA DETALHADA DO MENU ==========

1  - Instalar stack completa
     Instala/atualiza repositórios e pacotes principais:
     OpenLiteSpeed, PHPs suportados, MariaDB, Redis, cloudflared e phpMyAdmin.

2  - Login no Cloudflare
     Abre o fluxo de autenticação do cloudflared.
     Necessário antes de criar tunnels para domínios.

3  - Mostrar status do ambiente
     Exibe status dos serviços (lsws, mariadb, redis), versão do cloudflared
     e informações úteis do ambiente.

4  - Reiniciar serviços
     Reinicia serviços centrais da stack (mariadb, redis, lsws, crond)
     e garante comando php no terminal.

5  - Definir senha admin do OpenLiteSpeed
     Abre o utilitário oficial do OLS para trocar senha do painel admin.

6  - Criar novo site ULTRA
     Cria usuário Linux, estrutura do site, banco principal, vhost,
     cron padrão e opcionalmente WordPress + tunnel Cloudflare.

7  - Listar sites
     Mostra sites existentes, usuários, credenciais salvas e status de tunnel.

8  - Clonar site
     Clona arquivos e tenta clonar banco (via mysqldump) para um novo domínio.
     Também cria estrutura, vhost e opcionalmente tunnel no destino.

9  - Remover site
     Remove site completo (arquivos, usuário Linux, banco(s), vhost e tunnel),
     gerando backup antes da exclusão.

10 - Suspender site
     Marca site como suspenso, restringe public_html e para tunnel individual.

11 - Reativar site
     Reverte suspensão e tenta reativar tunnel do site.

12 - Configurar domínio principal do phpMyAdmin
     Cria/atualiza um domínio dedicado do servidor para phpMyAdmin
     (usuário phpmyadmin_srv), com opção de tunnel Cloudflare.

13 - Trocar senha do banco
     Troca senha do usuário do banco principal do site e atualiza .env quando houver.

14 - Criar banco adicional para site
     Cria novo banco e novo usuário de banco para o mesmo site,
     salvando credenciais em /root/<usuario>_db_extra.txt.

15 - Adicionar entrada cron para site
     Adiciona cron personalizado com validação de expressão e ajuste automático
     do comando php para o binário correto do site.

16 - Ver logs de erro do site
     Exibe tail do log de erro do vhost para diagnóstico rápido.

17 - Verificar .htaccess do site
     Valida configurações de rewrite no vhost, presença/permissões do .htaccess
     e status do OpenLiteSpeed.

18 - Corrigir permalink WordPress
     Força bloco de rewrite WordPress e executa flush de regras via WP-CLI.

19 - Corrigir rewrite (site não WordPress)
     Aplica bloco de rewrite padrão para aplicações com front-controller
     (ex: index.php para Laravel/Slim e afins).

20 - Configurar domínio principal do painel web
     Publica o painel web administrativo em domínio próprio (usuário painel_srv),
     com login, acesso a phpMyAdmin, gerenciamento de arquivos e ações básicas.

21 - Atualizar painel web
     Reinstala helper/script do painel, sincroniza os arquivos publicados do
     webpanel em producao e reinicia o OpenLiteSpeed sem trocar credenciais.

0  - Sair
     Encerra o painel.

=============================================
EOF
}

menu() {
    while true; do
        clear
        titulo
        echo "=== SETUP E SERVIÇOS ==="
        echo "1  - Instalar stack completa"
        echo "2  - Login no Cloudflare"
        echo "3  - Mostrar status do ambiente"
        echo "4  - Reiniciar serviços"
        echo "5  - Definir senha admin do OpenLiteSpeed"
        echo
        echo "=== SITES ==="
        echo "6  - Criar novo site ULTRA"
        echo "7  - Listar sites"
        echo "8  - Clonar site"
        echo "9  - Remover site"
        echo "10 - Suspender site"
        echo "11 - Reativar site"
        echo "12 - Configurar domínio principal do phpMyAdmin"
        echo
        echo "=== BANCO E CRON ==="
        echo "13 - Trocar senha do banco"
        echo "14 - Criar banco adicional para site"
        echo "15 - Adicionar entrada cron para site"
        echo
        echo "=== DIAGNÓSTICO E REWRITE ==="
        echo "16 - Ver logs de erro do site"
        echo "17 - Verificar .htaccess do site"
        echo "18 - Corrigir permalink WordPress"
        echo "19 - Corrigir rewrite (site não WordPress)"
        echo "20 - Configurar domínio principal do painel web"
        echo "H  - Ajuda detalhada das opções"
        echo "21 - Atualizar painel web"
        echo "0  - Sair"
        echo
        read -rp "Escolha uma opção: " op

        case "$op" in
            1) acao_setup_instalar_stack ;;
            2) acao_setup_login_cloudflare ;;
            3) acao_setup_mostrar_status ;;
            4) acao_setup_reiniciar_servicos ;;
            5) acao_setup_definir_senha_ols ;;
            6) acao_site_criar_ultra ;;
            7) acao_site_listar ;;
            8) acao_site_clonar ;;
            9) acao_site_remover ;;
            10) acao_site_suspender ;;
            11) acao_site_reativar ;;
            12) acao_site_configurar_phpmyadmin_principal ;;
            13) acao_db_trocar_senha ;;
            14) acao_db_criar_banco_adicional ;;
            15) acao_cron_adicionar_entrada ;;
            16) acao_diag_ver_logs_erro ;;
            17) acao_diag_verificar_htaccess ;;
            18) acao_rewrite_corrigir_permalink_wp ;;
            19) acao_rewrite_corrigir_site_nao_wp ;;
            20) acao_setup_configurar_painel_web ;;
            21) acao_setup_atualizar_painel_web ;;
            [Hh]) mostrar_ajuda_detalhada_menu ;;
            0) exit 0 ;;
            *) aviso "Opção inválida." ;;
        esac

        echo
        pausa
    done
}

main() {
    local modo="${1:-menu}"
    shift || true

    checar_root

    if [[ "$modo" == "__api" ]]; then
        api_main "$@"
        return $?
    fi

    checar_systemd
    garantir_comando_php_cli || true
    menu
}

main "$@"
