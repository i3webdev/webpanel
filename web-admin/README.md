# ULTRA Web Panel

Arquivos do painel web administrativo.

- `public/index.php`: interface web.
- `config/panel.env`: credenciais e configurações.
- `ultra-panel-helper.sh`: helper root usado via sudo.

A instalação/publicação é feita pela opção do `script.sh`.

## Fluxo recomendado

1. Rodar `script.sh` opção **1 - Instalar stack completa**.
2. Durante a instalação guiada:
   - autenticar no Cloudflare,
   - configurar domínio principal do painel web,
   - configurar domínio principal do phpMyAdmin.
3. Fazer operação diária no painel web:
   - criar sites (com PHP, WordPress opcional e tunnel opcional),
   - clonar sites,
   - remover sites com backup,
   - criar banco adicional por site,
   - gerenciar cron por site (adicionar/listar/remover),
   - gerenciar arquivos, status e serviços.
