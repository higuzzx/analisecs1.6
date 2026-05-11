#!/usr/bin/env bash
# =============================================================================
# hardening/templates/iptables.sh
# =============================================================================
# Template de regras iptables para hardening de servidores CS 1.6 / GoldSource
#
# IMPORTANTE: Revise e adapte antes de aplicar.
#             Execute como root. Teste em ambiente isolado primeiro.
#
# Autor : Higor Samuel — Unimontes / DTI
# Uso   : sudo bash iptables.sh [--porta 27015] [--admin-ip SEU_IP]
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuração — ajuste conforme seu ambiente
# ---------------------------------------------------------------------------
PORTA_JOGO="${PORTA_JOGO:-27015}"          # Porta UDP do servidor CS 1.6
ADMIN_IP="${ADMIN_IP:-}"                   # IP do administrador para RCON (deixe vazio para bloquear tudo)
LIMITE_REQ_SEC=20                          # Máx. requisições UDP por segundo por IP
BURST_PERMITIDO=50                         # Burst máximo antes do rate limiting

# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------
log() { echo "[$(date '+%H:%M:%S')] $*"; }
erro() { echo "[ERRO] $*" >&2; exit 1; }

verificar_root() {
    [[ $EUID -ne 0 ]] && erro "Este script deve ser executado como root (sudo)."
}

verificar_iptables() {
    command -v iptables &>/dev/null || erro "iptables não encontrado. Instale com: apt install iptables"
}

# ---------------------------------------------------------------------------
# Aplicação das regras
# ---------------------------------------------------------------------------
aplicar_regras() {
    log "Iniciando configuração de hardening para porta ${PORTA_JOGO}/UDP..."

    # ---- 1. Permitir tráfego já estabelecido (stateful) ----
    # Essencial para não bloquear respostas legítimas de conexões existentes
    iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    log "✓ Regras stateful configuradas."

    # ---- 2. Permitir loopback (localhost) ----
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    log "✓ Loopback liberado."

    # ---- 3. Rate limiting UDP na porta do jogo (mitigação de amplificação) ----
    # hashlimit rastreia requisições por IP de origem individualmente
    # Isso impede que um único IP use o servidor como amplificador UDP
    iptables -A INPUT \
        -p udp \
        --dport "${PORTA_JOGO}" \
        -m hashlimit \
        --hashlimit-name "cs16_rate" \
        --hashlimit-mode srcip \
        --hashlimit-upto "${LIMITE_REQ_SEC}/sec" \
        --hashlimit-burst "${BURST_PERMITIDO}" \
        -j ACCEPT
    log "✓ Rate limiting UDP configurado: ${LIMITE_REQ_SEC} req/s por IP (burst: ${BURST_PERMITIDO})."

    # ---- 4. Descartar pacotes UDP que excederem o rate limit ----
    # Pacotes acima do limite são silenciosamente descartados (DROP vs REJECT)
    # DROP não envia resposta, evitando revelar que o filtro existe
    iptables -A INPUT -p udp --dport "${PORTA_JOGO}" -j DROP
    log "✓ Excesso de pacotes UDP será descartado silenciosamente (DROP)."

    # ---- 5. Controle de acesso ao RCON (TCP) ----
    if [[ -n "${ADMIN_IP}" ]]; then
        # Permite RCON apenas do IP administrativo
        iptables -A INPUT -p tcp --dport "${PORTA_JOGO}" -s "${ADMIN_IP}" -j ACCEPT
        log "✓ RCON (TCP) permitido apenas para: ${ADMIN_IP}"
    else
        log "⚠️  Nenhum ADMIN_IP configurado."
    fi

    # Bloqueia RCON de todos os outros IPs
    iptables -A INPUT -p tcp --dport "${PORTA_JOGO}" -j DROP
    log "✓ RCON bloqueado para todos os IPs não autorizados."

    # ---- 6. Proteção contra SYN flood na porta TCP ----
    # Limita a criação de novas conexões TCP para evitar SYN flood
    iptables -A INPUT \
        -p tcp \
        --syn \
        --dport "${PORTA_JOGO}" \
        -m limit \
        --limit 10/s \
        --limit-burst 20 \
        -j ACCEPT
    log "✓ Proteção SYN flood configurada."

    # ---- 7. Bloquear pacotes ICMP de ping em excesso ----
    # Permite ping normal mas limita para evitar ping floods
    iptables -A INPUT \
        -p icmp \
        --icmp-type echo-request \
        -m limit \
        --limit 1/s \
        --limit-burst 10 \
        -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    log "✓ Rate limiting de ICMP (ping) configurado."

    log ""
    log "=== Hardening aplicado com sucesso! ==="
    log "Porta do jogo : ${PORTA_JOGO}/UDP (com rate limiting)"
    log "RCON          : ${PORTA_JOGO}/TCP (restrito${ADMIN_IP:+ a ${ADMIN_IP}})"
    log ""
    log "LEMBRE-SE:"
    log "  - Estas regras não são persistentes após reboot."
    log "  - Para persistir: apt install iptables-persistent && netfilter-persistent save"
    log "  - Teste sempre antes de aplicar em produção."
}

# ---- Salvar regras para persistência ----
salvar_regras() {
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save
        log "✓ Regras salvas com netfilter-persistent."
    elif command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4
        log "✓ Regras salvas em /etc/iptables/rules.v4"
    else
        log "⚠️  Instale 'iptables-persistent' para persistir as regras após reboot:"
        log "   apt install iptables-persistent"
    fi
}

# ---- Exibir regras atuais ----
exibir_regras() {
    echo ""
    echo "=== Regras iptables ativas ==="
    iptables -L INPUT -v -n --line-numbers
}

# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------
main() {
    verificar_root
    verificar_iptables
    aplicar_regras
    salvar_regras
    exibir_regras
}

main "$@"
