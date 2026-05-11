# =============================================================================
# Dockerfile — CS 1.6 Network Audit & Exposure Scanner
# =============================================================================
# Imagem isolada para execução segura do scanner.
#
# O isolamento em container garante:
#   - Ambiente reproduzível em qualquer máquina
#   - Sem instalação de dependências no sistema host
#   - Fácil descarte após uso (rm após execução)
#   - Controle explícito de permissões de rede
#
# Build : docker build -t cs16-auditor .
# Run   : docker run --rm -v $(pwd)/output:/app/output cs16-auditor --help
# =============================================================================

# Imagem base minimalista — Alpine reduz superfície de ataque da imagem
FROM python:3.11-alpine

# Metadados da imagem
LABEL maintainer="Higor Samuel <higor.rodrigues@unimontes.br>"
LABEL description="CS 1.6 GoldSource Network Audit Scanner — Uso educativo"
LABEL version="1.0.0"

# ---------------------------------------------------------------------------
# Variáveis de ambiente
# ---------------------------------------------------------------------------
ENV PYTHONDONTWRITEBYTECODE=1   \
    PYTHONUNBUFFERED=1          \
    PYTHONFAULTHANDLER=1        \
    # Diretório de trabalho dentro do container
    APP_DIR=/app                \
    # Diretório de saída dos relatórios (mount point externo)
    OUTPUT_DIR=/app/output

# ---------------------------------------------------------------------------
# Usuário não-root para execução segura
# ---------------------------------------------------------------------------
# Nunca execute containers como root sem necessidade explícita
RUN addgroup -S auditor && adduser -S auditor -G auditor

# ---------------------------------------------------------------------------
# Dependências do sistema (mínimas)
# ---------------------------------------------------------------------------
RUN apk add --no-cache \
    # Necessário para algumas operações de rede no Alpine
    iputils \
    # Para debug de rede dentro do container (opcional, pode remover em prod)
    bind-tools

# ---------------------------------------------------------------------------
# Dependências Python
# ---------------------------------------------------------------------------
WORKDIR ${APP_DIR}

# Copiar requirements primeiro para aproveitar cache de layers do Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Código da aplicação
# ---------------------------------------------------------------------------
COPY --chown=auditor:auditor . .

# Criar diretório de output com permissões corretas
RUN mkdir -p ${OUTPUT_DIR} && chown auditor:auditor ${OUTPUT_DIR}

# ---------------------------------------------------------------------------
# Trocar para usuário não-root
# ---------------------------------------------------------------------------
USER auditor

# Volume para persistir relatórios fora do container
VOLUME ["/app/output"]

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
ENTRYPOINT ["python", "-m", "scanner"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# Exemplo de uso:
#
#   # Varrer uma faixa CIDR
#   docker run --rm \
#     -v $(pwd)/output:/app/output \
#     cs16-auditor \
#     --cidr "200.100.0.0/24" \
#     --output /app/output/auditoria.json \
#     --threads 50
#
#   # Consultar um servidor específico
#   docker run --rm cs16-auditor \
#     --ip 192.168.1.10 --porta 27015
# ---------------------------------------------------------------------------
