"""
analysis/risk_score.py
=======================
Classificação automática de risco para servidores GoldSource auditados.

O modelo de risco é baseado em três fatores públicos e observáveis:
    1. Configuração de segurança (VAC, senha, tipo de servidor)
    2. Exposição do protocolo (porta padrão, amplificação UDP)
    3. Estado de atualização (versão do protocolo)

Nenhum dado privado é coletado — apenas os metadados que o servidor
já expõe publicamente via A2S_INFO são utilizados na classificação.

Escala de risco:
    CRÍTICO  (score >= 70): Múltiplos vetores de ataque conhecidos
    ALTO     (score >= 50): Pelo menos um vetor relevante sem mitigação
    MÉDIO    (score >= 30): Configuração sub-ótima, risco limitado
    BAIXO    (score  < 30): Boa postura de segurança observável
"""

import logging
from dataclasses import dataclass, field
from typing import Literal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tipos e constantes
# ---------------------------------------------------------------------------

NivelRisco = Literal["CRÍTICO", "ALTO", "MÉDIO", "BAIXO"]

# Versão mais recente conhecida do protocolo GoldSource
VERSAO_PROTOCOLO_ATUAL = 48

# Build mínima considerada "atual" (builds abaixo são sinalizadas)
BUILD_MINIMA_SEGURA = 8000  # Aprox. 2013 em diante com patches de segurança

# Pesos dos fatores de risco (somam até 100 no pior caso)
PESO_SEM_VAC          = 20  # VAC desabilitado — sem proteção anti-cheat/anti-exploit
PESO_SEM_SENHA        = 15  # Servidor aberto — qualquer um pode conectar
PESO_PROTOCOLO_ANTIGO = 20  # Versão de protocolo antiga — CVEs conhecidos
PESO_PORTA_PADRAO     = 15  # Porta 27015 — alvo de varreduras automatizadas
PESO_SERVIDOR_LOCAL   = 10  # Servidor tipo "Local" — não deveria ser público
PESO_LINUX_EXPOSTO    = 10  # Linux sem evidência de hardening (inferência)
PESO_AMPLIFICACAO     = 10  # Potencial amplificador UDP (sempre presente em GoldSource)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AlertaRisco:
    """Um alerta de segurança identificado durante a análise."""
    codigo: str
    nivel: NivelRisco
    descricao: str
    recomendacao: str


@dataclass
class ResultadoRisco:
    """Resultado completo da análise de risco de um servidor."""
    ip: str
    porta: int
    nome_servidor: str
    score: int
    nivel: NivelRisco
    alertas: list[AlertaRisco] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "porta": self.porta,
            "nome_servidor": self.nome_servidor,
            "score_risco": self.score,
            "nivel_risco": self.nivel,
            "alertas": [
                {
                    "codigo": a.codigo,
                    "nivel": a.nivel,
                    "descricao": a.descricao,
                    "recomendacao": a.recomendacao,
                }
                for a in self.alertas
            ],
        }


# ---------------------------------------------------------------------------
# Motor de análise de risco
# ---------------------------------------------------------------------------

class AnalisadorRisco:
    """
    Analisa os metadados públicos de um servidor GoldSource e produz
    uma classificação de risco com alertas detalhados e recomendações.

    Todos os dados utilizados são obtidos exclusivamente via A2S_INFO —
    consulta pública, sem autenticação, sem acesso privilegiado.
    """

    def analisar(self, servidor: dict) -> ResultadoRisco:
        """
        Executa a análise de risco completa em um servidor.

        Args:
            servidor (dict): Metadados do servidor retornados pelo scanner.

        Returns:
            ResultadoRisco: Resultado com score, nível e lista de alertas.
        """
        ip    = servidor.get("ip", "desconhecido")
        porta = servidor.get("porta", 27015)
        nome  = servidor.get("nome_servidor", "Sem nome")

        score   = 0
        alertas = []

        # ---- Fator 1: VAC ----
        if not servidor.get("vac_ativo", False):
            score += PESO_SEM_VAC
            alertas.append(AlertaRisco(
                codigo="VAC_DISABLED",
                nivel="ALTO",
                descricao="Valve Anti-Cheat (VAC) está desabilitado.",
                recomendacao=(
                    "Habilite o VAC no server.cfg com 'sv_secure 1'. "
                    "Além de proteção anti-cheat, o VAC também filtra alguns "
                    "exploits conhecidos do motor GoldSource."
                ),
            ))

        # ---- Fator 2: Senha ----
        if not servidor.get("requer_senha", False):
            score += PESO_SEM_SENHA
            alertas.append(AlertaRisco(
                codigo="NO_PASSWORD",
                nivel="MÉDIO",
                descricao="Servidor público sem senha de acesso.",
                recomendacao=(
                    "Para servidores privados ou de treinamento, configure "
                    "'sv_password <senha>' no server.cfg. "
                    "Para servidores públicos, este comportamento é esperado."
                ),
            ))

        # ---- Fator 3: Versão do protocolo ----
        versao = servidor.get("versao_protocolo", 0)
        if versao < VERSAO_PROTOCOLO_ATUAL:
            score += PESO_PROTOCOLO_ANTIGO
            alertas.append(AlertaRisco(
                codigo="OUTDATED_PROTOCOL",
                nivel="CRÍTICO",
                descricao=(
                    f"Protocolo versão {versao} (atual: {VERSAO_PROTOCOLO_ATUAL}). "
                    f"Versões antigas do GoldSource contêm vulnerabilidades de "
                    f"execução remota via pacotes UDP malformados."
                ),
                recomendacao=(
                    "Atualize o servidor para a versão mais recente do HLDS. "
                    "Verifique o SteamCMD: 'app_update 90 validate'. "
                    "Builds antigas (< 8684) têm CVEs conhecidos documentados."
                ),
            ))

        # ---- Fator 4: Porta padrão ----
        if porta == 27015:
            score += PESO_PORTA_PADRAO
            alertas.append(AlertaRisco(
                codigo="DEFAULT_PORT",
                nivel="MÉDIO",
                descricao=(
                    "Servidor na porta padrão 27015. "
                    "Varreduras automatizadas como esta priorizam portas padrão, "
                    "aumentando a superfície de exposição."
                ),
                recomendacao=(
                    "Considere mover para uma porta não-padrão "
                    "(ex: 28015, 27116) com '+port XXXX' na linha de inicialização. "
                    "Segurança por obscuridade não é suficiente, mas reduz ruído."
                ),
            ))

        # ---- Fator 5: Tipo de servidor local ----
        tipo = servidor.get("tipo_servidor", "")
        if "Local" in tipo:
            score += PESO_SERVIDOR_LOCAL
            alertas.append(AlertaRisco(
                codigo="LOCAL_SERVER_EXPOSED",
                nivel="ALTO",
                descricao=(
                    "Servidor do tipo 'Local (Listen)' exposto publicamente. "
                    "Servidores listen são projetados para uso interno/LAN "
                    "e têm controles de segurança reduzidos em comparação "
                    "com servidores dedicados."
                ),
                recomendacao=(
                    "Use '-dedicated' na linha de inicialização para rodar como "
                    "servidor dedicado. Nunca exponha servidores listen à internet."
                ),
            ))

        # ---- Fator 6: Amplificação UDP (universal para GoldSource) ----
        # Todo servidor GoldSource sem rate limiting é um potencial amplificador.
        # Adicionamos este alerta sempre, pois é inerente ao protocolo.
        score += PESO_AMPLIFICACAO
        alertas.append(AlertaRisco(
            codigo="UDP_AMPLIFICATION_RISK",
            nivel="ALTO",
            descricao=(
                "O protocolo A2S/GoldSource é inerentemente vulnerável a "
                "amplificação UDP. Um atacante pode spoofar o IP de origem "
                "e direcionar a resposta (fator ~14x) a uma vítima, "
                "tornando este servidor um vetor involuntário de DDoS."
            ),
            recomendacao=(
                "Configure rate limiting no iptables:\n"
                "  iptables -A INPUT -p udp --dport 27015 \\\n"
                "    -m hashlimit --hashlimit-upto 20/sec \\\n"
                "    --hashlimit-burst 50 --hashlimit-mode srcip \\\n"
                "    --hashlimit-name cs16 -j ACCEPT\n"
                "  iptables -A INPUT -p udp --dport 27015 -j DROP"
            ),
        ))

        # ---- Classificação final ----
        nivel = self._score_para_nivel(score)

        logger.debug(f"Análise de {ip}:{porta} — score={score}, nível={nivel}, alertas={len(alertas)}")

        return ResultadoRisco(
            ip=ip,
            porta=porta,
            nome_servidor=nome,
            score=score,
            nivel=nivel,
            alertas=alertas,
        )

    @staticmethod
    def _score_para_nivel(score: int) -> NivelRisco:
        """Converte score numérico em nível categórico de risco."""
        if score >= 70:
            return "CRÍTICO"
        elif score >= 50:
            return "ALTO"
        elif score >= 30:
            return "MÉDIO"
        else:
            return "BAIXO"


# ---------------------------------------------------------------------------
# Função de conveniência
# ---------------------------------------------------------------------------

def calcular_risco(servidor: dict) -> ResultadoRisco:
    """
    Atalho para análise de risco sem instanciar o AnalisadorRisco diretamente.

    Args:
        servidor (dict): Metadados do servidor.

    Returns:
        ResultadoRisco: Resultado da análise.
    """
    return AnalisadorRisco().analisar(servidor)
