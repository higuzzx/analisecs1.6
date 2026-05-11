"""
scanner/parser.py
=================
Deserialização do payload binário da resposta A2S_INFO.

O protocolo GoldSource usa campos de tamanho variável (strings null-terminated)
intercalados com campos de tamanho fixo (bytes, shorts, longs).

Estrutura da resposta A2S_INFO (GoldSource):
    Offset  Tipo        Campo
    ------  --------    -----
    0-3     byte[4]     Header: FF FF FF FF
    4       byte        Tipo resposta: 0x6D ('m') para GoldSource
    5       string      Endereço IP:porta do servidor
    +       string      Nome do servidor (hostname)
    +       string      Mapa atual
    +       string      Pasta do jogo (mod folder)
    +       string      Nome do jogo
    +       short       Steam App ID
    +       byte        Número de jogadores
    +       byte        Máximo de jogadores
    +       byte        Número de bots
    +       byte        Tipo do servidor (d/l/p)
    +       byte        Sistema operacional (l/w/m)
    +       byte        Requer senha (0/1)
    +       byte        VAC ativo (0/1)
    +       string      Versão do servidor

Referência: https://developer.valvesoftware.com/wiki/Server_queries#A2S_INFO
"""

import struct
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Mapeamentos de bytes para valores legíveis
TIPO_SERVIDOR = {
    ord('d'): "Dedicado",
    ord('l'): "Local (Listen)",
    ord('p'): "Proxy (HLTV/SourceTV)",
}

SISTEMA_OPERACIONAL = {
    ord('l'): "Linux",
    ord('w'): "Windows",
    ord('m'): "macOS",
}


class PayloadParser:
    """
    Parser sequencial para payloads binários com campos de tamanho variável.

    Mantém um cursor interno (offset) que avança conforme os campos são lidos.
    Todos os métodos de leitura são destrutivos — avançam o cursor.
    """

    def __init__(self, dados: bytes):
        self._dados = dados
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def restante(self) -> int:
        return len(self._dados) - self._offset

    def ler_bytes_raw(self, n: int) -> bytes:
        """Lê n bytes sem interpretação."""
        if self._offset + n > len(self._dados):
            raise IndexError(
                f"Tentativa de ler {n} bytes no offset {self._offset}, "
                f"mas payload tem apenas {len(self._dados)} bytes."
            )
        valor = self._dados[self._offset:self._offset + n]
        self._offset += n
        return valor

    def ler_byte(self) -> int:
        """Lê 1 byte sem sinal (uint8, 0–255)."""
        return self.ler_bytes_raw(1)[0]

    def ler_short(self) -> int:
        """Lê 2 bytes como short com sinal (little-endian, int16)."""
        return struct.unpack_from('<h', self.ler_bytes_raw(2))[0]

    def ler_ushort(self) -> int:
        """Lê 2 bytes como short sem sinal (little-endian, uint16)."""
        return struct.unpack_from('<H', self.ler_bytes_raw(2))[0]

    def ler_string(self, encoding: str = 'utf-8') -> str:
        """
        Lê uma string ASCII/UTF-8 terminada em byte nulo (\\x00).

        Args:
            encoding: Encoding a usar na decodificação (padrão: utf-8).

        Returns:
            String decodificada sem o byte nulo terminador.
        """
        try:
            # Encontra o próximo byte nulo a partir da posição atual
            fim = self._dados.index(b'\x00', self._offset)
        except ValueError:
            # Sem byte nulo — lê até o final do payload (tolerância a erros)
            fim = len(self._dados)

        raw = self._dados[self._offset:fim]
        self._offset = fim + 1  # Pula o byte nulo

        return raw.decode(encoding, errors='replace')

    def pular(self, n: int) -> None:
        """Avança o cursor sem ler os dados."""
        self._offset += n


# ---------------------------------------------------------------------------
# Função pública de parsing
# ---------------------------------------------------------------------------

def parsear_resposta(payload: bytes) -> dict:
    """
    Deserializa o payload binário bruto de uma resposta A2S_INFO.

    Suporta tanto o formato Source (0x49) quanto o GoldSource legado (0x6D).
    O CS 1.6 usa o formato GoldSource na maioria das builds antigas.

    Args:
        payload (bytes): Bytes brutos recebidos do socket UDP.

    Returns:
        dict: Dicionário com todos os campos públicos do servidor.

    Raises:
        ValueError: Se o payload não for reconhecido como A2S_INFO.
    """
    parser = PayloadParser(payload)

    # ---- Validação do header (4 bytes FF FF FF FF) ----
    header = parser.ler_bytes_raw(4)
    if header != b'\xFF\xFF\xFF\xFF':
        raise ValueError(f"Header inválido: {header.hex()} (esperado: ffffffff)")

    # ---- Tipo de resposta ----
    tipo_resposta = parser.ler_byte()

    # 0x6D = 'm' → GoldSource (CS 1.6, HL1)
    # 0x49 = 'I' → Source Engine (CS:S, CS:GO, etc.)
    if tipo_resposta == 0x6D:
        return _parsear_goldsource(parser)
    elif tipo_resposta == 0x49:
        return _parsear_source(parser)
    else:
        raise ValueError(
            f"Tipo de resposta desconhecido: 0x{tipo_resposta:02X}. "
            f"Este scanner suporta apenas A2S_INFO GoldSource (0x6D) e Source (0x49)."
        )


def _parsear_goldsource(parser: PayloadParser) -> dict:
    """
    Parsing do formato A2S_INFO legado GoldSource (CS 1.6, Half-Life).

    No GoldSource, o primeiro campo após o tipo é o endereço IP:porta
    do próprio servidor — uma peculiaridade do protocolo legado.
    """
    try:
        # Campo exclusivo do GoldSource: IP:porta do servidor
        endereco_servidor = parser.ler_string()

        # Metadados públicos do servidor
        nome_servidor  = parser.ler_string()
        mapa_atual     = parser.ler_string()
        pasta_jogo     = parser.ler_string()
        nome_jogo      = parser.ler_string()

        # Dados numéricos
        jogadores      = parser.ler_byte()
        max_jogadores  = parser.ler_byte()
        versao_proto   = parser.ler_byte()   # Versão do protocolo (geralmente 47 ou 48)
        dedicado_byte  = parser.ler_byte()
        os_byte        = parser.ler_byte()
        requer_senha   = bool(parser.ler_byte())
        is_mod         = bool(parser.ler_byte())

        # Se o servidor rodar um mod, há campos extras antes do VAC
        if is_mod:
            _pular_campos_mod(parser)

        vac_ativo      = bool(parser.ler_byte())
        bots           = parser.ler_byte() if parser.restante >= 1 else 0

        return {
            # Identificação
            "protocolo":       "GoldSource",
            "endereco_server": endereco_servidor,

            # Informações visíveis na lista de servidores
            "nome_servidor":   nome_servidor,
            "mapa_atual":      mapa_atual,
            "pasta_jogo":      pasta_jogo,
            "nome_jogo":       nome_jogo,

            # Capacidade e população
            "jogadores":       jogadores,
            "max_jogadores":   max_jogadores,
            "bots":            bots,

            # Infraestrutura — dados relevantes para análise de risco
            "versao_protocolo": versao_proto,
            "tipo_servidor":   TIPO_SERVIDOR.get(dedicado_byte, f"Desconhecido (0x{dedicado_byte:02X})"),
            "sistema_op":      SISTEMA_OPERACIONAL.get(os_byte, f"Desconhecido (0x{os_byte:02X})"),
            "requer_senha":    requer_senha,
            "vac_ativo":       vac_ativo,
            "is_mod":          is_mod,
        }

    except (IndexError, ValueError) as e:
        logger.warning(f"Erro no parsing GoldSource: {e}")
        # Retorna o que foi parseado até o erro — melhor do que None
        raise


def _parsear_source(parser: PayloadParser) -> dict:
    """
    Parsing do formato A2S_INFO Source Engine (CS:S, TF2, CS:GO legado).
    Incluído para compatibilidade, embora o foco do projeto seja CS 1.6.
    """
    try:
        versao_proto  = parser.ler_byte()
        nome_servidor = parser.ler_string()
        mapa_atual    = parser.ler_string()
        pasta_jogo    = parser.ler_string()
        nome_jogo     = parser.ler_string()
        app_id        = parser.ler_ushort()
        jogadores     = parser.ler_byte()
        max_jogadores = parser.ler_byte()
        bots          = parser.ler_byte()
        dedicado_byte = parser.ler_byte()
        os_byte       = parser.ler_byte()
        requer_senha  = bool(parser.ler_byte())
        vac_ativo     = bool(parser.ler_byte())
        versao_game   = parser.ler_string()

        return {
            "protocolo":        "Source",
            "versao_protocolo": versao_proto,
            "nome_servidor":    nome_servidor,
            "mapa_atual":       mapa_atual,
            "pasta_jogo":       pasta_jogo,
            "nome_jogo":        nome_jogo,
            "app_id":           app_id,
            "jogadores":        jogadores,
            "max_jogadores":    max_jogadores,
            "bots":             bots,
            "tipo_servidor":    TIPO_SERVIDOR.get(dedicado_byte, f"0x{dedicado_byte:02X}"),
            "sistema_op":       SISTEMA_OPERACIONAL.get(os_byte, f"0x{os_byte:02X}"),
            "requer_senha":     requer_senha,
            "vac_ativo":        vac_ativo,
            "versao_game":      versao_game,
        }

    except (IndexError, ValueError) as e:
        logger.warning(f"Erro no parsing Source Engine: {e}")
        raise


def _pular_campos_mod(parser: PayloadParser) -> None:
    """
    Pula os campos extras presentes em respostas de servidores que rodam mods.

    Quando is_mod=1, o GoldSource inclui campos adicionais sobre o mod
    antes do campo VAC. Precisamos pulá-los para manter o offset correto.
    """
    parser.ler_string()  # URL do mod
    parser.ler_string()  # Diretório do mod
    parser.ler_string()  # Descrição do mod
    parser.ler_ushort()  # Versão do mod
    parser.ler_bytes_raw(4)  # Tamanho do mod (long)
    parser.ler_byte()    # Multiplayer only (0/1)
    parser.ler_byte()    # Custom DLL (0/1)
