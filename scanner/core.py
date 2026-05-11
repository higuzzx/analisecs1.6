"""
scanner/core.py
===============
Núcleo do scanner — consulta pública A2S_INFO via protocolo GoldSource (UDP).

Referência do protocolo:
    https://developer.valvesoftware.com/wiki/Server_queries

NOTA ÉTICA:
    Este módulo realiza apenas consultas de leitura (read-only queries).
    O pacote A2S_INFO é idêntico ao que qualquer cliente CS 1.6 envia
    ao navegar na lista de servidores. Não há autenticação, exploração
    ou envio de payloads maliciosos de nenhum tipo.
"""

import socket
import logging
from typing import Optional

from .parser import parsear_resposta

# ---------------------------------------------------------------------------
# Constantes do protocolo
# ---------------------------------------------------------------------------

# Payload A2S_INFO — definido pela Valve (público e documentado)
# Estrutura: [FF FF FF FF] header + [54] tipo 'T' + string terminada em \x00
A2S_INFO_PAYLOAD = (
    b'\xFF\xFF\xFF\xFF'          # Prefixo de 4 bytes — identifica pacote GoldSource/Source
    b'\x54'                      # Byte de tipo: 0x54 = 'T' → A2S_INFO request
    b'Source Engine Query\x00'   # String de identificação (null-terminated)
)

# Porta padrão do GoldSource Engine (CS 1.6, Half-Life, etc.)
PORTA_PADRAO = 27015

# Timeout em segundos — evita bloqueio indefinido em IPs que não respondem
TIMEOUT_SEGUNDOS = 2.0

# Tamanho máximo do buffer de recepção (bytes)
BUFFER_SIZE = 4096

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Função principal de consulta
# ---------------------------------------------------------------------------

def consultar_servidor(ip: str, porta: int = PORTA_PADRAO) -> Optional[dict]:
    """
    Envia um pacote A2S_INFO a um servidor GoldSource e retorna os metadados.

    O servidor responde com informações públicas que ele próprio anuncia
    para qualquer cliente na rede — nome, mapa, jogadores, versão, VAC, etc.

    Args:
        ip   (str): Endereço IPv4 do servidor alvo.
        porta (int): Porta UDP do servidor. Padrão: 27015.

    Returns:
        dict: Metadados públicos do servidor se responder.
        None: Se o servidor estiver offline, filtrado por firewall ou timeout.

    Exemplo:
        >>> dados = consultar_servidor("192.168.1.10")
        >>> if dados:
        ...     print(dados["nome_servidor"], dados["mapa_atual"])
    """
    sock = None
    try:
        # Cria socket UDP (AF_INET = IPv4, SOCK_DGRAM = UDP)
        # UDP é stateless — não há handshake TCP, apenas envio/recepção
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT_SEGUNDOS)

        # Envia o payload de consulta pública ao servidor
        sock.sendto(A2S_INFO_PAYLOAD, (ip, porta))
        logger.debug(f"[>] A2S_INFO enviado para {ip}:{porta}")

        # Aguarda a resposta — bloqueia até receber dados ou timeout
        dados_brutos, endereco_origem = sock.recvfrom(BUFFER_SIZE)
        logger.debug(f"[<] Resposta recebida de {endereco_origem} ({len(dados_brutos)} bytes)")

        # Deserializa o payload binário em dicionário Python
        resultado = parsear_resposta(dados_brutos)
        resultado["ip"] = ip
        resultado["porta"] = porta
        return resultado

    except socket.timeout:
        # Servidor não respondeu dentro do timeout — offline ou filtrado
        logger.debug(f"[!] Timeout: {ip}:{porta} não respondeu em {TIMEOUT_SEGUNDOS}s")
        return None

    except ConnectionRefusedError:
        # Porta UDP fechada (ICMP Port Unreachable recebido)
        logger.debug(f"[!] Conexão recusada: {ip}:{porta}")
        return None

    except OSError as e:
        # Erros de rede gerais (IP inválido, interface inativa, etc.)
        logger.debug(f"[!] Erro de rede em {ip}:{porta} — {e}")
        return None

    except Exception as e:
        # Erro de parsing ou outro inesperado — logar para investigação
        logger.warning(f"[!] Erro inesperado ao consultar {ip}:{porta} — {type(e).__name__}: {e}")
        return None

    finally:
        # Garantir que o socket seja sempre fechado, mesmo em caso de erro
        if sock:
            sock.close()


def verificar_conectividade(ip: str, porta: int = PORTA_PADRAO) -> bool:
    """
    Verificação rápida de conectividade — apenas checa se o servidor responde.
    Útil para pré-filtrar IPs antes de uma consulta completa.

    Args:
        ip   (str): Endereço IPv4.
        porta (int): Porta UDP.

    Returns:
        bool: True se o servidor respondeu, False caso contrário.
    """
    return consultar_servidor(ip, porta) is not None
