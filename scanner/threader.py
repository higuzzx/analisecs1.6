"""
scanner/threader.py
====================
Varredura paralela de faixas de IP usando pool de threads.

O uso de threads (ao invés de processos) é adequado aqui porque
a operação é I/O-bound — passamos a maior parte do tempo aguardando
respostas de rede, não processando CPU. Threads liberam o GIL durante
chamadas de socket bloqueantes, permitindo paralelismo real.

Arquitetura:
    - VarredorThreaded divide a lista de IPs em chunks
    - Cada thread processa seu chunk independentemente
    - Resultados são coletados thread-safe via Lock
    - Barra de progresso opcional via tqdm
"""

import threading
import logging
import ipaddress
import time
from typing import Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .core import consultar_servidor

logger = logging.getLogger(__name__)


class VarredorThreaded:
    """
    Varredor multi-thread para faixas de endereços IPv4.

    Usa ThreadPoolExecutor para gerenciamento eficiente do pool de workers.
    Inclui rate limiting opcional para varreduras éticas e controladas.

    Args:
        max_threads (int):   Número máximo de threads paralelas. Padrão: 50.
        porta       (int):   Porta UDP a consultar. Padrão: 27015.
        timeout     (float): Timeout por servidor em segundos. Padrão: 2.0.
        rate_limit  (float): Requisições por segundo (0 = sem limite). Padrão: 0.
        callback    (callable): Função chamada a cada servidor encontrado.
    """

    def __init__(
        self,
        max_threads: int = 50,
        porta: int = 27015,
        timeout: float = 2.0,
        rate_limit: float = 0.0,
        callback: Optional[Callable[[dict], None]] = None,
    ):
        self.max_threads = max_threads
        self.porta = porta
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.callback = callback or self._callback_padrao

        # Estado interno (thread-safe via Lock)
        self._resultados: list[dict] = []
        self._lock = threading.Lock()
        self._total_consultados = 0
        self._total_encontrados = 0
        self._inicio: float = 0.0

    # -----------------------------------------------------------------------
    # Interface pública
    # -----------------------------------------------------------------------

    def varrer_cidr(self, cidr: str) -> list[dict]:
        """
        Varre todos os IPs em uma faixa CIDR.

        Args:
            cidr (str): Notação CIDR, ex: "200.100.0.0/24"

        Returns:
            list[dict]: Lista de servidores encontrados com seus metadados.

        Exemplo:
            >>> varredor = VarredorThreaded(max_threads=100)
            >>> servidores = varredor.varrer_cidr("10.0.0.0/24")
            >>> print(f"Encontrados: {len(servidores)}")
        """
        try:
            rede = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError as e:
            raise ValueError(f"CIDR inválido: '{cidr}' — {e}")

        ips = [str(ip) for ip in rede.hosts()]
        logger.info(f"[*] Iniciando varredura de {cidr} ({len(ips)} hosts) com {self.max_threads} threads")
        return self.varrer_lista(ips)

    def varrer_lista(self, ips: list[str]) -> list[dict]:
        """
        Varre uma lista arbitrária de endereços IP.

        Args:
            ips (list[str]): Lista de endereços IPv4 como strings.

        Returns:
            list[dict]: Servidores que responderam com seus metadados.
        """
        self._resultados = []
        self._total_consultados = 0
        self._total_encontrados = 0
        self._inicio = time.time()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submete todas as tarefas ao pool
            futures = {
                executor.submit(self._consultar_com_rate_limit, ip): ip
                for ip in ips
            }

            # Processa resultados conforme ficam prontos
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    resultado = future.result()
                    with self._lock:
                        self._total_consultados += 1
                        if resultado:
                            self._resultados.append(resultado)
                            self._total_encontrados += 1
                            self.callback(resultado)
                except Exception as e:
                    logger.debug(f"[!] Exceção ao processar {ip}: {e}")

        self._imprimir_resumo()
        return list(self._resultados)

    # -----------------------------------------------------------------------
    # Métodos internos
    # -----------------------------------------------------------------------

    def _consultar_com_rate_limit(self, ip: str) -> Optional[dict]:
        """
        Consulta um IP aplicando rate limiting se configurado.

        O rate limiting é importante para varreduras éticas:
        - Evita saturar links de rede
        - Reduz o impacto nos servidores consultados
        - Torna a varredura menos detectável como comportamento anômalo
        """
        if self.rate_limit > 0:
            # Pausa mínima entre requisições da mesma thread
            time.sleep(1.0 / self.rate_limit)

        return consultar_servidor(ip, self.porta)

    def _callback_padrao(self, servidor: dict) -> None:
        """Callback padrão: imprime no stdout formatado."""
        ip       = servidor.get("ip", "?")
        nome     = servidor.get("nome_servidor", "?")
        mapa     = servidor.get("mapa_atual", "?")
        players  = servidor.get("jogadores", 0)
        max_pl   = servidor.get("max_jogadores", 0)
        vac      = "✓ VAC" if servidor.get("vac_ativo") else "✗ SEM VAC"
        protocolo = servidor.get("protocolo", "?")

        print(
            f"  [+] {ip:<18} | {protocolo:<11} | "
            f"{players:>2}/{max_pl:<2} jogadores | "
            f"{vac} | "
            f"Mapa: {mapa:<20} | "
            f"{nome}"
        )

    def _imprimir_resumo(self) -> None:
        """Imprime estatísticas da varredura ao final."""
        elapsed = time.time() - self._inicio
        taxa = self._total_consultados / elapsed if elapsed > 0 else 0
        print(
            f"\n{'='*60}\n"
            f"  Varredura concluída em {elapsed:.1f}s\n"
            f"  IPs consultados : {self._total_consultados}\n"
            f"  Servidores ativos: {self._total_encontrados}\n"
            f"  Taxa média       : {taxa:.0f} req/s\n"
            f"{'='*60}"
        )

    # -----------------------------------------------------------------------
    # Propriedades de acesso ao estado
    # -----------------------------------------------------------------------

    @property
    def resultados(self) -> list[dict]:
        """Lista de servidores encontrados na última varredura."""
        return list(self._resultados)

    @property
    def estatisticas(self) -> dict:
        """Estatísticas da última varredura executada."""
        return {
            "total_consultados": self._total_consultados,
            "total_encontrados": self._total_encontrados,
            "taxa_resposta": (
                self._total_encontrados / self._total_consultados
                if self._total_consultados > 0 else 0
            ),
        }
