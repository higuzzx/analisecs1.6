"""
scanner/__main__.py
====================
Ponto de entrada da CLI — permite execução com: python -m scanner [args]

Uso básico:
    python -m scanner --ip 192.168.1.10
    python -m scanner --cidr 200.100.0.0/24 --threads 50
    python -m scanner --cidr 200.100.0.0/24 --output relatorio.json --html relatorio.html
"""

import logging
import sys
import json
from pathlib import Path

import click

from .core import consultar_servidor
from .threader import VarredorThreaded
from analysis.reporter import GeradorRelatorio

# ---------------------------------------------------------------------------
# Configuração de logging
# ---------------------------------------------------------------------------

def configurar_log(nivel: str) -> None:
    logging.basicConfig(
        level=getattr(logging, nivel.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# CLI com Click
# ---------------------------------------------------------------------------

@click.command()
@click.option("--ip",       default=None,   help="IP único a consultar (ex: 192.168.1.10).")
@click.option("--porta",    default=27015,  show_default=True, help="Porta UDP do servidor.")
@click.option("--cidr",     default=None,   help="Faixa CIDR a varrer (ex: 200.100.0.0/24).")
@click.option("--threads",  default=50,     show_default=True, help="Número de threads paralelas.")
@click.option("--timeout",  default=2.0,    show_default=True, help="Timeout por servidor (segundos).")
@click.option("--output",   default=None,   help="Salvar resultados em JSON (ex: output/auditoria.json).")
@click.option("--html",     default=None,   help="Salvar relatório HTML (ex: output/relatorio.html).")
@click.option("--log-level",default="INFO", show_default=True,
              type=click.Choice(["DEBUG","INFO","WARNING","ERROR"], case_sensitive=False),
              help="Nível de log.")
def main(ip, porta, cidr, threads, timeout, output, html, log_level):
    """
    \b
    🔍 CS 1.6 Network Audit & Exposure Scanner
    Auditoria ética de servidores GoldSource via protocolo A2S_INFO.

    \b
    ⚖️  USO ÉTICO: Apenas consultas públicas. Sem força bruta. Sem invasão.
        Respeite a Lei nº 12.737/2012 e o Marco Civil da Internet.

    \b
    Exemplos:
        python -m scanner --ip 192.168.1.10
        python -m scanner --cidr 200.100.0.0/24 --threads 100
        python -m scanner --cidr 200.100.0.0/24 --output output/resultado.json --html output/relatorio.html
    """
    configurar_log(log_level)
    logger = logging.getLogger("scanner.cli")

    # ---- Validação de argumentos ----
    if not ip and not cidr:
        click.echo("❌ Informe --ip ou --cidr. Use --help para ver as opções.", err=True)
        sys.exit(1)

    if ip and cidr:
        click.echo("❌ Use --ip OU --cidr, não ambos.", err=True)
        sys.exit(1)

    servidores_encontrados = []

    # ---- Modo: IP único ----
    if ip:
        click.echo(f"\n🔍 Consultando {ip}:{porta}...")
        resultado = consultar_servidor(ip, porta)

        if resultado:
            click.echo(f"\n✅ Servidor encontrado!\n")
            for chave, valor in resultado.items():
                click.echo(f"   {chave:<20}: {valor}")
            servidores_encontrados = [resultado]
        else:
            click.echo(f"❌ Nenhuma resposta de {ip}:{porta} (offline, filtrado ou porta errada).")
            sys.exit(0)

    # ---- Modo: Varredura CIDR ----
    elif cidr:
        click.echo(f"\n🔍 Iniciando varredura de {cidr}")
        click.echo(f"   Threads  : {threads}")
        click.echo(f"   Porta    : {porta}/UDP")
        click.echo(f"   Timeout  : {timeout}s por host")
        click.echo(f"\n{'─'*60}")

        varredor = VarredorThreaded(
            max_threads=threads,
            porta=porta,
            timeout=timeout,
        )

        servidores_encontrados = varredor.varrer_cidr(cidr)

    # ---- Geração de relatórios ----
    if servidores_encontrados:
        metadados = {
            "cidr_varrido": cidr or f"{ip}/32",
            "threads_usadas": threads,
            "timeout_segundos": timeout,
        }

        gerador = GeradorRelatorio(servidores_encontrados, metadados)
        gerador.executar_analise()

        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            gerador.exportar_json(output)
            click.echo(f"\n📄 Relatório JSON salvo: {output}")

        if html:
            Path(html).parent.mkdir(parents=True, exist_ok=True)
            gerador.exportar_html(html, mascarar_ips=True)
            click.echo(f"🌐 Relatório HTML salvo: {html}")

        if not output and not html:
            # Sem arquivo de saída — imprime JSON resumido no stdout
            click.echo(f"\n{'─'*60}")
            click.echo(json.dumps(
                [{"ip": s.get("ip"), "nome": s.get("nome_servidor"), "mapa": s.get("mapa_atual")}
                 for s in servidores_encontrados],
                ensure_ascii=False, indent=2
            ))

    click.echo("\n✅ Auditoria concluída.")


if __name__ == "__main__":
    main()
