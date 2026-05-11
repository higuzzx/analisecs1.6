"""
analysis/reporter.py
=====================
Geração de relatórios de auditoria em formato JSON e HTML.

O relatório é o produto final da auditoria — apresenta os dados coletados
de forma estruturada, com análise de risco, estatísticas e recomendações.

PRIVACIDADE:
    IPs reais dos servidores auditados são mascarados por padrão no HTML
    (últimos dois octetos substituídos por 'xxx.xxx') para publicação ética.
    O JSON completo é salvo localmente para análise interna.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .risk_score import calcular_risco, ResultadoRisco

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Gerador de relatórios
# ---------------------------------------------------------------------------

class GeradorRelatorio:
    """
    Gera relatórios de auditoria a partir dos resultados da varredura.

    Fluxo:
        1. Recebe lista de servidores (dicts do scanner)
        2. Calcula risco para cada um
        3. Agrega estatísticas
        4. Exporta para JSON (completo) e HTML (mascarado para publicação)
    """

    def __init__(self, servidores: list[dict], metadados_varredura: Optional[dict] = None):
        """
        Args:
            servidores           (list[dict]): Servidores encontrados pelo scanner.
            metadados_varredura  (dict):       Info sobre a varredura (CIDR, data, etc.).
        """
        self.servidores = servidores
        self.metadados = metadados_varredura or {}
        self._analises: list[ResultadoRisco] = []
        self._analisado = False

    def executar_analise(self) -> "GeradorRelatorio":
        """Executa análise de risco em todos os servidores. Retorna self para chaining."""
        self._analises = [calcular_risco(s) for s in self.servidores]
        self._analisado = True
        logger.info(f"Análise de risco concluída para {len(self._analises)} servidores.")
        return self

    def exportar_json(self, caminho: str | Path) -> Path:
        """
        Exporta relatório completo (sem mascaramento) em JSON.

        Args:
            caminho: Caminho do arquivo de saída.

        Returns:
            Path: Caminho do arquivo gerado.
        """
        if not self._analisado:
            self.executar_analise()

        caminho = Path(caminho)
        caminho.parent.mkdir(parents=True, exist_ok=True)

        relatorio = self._construir_estrutura_json()

        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(relatorio, f, ensure_ascii=False, indent=2)

        logger.info(f"Relatório JSON salvo em: {caminho}")
        return caminho

    def exportar_html(self, caminho: str | Path, mascarar_ips: bool = True) -> Path:
        """
        Exporta relatório HTML formatado para publicação/documentação.

        Args:
            caminho      : Caminho do arquivo de saída.
            mascarar_ips : Se True, mascara os dois últimos octetos dos IPs.

        Returns:
            Path: Caminho do arquivo gerado.
        """
        if not self._analisado:
            self.executar_analise()

        caminho = Path(caminho)
        caminho.parent.mkdir(parents=True, exist_ok=True)

        html = self._construir_html(mascarar_ips)

        with open(caminho, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Relatório HTML salvo em: {caminho}")
        return caminho

    # -----------------------------------------------------------------------
    # Métodos internos
    # -----------------------------------------------------------------------

    def _construir_estrutura_json(self) -> dict:
        """Monta a estrutura completa do relatório JSON."""
        contagem_niveis = {"CRÍTICO": 0, "ALTO": 0, "MÉDIO": 0, "BAIXO": 0}
        for analise in self._analises:
            contagem_niveis[analise.nivel] += 1

        return {
            "auditoria": {
                "titulo": "CS 1.6 Network Audit & Exposure Scanner",
                "autor": "Higor Samuel — Unimontes / DTI",
                "data_geracao": datetime.now(timezone.utc).isoformat(),
                "finalidade": "Educativa e defensiva — Lei nº 12.737/2012 e Marco Civil da Internet",
                **self.metadados,
            },
            "resumo": {
                "total_servidores_auditados": len(self._analises),
                "distribuicao_risco": contagem_niveis,
                "score_medio": (
                    sum(a.score for a in self._analises) / len(self._analises)
                    if self._analises else 0
                ),
            },
            "servidores": [a.to_dict() for a in self._analises],
        }

    @staticmethod
    def _mascarar_ip(ip: str) -> str:
        """
        Mascara os dois últimos octetos de um IPv4.
        Ex: '200.100.50.25' → '200.100.xxx.xxx'
        """
        partes = ip.split(".")
        if len(partes) == 4:
            return f"{partes[0]}.{partes[1]}.xxx.xxx"
        return "xxx.xxx.xxx.xxx"

    def _construir_html(self, mascarar_ips: bool) -> str:
        """Monta o HTML do relatório de auditoria."""
        data_str = datetime.now().strftime("%d/%m/%Y às %H:%M")
        total = len(self._analises)

        contagem = {"CRÍTICO": 0, "ALTO": 0, "MÉDIO": 0, "BAIXO": 0}
        for a in self._analises:
            contagem[a.nivel] += 1

        cores_nivel = {
            "CRÍTICO": "#e74c3c",
            "ALTO":    "#e67e22",
            "MÉDIO":   "#f1c40f",
            "BAIXO":   "#2ecc71",
        }

        linhas_servidores = ""
        for analise in self._analises:
            ip_exibido = self._mascarar_ip(analise.ip) if mascarar_ips else analise.ip
            cor = cores_nivel.get(analise.nivel, "#999")
            alertas_html = "".join(
                f'<li><strong>[{a.codigo}]</strong> {a.descricao}</li>'
                for a in analise.alertas
            )
            linhas_servidores += f"""
            <tr>
                <td><code>{ip_exibido}:{analise.porta}</code></td>
                <td>{analise.nome_servidor}</td>
                <td><span style="background:{cor};color:#fff;padding:2px 8px;border-radius:4px;font-weight:bold;">{analise.nivel}</span></td>
                <td>{analise.score}/100</td>
                <td><ul style="margin:0;padding-left:16px;">{alertas_html}</ul></td>
            </tr>"""

        aviso_mascara = (
            '<p style="color:#888;font-style:italic;">⚠️ IPs mascarados para publicação ética.</p>'
            if mascarar_ips else ""
        )

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CS 1.6 Network Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 24px; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 8px; }}
        h2 {{ color: #0f3460; background: #16213e; padding: 8px 16px; border-left: 4px solid #e94560; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; margin: 4px; }}
        table {{ width: 100%; border-collapse: collapse; background: #16213e; margin-top: 16px; }}
        th {{ background: #0f3460; padding: 10px; text-align: left; color: #e94560; }}
        td {{ padding: 10px; border-bottom: 1px solid #0f3460; vertical-align: top; }}
        tr:hover {{ background: #0f3460; }}
        code {{ background: #0f3460; padding: 2px 6px; border-radius: 3px; color: #64ffda; }}
        .aviso {{ background: #2d1b00; border-left: 4px solid #e67e22; padding: 12px 16px; margin: 16px 0; border-radius: 0 4px 4px 0; }}
    </style>
</head>
<body>
    <h1>🔍 CS 1.6 Network Audit & Exposure Scanner</h1>
    <p>Gerado em {data_str} | Autor: Higor Samuel — Unimontes / DTI</p>

    <div class="aviso">
        ⚖️ <strong>Aviso Legal:</strong> Este relatório foi gerado com fins exclusivamente educativos e defensivos.
        Todas as consultas utilizam apenas dados públicos via protocolo A2S.
        Nenhuma autenticação, força bruta ou acesso não autorizado foi realizado.
    </div>

    {aviso_mascara}

    <h2>📊 Resumo Executivo</h2>
    <p>Total de servidores auditados: <strong>{total}</strong></p>
    <span class="badge" style="background:#e74c3c;">CRÍTICO: {contagem['CRÍTICO']}</span>
    <span class="badge" style="background:#e67e22;">ALTO: {contagem['ALTO']}</span>
    <span class="badge" style="background:#f1c40f;color:#333;">MÉDIO: {contagem['MÉDIO']}</span>
    <span class="badge" style="background:#2ecc71;color:#333;">BAIXO: {contagem['BAIXO']}</span>

    <h2>📋 Detalhamento por Servidor</h2>
    <table>
        <thead>
            <tr>
                <th>IP:Porta</th>
                <th>Nome do Servidor</th>
                <th>Nível de Risco</th>
                <th>Score</th>
                <th>Alertas Identificados</th>
            </tr>
        </thead>
        <tbody>
            {linhas_servidores}
        </tbody>
    </table>
</body>
</html>"""
