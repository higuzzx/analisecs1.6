"""
CS 1.6 Network Audit & Exposure Scanner
========================================
Módulo principal do scanner de servidores GoldSource.

Uso educativo e defensivo — consultas apenas a dados públicos via protocolo A2S.
Autor: Higor Samuel | Unimontes / DTI
"""

from .core import consultar_servidor
from .parser import parsear_resposta
from .threader import VarredorThreaded

__version__ = "1.0.0"
__author__ = "Higor Samuel"
__all__ = ["consultar_servidor", "parsear_resposta", "VarredorThreaded"]
