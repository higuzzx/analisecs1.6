#  CS 1.6 Network Audit & Exposure Scanner
### Auditoria Ética de Infraestrutura GoldSource — Hardening, Exposição e Segurança Defensiva

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Isolamento-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-Análise_de_Pacotes-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![License](https://img.shields.io/badge/Uso-Educativo_e_Ético-brightgreen?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Em_Desenvolvimento-yellow?style=for-the-badge)

</div>

---

> **⚠️ Aviso Legal:** Este projeto tem finalidade **estritamente educativa e defensiva**. Todas as consultas realizadas utilizam apenas dados publicamente disponíveis pelo protocolo A2S do Valve. Nenhuma tentativa de autenticação, força bruta ou acesso não autorizado é realizada. O uso deve respeitar a **Lei nº 12.737/2012 (Lei Carolina Dieckmann)** e o **Marco Civil da Internet (Lei nº 12.965/2014)**.

---

##  Introdução

Olá, me chamo **Higor Samuel**, sou estudante de **Sistemas de Informação na Unimontes**. Este projeto nasceu da minha inquietação com um problema real: a negligência generalizada em relação ao hardening de servidores de jogos expostos na internet brasileira.

Servidores de Counter-Strike 1.6 ainda rodam em produção com configurações padrão de 2003, versões sem patch e consoles administrativos (RCON) acessíveis sem proteção adequada. São alvos triviais para amplificação de tráfego UDP, reconhecimento de infraestrutura e, em casos mais graves, execução remota de comandos.

Inspirado pelo trabalho do **[@YuriRDev](https://github.com/YuriRDev)** — cujo projeto de descoberta de ativos me mostrou a beleza da automação aplicada à segurança —, adaptei a lógica de asset discovery para o protocolo **GoldSource Engine**, com foco em mapear, documentar e conscientizar sobre a exposição desses servidores no Brasil.

Este não é um projeto de ataque. É um projeto de **espelho**: mostrar aos operadores o que qualquer pessoa na internet já consegue ver sobre sua infraestrutura.

---

## 🏗️ Stack Tecnológica

| Tecnologia | Função |
|---|---|
| **Python 3.10+** | Core do scanner — Sockets UDP, Threading e parsing de payload |
| **Docker** | Isolamento do ambiente de execução para segurança e reprodutibilidade |
| **Wireshark** | Análise e inspeção dos pacotes GoldSource em nível de bits |
| **Iptables / UFW** | Demonstração das mitigações recomendadas |

---

## 📡 Como Funciona: O Protocolo GoldSource (A2S_INFO)

O protocolo **GoldSource da Valve** expõe uma API UDP não autenticada na porta `27015`. Qualquer cliente pode enviar um pacote de consulta `A2S_INFO` e o servidor responderá com seus metadados completos — sem nenhum processo de autenticação.

### O Handshake em 3 Passos

```
Cliente                         Servidor CS 1.6 (:27015/UDP)
   |                                     |
   |  [A2S_INFO Request]                 |
   |  FF FF FF FF 54 53 6F 75 72 63 65  |
   |  20 45 6E 67 69 6E 65 20 51 75 65  |
   |  72 79 00                           |
   | ----------------------------------> |
   |                                     |
   |  [A2S_INFO Response]                |
   |  Header | Protocol | Name | Map     |
   |  Folder | Game | Players | MaxPlayers|
   |  Bots | Type | OS | VAC | Version  |
   | <---------------------------------- |
```

### Implementação do Scanner

```python
import socket
import threading
from typing import Optional

# Payload do pacote A2S_INFO — padrão público do protocolo Valve
# Referência: https://developer.valvesoftware.com/wiki/Server_queries
A2S_INFO_PAYLOAD = (
    b'\xFF\xFF\xFF\xFF'   # Header de prefixo (4 bytes — identifica pacote Source/GoldSource)
    b'\x54'               # Tipo da query: 'T' = A2S_INFO
    b'Source Engine Query\x00'  # String de identificação terminada em null
)

TIMEOUT_SEGUNDOS = 2.0
PORTA_PADRAO_GOLDSOURCE = 27015


def consultar_servidor(ip: str, porta: int = PORTA_PADRAO_GOLDSOURCE) -> Optional[dict]:
    """
    Realiza uma consulta pública A2S_INFO a um servidor GoldSource.
    Retorna os metadados públicos ou None se o servidor não responder.

    NOTA ÉTICA: Esta função apenas envia o payload padrão de consulta
    que qualquer cliente CS 1.6 envia ao conectar na lista de servidores.
    Não há tentativa de autenticação ou envio de comandos.
    """
    try:
        # Cria socket UDP — sem conexão (stateless), assim como o protocolo
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT_SEGUNDOS)

        # Envia o payload de consulta pública
        sock.sendto(A2S_INFO_PAYLOAD, (ip, porta))

        # Aguarda a resposta do servidor (máx. 4096 bytes)
        dados, _ = sock.recvfrom(4096)
        sock.close()

        # Realiza o parsing do payload de resposta
        return _parsear_resposta(dados)

    except (socket.timeout, OSError):
        # Servidor offline, porta fechada ou filtrada por firewall
        return None


def _parsear_resposta(payload: bytes) -> dict:
    """
    Deserializa o payload binário da resposta A2S_INFO.
    Extrai campos de texto (null-terminated) e campos numéricos.
    """
    offset = 6  # Pula header (4 bytes) + tipo de resposta (1) + protocolo (1)

    def ler_string() -> str:
        """Lê uma string ASCII terminada em byte nulo (\\x00)."""
        nonlocal offset
        fim = payload.index(b'\x00', offset)
        valor = payload[offset:fim].decode('utf-8', errors='replace')
        offset = fim + 1
        return valor

    def ler_byte() -> int:
        nonlocal offset
        valor = payload[offset]
        offset += 1
        return valor

    return {
        "nome_servidor": ler_string(),     # Nome público do servidor
        "mapa_atual":    ler_string(),     # Mapa em execução (ex: de_dust2)
        "pasta_jogo":    ler_string(),     # Pasta do mod (ex: cstrike)
        "nome_jogo":     ler_string(),     # Nome do jogo (ex: Counter-Strike)
        "jogadores":     ler_byte(),       # Jogadores atualmente conectados
        "max_jogadores": ler_byte(),       # Capacidade máxima do servidor
        "bots":          ler_byte(),       # Quantidade de bots
        "tipo_servidor": chr(ler_byte()),  # d=dedicado, l=local, p=proxy
        "sistema_op":    chr(ler_byte()),  # l=Linux, w=Windows, m=Mac
        "vac_ativo":     bool(ler_byte()), # Valve Anti-Cheat habilitado
    }


def varrer_faixa_ips(faixa: list[str], resultados: list, lock: threading.Lock) -> None:
    """
    Varre uma lista de IPs usando threading para paralelismo.
    Thread-safe: usa Lock para escrita na lista de resultados compartilhada.
    """
    for ip in faixa:
        dados = consultar_servidor(ip)
        if dados:
            with lock:
                resultados.append({"ip": ip, **dados})
                print(f"[+] Servidor encontrado: {ip} | {dados['nome_servidor']} | {dados['mapa_atual']}")
```

### Execução com Docker (Ambiente Isolado)

```bash
# Build da imagem isolada
docker build -t cs16-auditor .

# Execução com saída em JSON — sem acesso à rede host
docker run --rm \
  --network=bridge \
  -v $(pwd)/resultados:/app/output \
  cs16-auditor \
  --faixa "200.x.x.0/24" \
  --output /app/output/auditoria.json \
  --threads 50
```

---

##  Análise de Riscos: O Que os Dados Revelam

### Vulnerabilidades Identificadas em Campo

Durante os testes de auditoria, os seguintes padrões de exposição foram documentados:

#### 1. Versões Obsoletas Sem Patch
Servidores rodando CS 1.6 build `4554` (2013) ainda são comuns no Brasil. Essas versões contêm vulnerabilidades conhecidas publicamente no motor GoldSource que permitem **crash remoto** via pacotes UDP malformados.

```
[!] Versão detectada: 47/4554 (DESATUALIZADA)
    CVEs conhecidos associados: sim
    Última versão estável: 48/8684
```

#### 2. RCON Exposto Sem Rate Limiting
O **Remote Console (RCON)** é o protocolo de administração remota do servidor. Quando exposto sem limitação de tentativas, torna-se alvo trivial de ataques de força bruta por dicionário:

```python
# EXEMPLO DO RISCO (não implementado neste scanner)
# Um atacante poderia enviar repetidamente:
# FF FF FF FF 63 6F 6E 6E 65 63 74 00  [RCON challenge request]
# Seguido de: FF FF FF FF 72 63 6F 6E  [RCON auth attempt]
# Em loop, até encontrar a senha correta
# SEM QUALQUER BLOQUEIO por padrão no servidor
```

#### 3. Amplificação UDP — O Risco Silencioso

Este é o risco mais crítico identificado. O protocolo A2S permite **amplificação de tráfego**:

```
Pacote enviado (spoofado):  ~25 bytes
Resposta do servidor:       ~350 bytes
Fator de amplificação:      ~14x

Em um ataque DDoS de reflexão:
  100 Mbps de envio → ~1.4 Gbps direcionado à vítima
  Sem qualquer autenticação necessária
```

Servidores sem rate limiting no kernel se tornam involuntariamente **amplificadores de DDoS**, vitimizando terceiros.

---

##  Hardening & Mitigação: Passos Práticos

### Nível 1 — Firewall com UFW/Iptables

```bash
# Permitir apenas a porta do jogo para consultas legítimas
ufw allow 27015/udp comment "CS 1.6 Game Port"

# Bloquear RCON para IPs não autorizados (substitua pelo seu IP de admin)
ufw deny 27015/tcp
ufw allow from 203.0.113.10 to any port 27015 proto tcp comment "Admin RCON"

# Rate limiting para mitigar amplificação UDP
iptables -A INPUT -p udp --dport 27015 \
  -m hashlimit \
  --hashlimit-name cs16_ratelimit \
  --hashlimit-mode srcip \
  --hashlimit-upto 20/sec \
  --hashlimit-burst 50 \
  -j ACCEPT

# Descartar excesso de pacotes
iptables -A INPUT -p udp --dport 27015 -j DROP
```

### Nível 2 — Configuração do Servidor (server.cfg)

```bash
# Troque a porta padrão para dificultar varreduras automatizadas
# (em linha de comando na inicialização do server)
./hlds_run -game cstrike +ip 0.0.0.0 +port 28015 +maxplayers 20 +map de_dust2

# Dentro do server.cfg — proteção do RCON
rcon_password "SenhaForteAleatoria_Minimo32Chars!"
sv_rcon_maxfailures 3       // Banir após 3 tentativas falhas
sv_rcon_minfailuretime 30   // Janela de tempo para as tentativas (segundos)
sv_rcon_banpenalty 60       // Duração do ban em minutos

# Limitar informações expostas na query
sv_visiblemaxplayers -1     // Ocultar capacidade real
```

### Nível 3 — Proxy Reverso com IP Mascarado

```
Internet ──► Proxy/CDN (IP Público) ──► Servidor CS 1.6 (IP Interno)
              (Absorve DDoS)              (Nunca exposto diretamente)
```

Ferramentas recomendadas: **TCPShield**, **NFOCloud DDoS Protection**, ou **nginx UDP stream proxy** para infraestrutura própria.

---

## 🧪 Análise com Wireshark

Para capturar o handshake A2S_INFO durante a execução do scanner:

```bash
# Filtro Wireshark para isolar o tráfego GoldSource
udp.port == 27015

# Filtro mais específico para ver apenas as respostas
udp.port == 27015 && udp.length > 100

# Para identificar tentativas de RCON (apenas monitoramento defensivo)
udp.port == 27015 && data.data[4:1] == 55  # byte 0x55 = RCON challenge
```

> 📸 **Recomendação de documentação:** Capture o payload expandido na árvore do Wireshark mostrando o campo `Valve Protocol Header (FF FF FF FF)` e os campos de texto desserializados. Censure IPs reais antes de publicar qualquer screenshot.

---

## 📁 Estrutura do Projeto

```
cs16-network-auditor/
├── scanner/
│   ├── __init__.py
│   ├── core.py           # Lógica de consulta A2S_INFO
│   ├── parser.py         # Deserialização do payload binário
│   └── threader.py       # Pool de threads para varredura paralela
├── analysis/
│   ├── risk_score.py     # Classificação automática de risco por servidor
│   └── reporter.py       # Geração de relatório JSON/HTML
├── hardening/
│   └── templates/
│       ├── iptables.sh   # Template de regras recomendadas
│       └── server.cfg    # Template de configuração segura
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

##  Metodologia Ética e Conformidade Legal

Este projeto foi desenvolvido com rigoroso compromisso ético:

**O que o scanner FAZ:**
- Envia o pacote `A2S_INFO` padrão — idêntico ao que todo cliente CS 1.6 envia ao navegar na lista de servidores
- Recebe e processa metadados **públicos** que o servidor entrega voluntariamente a qualquer requisitante
- Documenta a exposição para fins de conscientização

**O que o scanner NUNCA fará:**
- Tentativas de autenticação ou quebra de senha (RCON brute force)
- Envio de payloads malformados ou exploits
- Exfiltração de dados privados ou de jogadores conectados
- Varredura de redes privadas ou corporativas sem autorização explícita

**Base legal:** As consultas A2S_INFO são equivalentes a visualizar uma página web pública — o servidor anuncia essas informações ativamente para qualquer cliente na rede. A auditoria se enquadra na **atividade de pesquisa de segurança defensiva**, compatível com o artigo 154-A do Código Penal (que criminaliza acesso *não autorizado*, não consultas a dados voluntariamente públicos).

---

##  Exemplo de Saída

```json
{
  "auditoria": {
    "data": "2025-06-01T14:32:00Z",
    "total_consultados": 1024,
    "responderam": 87,
    "vulnerabilidades_criticas": 23
  },
  "servidores": [
    {
      "ip": "███.███.███.███",
      "porta": 27015,
      "nome_servidor": "[BR] Server ████████",
      "mapa_atual": "de_inferno",
      "versao": "47/4554",
      "vac_ativo": false,
      "risco": "CRÍTICO",
      "alertas": [
        "Versão desatualizada (build 4554 — CVEs conhecidos)",
        "VAC desabilitado",
        "RCON na porta padrão sem evidência de rate limiting"
      ]
    }
  ]
}
```

> **Nota:** IPs reais são sempre censurados antes de qualquer divulgação pública, conforme boa prática de divulgação responsável (responsible disclosure).

---

##  Como Executar

```bash
# 1. Clone o repositório
git clone https://github.com/higorsamuel/cs16-network-auditor.git
cd cs16-network-auditor

# 2. Instale as dependências
pip install -r requirements.txt

# 3. Execute com Docker (recomendado)
docker-compose up --build

# 4. Ou execute diretamente (apenas em ambiente controlado)
python -m scanner --faixa "SEU_IP_AUTORIZADO/24" --output resultados.json
```

---

##  Referências e Créditos

- **[@YuriRDev](https://github.com/YuriRDev)** — Inspiração central deste projeto. Seu trabalho com descoberta automatizada de ativos me mostrou como transformar conceitos de segurança em ferramentas práticas e elegantes. Muito do raciocínio de threading e estruturação do scanner foi influenciado pela sua abordagem.
- [Valve Developer Wiki — Server Queries](https://developer.valvesoftware.com/wiki/Server_queries) — Especificação oficial do protocolo A2S
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — Metodologia de testes de segurança
- [CERT.br — Boas Práticas de Segurança](https://cert.br/docs/) — Referência nacional em segurança defensiva

---

##  Aprendizados e Próximos Passos

Este projeto me ensinou que **segurança defensiva começa com visibilidade**. Você não pode proteger o que não consegue enxergar. Ao mapear sistematicamente a exposição de servidores GoldSource brasileiros, entendi na prática:

- Como protocolos UDP sem autenticação se tornam vetores de amplificação
- Por que o modelo de ameaça deve preceder qualquer decisão de arquitetura
- A importância de firewalls com estado (stateful) mesmo para servidores de jogos
- Como o isolamento via containers reduz drasticamente a superfície de ataque

Os próximos passos incluem adicionar detecção automática de versão vulnerável, integração com CVE databases e geração de relatórios de hardening personalizados por servidor.

---

<div align="center">

Desenvolvido por **Higor Samuel** | Estudante de SI — Unimontes | DTI

*"A segurança não é um produto, é um processo."* — Bruce Schneier

⭐ Se este projeto foi útil, considere deixar uma estrela!

</div>
