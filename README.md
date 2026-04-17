# SubdomainEnum

<p align="center">
  Ferramenta enxuta para descoberta de subdomínios via VirusTotal, resolução DNS e validação web inicial.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-111111?style=flat-square&logo=python&logoColor=white&labelColor=000000" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-111111?style=flat-square&logo=open-source-initiative&logoColor=white&labelColor=000000" alt="License MIT">
  <img src="https://img.shields.io/badge/fonte-VirusTotal-111111?style=flat-square&logo=virustotal&logoColor=white&labelColor=000000" alt="Fonte VirusTotal">
  <img src="https://img.shields.io/badge/foco-OSINT%20%7C%20Surface%20Web-111111?style=flat-square&logo=datadog&logoColor=white&labelColor=000000" alt="Foco OSINT e Surface Web">
</p>

## Sobre

O `SubdomainEnum` foi feito para um fluxo simples e útil no dia a dia: consultar subdomínios conhecidos pelo VirusTotal, verificar quais resolvem via DNS e, se fizer sentido para a análise, validar quais realmente respondem em `HTTPS` ou `HTTP`.

Não é uma ferramenta de exploração, fuzzing ou brute force. A proposta aqui é apoiar triagem, OSINT e validação inicial de superfície externa de forma objetiva.

## O que a ferramenta faz

- consulta subdomínios via API do VirusTotal
- resolve os hostnames encontrados com concorrência
- testa `HTTPS` por padrão
- permite `HTTP` apenas quando você pedir isso explicitamente
- salva resultados em arquivo quando necessário
- lê a chave da API por variável de ambiente ou prompt seguro

## Tecnologias

- Python 3
- `dnspython`
- VirusTotal API v3
- `ThreadPoolExecutor` para concorrência
- `urllib` e `ssl` da biblioteca padrão

## Fluxo de uso

```text
VirusTotal -> DNS -> HTTPS/HTTP -> saída no terminal ou arquivo
```

## Instalação

Clone o repositório e entre na pasta do projeto:

```bash
git clone https://github.com/ftzk1ng/SubdomainEnum.git
cd SubdomainEnum
```

Crie um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Instale a dependência necessária:

```bash
python -m pip install dnspython
```

## Configuração

A forma mais segura é definir a chave no ambiente:

```bash
export VT_API_KEY="sua_chave_aqui"
```

Se preferir usar arquivo local, copie o modelo:

```bash
cp .env.example .env
```

Depois edite o `.env` local com sua chave. Esse arquivo não deve ser versionado.

## Uso rápido

Consulta básica:

```bash
python3 subenum.py google.com
```

Consulta com validação web:

```bash
python3 subenum.py google.com --insecure
```

Consulta menor para teste:

```bash
python3 subenum.py google.com --virustotal-max-results 20
```

Salvar a saída em arquivo:

```bash
python3 subenum.py google.com -o resultados.txt
```

Testar apenas HTTP:

```bash
python3 subenum.py google.com --http-only
```

Permitir fallback de HTTPS para HTTP:

```bash
python3 subenum.py google.com --allow-http-fallback
```

## Principais opções

- `--virustotal-max-results`: define o limite de subdomínios consultados
- `--check-web`: mantém a checagem web ativa
- `--no-check-web`: pula a etapa HTTP/HTTPS
- `--web-timeout`: ajusta o tempo limite da validação web
- `--http-only`: usa apenas HTTP
- `--allow-http-fallback`: tenta HTTP após falha em HTTPS
- `--insecure`: desativa validação TLS para testes controlados
- `-o` ou `--output`: salva a saída em arquivo

Para ver todas as opções:

```bash
python3 subenum.py --help
```

## Exemplo de saída

```text
[*] O VirusTotal retornou 20 subdominio(s).
[+] Encontrados 16 subdominio(s) ativo(s):
 - ead.exemplo.com -> 203.0.113.10
 - app.exemplo.com -> 203.0.113.11
[*] Foram testados 20 candidato(s).
[*] Falharam ou ficaram inativos: 4
[+] Hosts acessiveis via web: 8
 - ead.exemplo.com -> https://ead.exemplo.com (status: 200)
 - app.exemplo.com -> https://app.exemplo.com (status: 403)
```

## Estrutura do repositório

```text
.
├── subenum.py
├── .env.example
├── .gitignore
├── README.md
├── SECURITY.md
└── LICENSE
```

## Boas práticas

- use a ferramenta apenas em contextos autorizados
- trate `403` e `404` como sinais de serviço exposto, não como ausência de host
- não publique inventários sensíveis de terceiros
- revogue imediatamente qualquer chave exposta por engano
- use `--insecure` apenas quando souber exatamente por que está fazendo isso

## Limitações

- a qualidade dos resultados depende da visibilidade que o VirusTotal tem do domínio
- nem todo host resolvido representa um ativo relevante ou atual
- a checagem web valida presença de serviço, não o comportamento funcional da aplicação
- ambientes com certificados quebrados podem exigir ajustes na validação TLS

## Segurança

As orientações de uso responsável, tratamento de segredos e relato de problemas estão em [SECURITY.md](./SECURITY.md).

## Licença

Este projeto está licenciado sob a [MIT License](./LICENSE).
