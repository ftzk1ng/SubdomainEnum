# Subdomain Enumerator

Ferramenta simples em Python para apoiar triagem de subdomínios a partir do VirusTotal.

O fluxo é direto:

1. consulta subdomínios de um domínio na API do VirusTotal
2. tenta resolver cada hostname via DNS
3. opcionalmente testa se o host responde em `HTTPS` e `HTTP`

O foco do projeto é ser útil em rotina de OSINT, validação de superfície web e revisão inicial de exposição externa, sem inventário invasivo nem exploração ativa.

## Visão geral

O script foi pensado para um uso prático e rápido no terminal. Em vez de depender de wordlists, ele trabalha com uma fonte externa de inteligência já consolidada e depois faz a validação local dos resultados.

Hoje o projeto cobre:

- coleta de subdomínios via VirusTotal
- resolução DNS concorrente
- checagem web leve com `HTTPS` por padrão
- fallback opcional para `HTTP` apenas quando solicitado
- saída no terminal
- exportação opcional para arquivo texto
- leitura da chave da API via variável de ambiente ou prompt seguro

## Requisitos

- Python 3.10 ou superior
- `dnspython` para resolução DNS mais confiável
- chave válida da API do VirusTotal

## Instalação

Clone o repositório e entre na pasta do projeto:

```bash
git clone <URL_DO_REPOSITORIO>
cd "Subdomain Enumerator"
```

Crie um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Instale a dependência:

```bash
python -m pip install dnspython
```

## Configuração

Você pode definir a chave da API no ambiente:

```bash
export VT_API_KEY="sua_chave_aqui"
```

Se preferir manter uma configuração local fora do versionamento, crie um arquivo `.env`:

```env
VT_API_KEY=sua_chave_aqui
```

Se preferir, use o modelo já incluído:

```bash
cp .env.example .env
```

O `.env` está no `.gitignore` e não deve ser versionado.

## Como usar

Exemplo básico:

```bash
python3 subenum.py google.com
```

Buscar subdomínios e testar acesso web:

```bash
python3 subenum.py google.com --insecure
```

Limitar o volume de resultados:

```bash
python3 subenum.py google.com --virustotal-max-results 20 --insecure
```

Salvar a saída em arquivo:

```bash
python3 subenum.py google.com --virustotal-max-results 20 --insecure -o resultados.txt
```

## Principais opções

- `--virustotal-max-results`: limita a quantidade de subdomínios retornados pela API
- `--check-web`: mantém a checagem web ativa
- `--web-timeout`: define o tempo limite da checagem web
- `--http-only`: testa apenas `HTTP`
- `--allow-http-fallback`: tenta `HTTP` só depois de falha em `HTTPS`
- `--insecure`: ignora validação de certificado TLS durante a checagem HTTPS
- `-o` ou `--output`: salva o resultado em arquivo

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

## Estrutura do projeto

```text
.
├── subenum.py
├── .env.example
├── .gitignore
├── README.md
└── SECURITY.md
```

## Boas práticas de uso

- use a ferramenta apenas em contextos autorizados
- trate respostas `403` e `404` como indício de serviço web exposto, não como ausência de host
- evite publicar arquivos de saída que contenham inventário sensível de terceiros
- considere os limites de uso da API do VirusTotal antes de aumentar o volume das consultas

## Limitações conhecidas

- a qualidade dos resultados depende do que o VirusTotal conhece sobre o domínio
- nem todo subdomínio resolvido necessariamente representa um ativo útil ou atual
- a checagem web testa apenas a resposta básica da aplicação, não o comportamento funcional da página
- alguns ambientes podem exigir `--insecure` por conta de certificados desalinhados ou expirados

## Licença

Se este projeto for publicado, vale incluir uma licença compatível com o uso pretendido.
