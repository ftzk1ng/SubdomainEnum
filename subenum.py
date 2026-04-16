#!/usr/bin/env python3
"""Enumerador de subdomínios usando VirusTotal, DNS e checagem web."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import re
import ssl
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib import error, parse, request

try:
    import dns.exception
    import dns.resolver
except ImportError:
    dns = None


MAX_THREADS = 200
MAX_VT_RESULTS = 1000
MAX_VT_PAGES = 25
MAX_JSON_BYTES = 2 * 1024 * 1024
VT_PAGE_SIZE = 40
VT_MIN_INTERVAL = 16
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


@dataclass
class WebCheckResult:
    """Guarda o resultado de uma checagem simples de acesso web."""

    hostname: str
    url: str | None
    accessible: bool
    status_code: int | None
    error: str | None


def parse_args() -> argparse.Namespace:
    """Lê os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(
        description="Busca subdomínios no VirusTotal, resolve via DNS e testa HTTP/HTTPS."
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Domínio alvo, por exemplo: example.com",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help=f"Quantidade de threads para usar (padrão: 20, maximo: {MAX_THREADS})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Tempo limite do DNS em segundos (padrão: 2.0)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Arquivo opcional para salvar os subdomínios ativos",
    )
    parser.add_argument(
        "--virustotal-max-results",
        type=int,
        default=100,
        help=f"Máximo de subdomínios buscados no VirusTotal (padrão: 100, maximo: {MAX_VT_RESULTS})",
    )
    parser.add_argument(
        "--check-web",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Liga ou desliga a checagem web leve em HTTP/HTTPS (padrão: ligado)",
    )
    parser.add_argument(
        "--web-timeout",
        type=float,
        default=3.0,
        help="Tempo limite da requisição web em segundos (padrão: 3.0)",
    )
    parser.add_argument(
        "--http-only",
        action="store_true",
        help="Testa só HTTP, sem tentar HTTPS antes",
    )
    parser.add_argument(
        "--allow-http-fallback",
        action="store_true",
        help="Se HTTPS falhar, tenta HTTP como fallback explicito",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Ignora a validação do certificado TLS nas checagens HTTPS",
    )
    return parser.parse_args()


def ask_domain_if_missing(domain: str | None) -> str:
    """Pede o domínio no terminal quando ele não vier na linha de comando."""
    if domain:
        return domain

    typed_domain = input("Dominio alvo: ").strip()
    if not typed_domain:
        raise ValueError("Nenhum dominio foi informado.")
    return typed_domain


def load_env_file(env_path: Path = Path(".env")) -> None:
    """Carrega variáveis simples de um arquivo .env local, se ele existir."""
    if not env_path.is_file():
        return

    try:
        with env_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                # Se a variável já existir no shell, a gente respeita esse valor.
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        # Se não der para ler o arquivo, seguimos usando só as variáveis do ambiente.
        return


def normalize_hostname(hostname: str) -> str:
    """Padroniza o hostname para facilitar comparação e deduplicação."""
    return hostname.strip().strip(".").lower()


def validate_domain(domain: str) -> str:
    """Valida o domínio alvo para evitar entradas inválidas ou perigosas."""
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Informe um dominio valido, como exemplo.com.")

    try:
        parsed_ip = ipaddress.ip_address(domain)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        raise ValueError("Informe um dominio publico, nao um endereco IP.")

    blocked_names = {"localhost", "localdomain"}
    if domain in blocked_names:
        raise ValueError("Dominios locais nao sao aceitos.")

    return domain


def read_api_key() -> str | None:
    """Busca a chave no ambiente e, se preciso, pede no terminal sem ecoar."""
    api_key = os.getenv("VT_API_KEY")
    if api_key:
        return api_key.strip()

    if not os.isatty(0):
        return None

    typed_key = getpass.getpass("Chave da API do VirusTotal: ").strip()
    return typed_key or None


def validate_output_path(output_path: Path) -> Path:
    """Permite salvar apenas em caminhos normais dentro da pasta atual."""
    resolved_output = output_path.expanduser().resolve()
    allowed_root = Path.cwd().resolve()

    if resolved_output == allowed_root or allowed_root not in resolved_output.parents:
        raise ValueError("Escolha um arquivo de saida dentro da pasta atual do projeto.")

    return resolved_output


def resolve_with_dnspython(hostname: str, timeout: float) -> list[str]:
    """Resolve um hostname usando dnspython, se a biblioteca estiver disponível."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    answers = resolver.resolve(hostname, "A")
    return [answer.to_text() for answer in answers]


def resolve_with_socket(hostname: str) -> list[str]:
    """Resolve um hostname usando a biblioteca padrão como plano B."""
    _, _, addresses = socket.gethostbyname_ex(hostname)
    return addresses


def resolve_subdomain(hostname: str, timeout: float) -> tuple[str, list[str], str | None]:
    """Tenta resolver o hostname e devolve IPs encontrados ou o motivo da falha."""
    try:
        if dns is not None:
            return hostname, resolve_with_dnspython(hostname, timeout), None

        return hostname, resolve_with_socket(hostname), None
    except socket.gaierror:
        return hostname, [], "Host nao encontrado"
    except socket.timeout:
        return hostname, [], "Tempo de resolucao esgotado"
    except Exception as exc:
        if dns is not None and isinstance(exc, dns.resolver.NXDOMAIN):
            return hostname, [], "NXDOMAIN"
        if dns is not None and isinstance(exc, dns.resolver.NoAnswer):
            return hostname, [], "Sem resposta DNS"
        if dns is not None and isinstance(exc, dns.resolver.NoNameservers):
            return hostname, [], "Nenhum nameserver disponivel"
        if dns is not None and isinstance(exc, dns.exception.Timeout):
            return hostname, [], "Tempo de resolucao esgotado"
        return hostname, [], str(exc)


def enumerate_hostnames(
    hostnames: Iterable[str], threads: int, timeout: float
) -> tuple[list[tuple[str, list[str]]], list[tuple[str, str]]]:
    """Resolve os hostnames em paralelo e separa o que respondeu do que falhou."""
    active: list[tuple[str, list[str]]] = []
    failed: list[tuple[str, str]] = []
    normalized_hosts = sorted({normalize_hostname(hostname) for hostname in hostnames if hostname})

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(resolve_subdomain, hostname, timeout): hostname
            for hostname in normalized_hosts
        }

        for future in as_completed(future_map):
            hostname, addresses, error = future.result()
            if addresses:
                active.append((hostname, addresses))
            elif error:
                failed.append((hostname, error))

    active.sort(key=lambda item: item[0])
    failed.sort(key=lambda item: item[0])
    return active, failed


def fetch_json(url: str, headers: dict[str, str], timeout: float) -> dict:
    """Busca um JSON em um endpoint HTTP."""
    api_request = request.Request(url, headers=headers)
    with request.urlopen(api_request, timeout=timeout) as response:
        payload = response.read(MAX_JSON_BYTES + 1)

    if len(payload) > MAX_JSON_BYTES:
        raise ValueError("Resposta da API maior do que o limite permitido.")

    return json.loads(payload.decode("utf-8"))


def fetch_virustotal_subdomains(
    domain: str,
    api_key: str,
    max_results: int,
    timeout: float,
) -> list[str]:
    """Busca subdomínios de um domínio usando a API do VirusTotal."""
    collected: list[str] = []
    next_url = (
        "https://www.virustotal.com/api/v3/domains/"
        f"{parse.quote(domain)}/subdomains?limit={VT_PAGE_SIZE}"
    )
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }
    pages_fetched = 0
    last_request_at = 0.0

    while next_url and len(collected) < max_results and pages_fetched < MAX_VT_PAGES:
        now = time.monotonic()
        elapsed = now - last_request_at
        if elapsed < VT_MIN_INTERVAL:
            time.sleep(VT_MIN_INTERVAL - elapsed)

        try:
            payload = fetch_json(next_url, headers=headers, timeout=timeout)
        except error.HTTPError as exc:
            if exc.code == 429:
                retry_after = exc.headers.get("Retry-After")
                wait_seconds = VT_MIN_INTERVAL
                if retry_after and retry_after.isdigit():
                    wait_seconds = max(wait_seconds, int(retry_after))
                print(f"[!] API do VirusTotal limitou as requisicoes. Aguardando {wait_seconds}s...")
                time.sleep(wait_seconds)
                continue
            raise

        last_request_at = time.monotonic()
        pages_fetched += 1
        for item in payload.get("data", []):
            hostname = normalize_hostname(item.get("id", ""))
            if hostname:
                collected.append(hostname)
            if len(collected) >= max_results:
                break
        next_url = payload.get("links", {}).get("next")

    return sorted(set(collected))


def build_ssl_context(verify_tls: bool) -> ssl.SSLContext | None:
    """Cria o contexto SSL usado nas checagens HTTPS."""
    if verify_tls:
        return None

    insecure_context = ssl.create_default_context()
    insecure_context.check_hostname = False
    insecure_context.verify_mode = ssl.CERT_NONE
    return insecure_context


class NoRedirectHandler(request.HTTPRedirectHandler):
    """Impede redirects automaticos para evitar saltos inesperados."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_url(
    url: str,
    method: str,
    timeout: float,
    ssl_context: ssl.SSLContext | None,
) -> tuple[bool, int | None, str | None]:
    """Abre uma URL sem seguir redirects automaticamente."""
    headers = {"User-Agent": "SubdomainEnumerator/1.0"}
    web_request = request.Request(url, method=method, headers=headers)
    handlers: list[request.BaseHandler] = [NoRedirectHandler()]
    if ssl_context is not None:
        handlers.append(request.HTTPSHandler(context=ssl_context))
    opener = request.build_opener(*handlers)

    try:
        with opener.open(web_request, timeout=timeout) as response:
            return True, response.getcode(), None
    except error.HTTPError as exc:
        if 300 <= exc.code < 400:
            return True, exc.code, "Redirect bloqueado para manter a checagem previsivel"
        return True, exc.code, None
    except (error.URLError, socket.timeout, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        return False, None, str(reason)


def check_url(url: str, timeout: float, ssl_context: ssl.SSLContext | None) -> tuple[bool, int | None, str | None]:
    """Faz uma requisição leve para ver se a URL responde."""
    accessible, status_code, error_message = open_url(
        url=url,
        method="HEAD",
        timeout=timeout,
        ssl_context=ssl_context,
    )
    if accessible:
        return accessible, status_code, error_message

    return open_url(
        url=url,
        method="GET",
        timeout=timeout,
        ssl_context=ssl_context,
    )


def check_web_host(
    hostname: str,
    web_timeout: float,
    prefer_https: bool,
    allow_http_fallback: bool,
    verify_tls: bool,
) -> WebCheckResult:
    """Verifica se um hostname resolvido responde por HTTP ou HTTPS."""
    if not prefer_https:
        schemes = ["http"]
    elif allow_http_fallback:
        schemes = ["https", "http"]
    else:
        schemes = ["https"]
    ssl_context = build_ssl_context(verify_tls)

    last_error = None
    for scheme in schemes:
        url = f"{scheme}://{hostname}"
        accessible, status_code, error_message = check_url(url, web_timeout, ssl_context)
        if accessible:
            return WebCheckResult(
                hostname=hostname,
                url=url,
                accessible=True,
                status_code=status_code,
                error=None,
            )
        last_error = error_message

    return WebCheckResult(
        hostname=hostname,
        url=None,
        accessible=False,
        status_code=None,
        error=last_error,
    )


def check_web_hosts(
    active: list[tuple[str, list[str]]],
    threads: int,
    web_timeout: float,
    prefer_https: bool,
    allow_http_fallback: bool,
    verify_tls: bool,
) -> list[WebCheckResult]:
    """Roda as checagens web em paralelo para os hosts que resolveram."""
    results: list[WebCheckResult] = []
    hostnames = [hostname for hostname, _ in active]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(
                check_web_host,
                hostname,
                web_timeout,
                prefer_https,
                allow_http_fallback,
                verify_tls,
            ): hostname
            for hostname in hostnames
        }

        for future in as_completed(future_map):
            results.append(future.result())

    results.sort(key=lambda item: item.hostname)
    return results


def print_results(active: list[tuple[str, list[str]]]) -> None:
    """Mostra no terminal os subdomínios que resolveram."""
    if not active:
        print("[-] Nenhum subdominio ativo foi encontrado.")
        return

    print(f"[+] Encontrados {len(active)} subdominio(s) ativo(s):")
    for hostname, addresses in active:
        print(f" - {hostname} -> {', '.join(addresses)}")


def print_web_results(results: list[WebCheckResult]) -> None:
    """Mostra no terminal quais hosts responderam na web."""
    if not results:
        print("[*] Nenhuma checagem web foi executada.")
        return

    reachable = [item for item in results if item.accessible]
    unreachable = [item for item in results if not item.accessible]

    print(f"[+] Hosts acessiveis via web: {len(reachable)}")
    for item in reachable:
        print(f" - {item.hostname} -> {item.url} (status: {item.status_code})")

    if unreachable:
        print(f"[*] Resolveram no DNS, mas nao responderam na web: {len(unreachable)}")
        for item in unreachable:
            print(f" - {item.hostname} -> {item.error}")


def save_results(output_path: Path, active: list[tuple[str, list[str]]]) -> None:
    """Salva os subdomínios ativos em um arquivo texto."""
    with output_path.open("w", encoding="utf-8") as handle:
        for hostname, addresses in active:
            handle.write(f"{hostname} -> {', '.join(addresses)}\n")


def save_web_results(output_path: Path, results: list[WebCheckResult]) -> None:
    """Salva o resultado da checagem web em um arquivo texto."""
    with output_path.open("w", encoding="utf-8") as handle:
        for item in results:
            if item.accessible:
                handle.write(
                    f"{item.hostname} -> {item.url} (status: {item.status_code})\n"
                )
            else:
                handle.write(f"{item.hostname} -> INACESSIVEL ({item.error})\n")


def main() -> int:
    """Ponto de entrada principal do script."""
    load_env_file()
    try:
        args = parse_args()
        domain = validate_domain(normalize_hostname(ask_domain_if_missing(args.domain)))
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1

    if args.threads < 1:
        print("[!] O numero de threads precisa ser pelo menos 1.")
        return 1

    if args.threads > MAX_THREADS:
        print(f"[!] O numero de threads nao pode passar de {MAX_THREADS}.")
        return 1

    if args.timeout <= 0:
        print("[!] O timeout precisa ser maior que 0.")
        return 1

    if args.web_timeout <= 0:
        print("[!] O timeout web precisa ser maior que 0.")
        return 1

    if args.virustotal_max_results < 1:
        print("[!] O limite maximo de resultados do VirusTotal precisa ser pelo menos 1.")
        return 1

    if args.virustotal_max_results > MAX_VT_RESULTS:
        print(f"[!] O limite maximo de resultados do VirusTotal e {MAX_VT_RESULTS}.")
        return 1

    vt_api_key = read_api_key()
    if not vt_api_key:
        print("[!] Chave da API do VirusTotal ausente. Defina VT_API_KEY ou informe quando o script pedir.")
        return 1

    if args.insecure:
        print("[!] Aviso: a validacao TLS foi desativada. Use isso apenas em ambiente controlado.")

    try:
        candidates = fetch_virustotal_subdomains(
            domain=domain,
            api_key=vt_api_key,
            max_results=args.virustotal_max_results,
            timeout=args.timeout,
        )
    except error.HTTPError as exc:
        print(f"[!] A API do VirusTotal retornou HTTP {exc.code}: {exc.reason}")
        return 1
    except error.URLError as exc:
        print(f"[!] Nao foi possivel chegar ate a API do VirusTotal: {exc.reason}")
        return 1
    except ValueError as exc:
        print(f"[!] Resposta invalida da API: {exc}")
        return 1
    except json.JSONDecodeError as exc:
        print(f"[!] A API do VirusTotal devolveu um JSON invalido: {exc}")
        return 1

    print(f"[*] O VirusTotal retornou {len(candidates)} subdominio(s).")

    if not candidates:
        print("[!] Nenhum subdominio foi retornado pelo VirusTotal.")
        return 1

    active, failed = enumerate_hostnames(
        hostnames=candidates,
        threads=args.threads,
        timeout=args.timeout,
    )

    print_results(active)
    print(f"[*] Foram testados {len(candidates)} candidato(s).")
    print(f"[*] Falharam ou ficaram inativos: {len(failed)}")

    web_results: list[WebCheckResult] = []
    if args.check_web and active:
        web_results = check_web_hosts(
            active=active,
            threads=args.threads,
            web_timeout=args.web_timeout,
            prefer_https=not args.http_only,
            allow_http_fallback=args.allow_http_fallback,
            verify_tls=not args.insecure,
        )
        print_web_results(web_results)

    if args.output:
        try:
            output_path = validate_output_path(args.output)
            if args.check_web:
                save_web_results(output_path, web_results)
            else:
                save_results(output_path, active)
            print(f"[*] Resultado salvo em: {output_path}")
        except ValueError as exc:
            print(f"[!] {exc}")
            return 1
        except OSError as exc:
            print(f"[!] Nao foi possivel salvar o arquivo de saida: {exc}")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
