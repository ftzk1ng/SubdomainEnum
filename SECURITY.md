# Security Policy

## Visão geral

Este projeto foi pensado para enumeração passiva e validação inicial de superfície web. Ele não foi desenhado para exploração ativa, brute force, fuzzing ou testes agressivos.

O uso deve acontecer apenas em contextos autorizados, com finalidade legítima de defesa, pesquisa, auditoria interna ou avaliação previamente aprovada.

## Escopo de segurança

Este repositório trata principalmente de:

- proteção de segredos locais
- segurança do fluxo de consulta à API do VirusTotal
- comportamento previsível nas checagens DNS e HTTP/HTTPS
- redução de exposição acidental no uso e no versionamento

## Segredos e credenciais

Para manter o projeto seguro:

- nunca versione o arquivo `.env`
- nunca publique sua `VT_API_KEY` em commits, prints, issues ou pull requests
- use `.env.example` apenas como modelo
- se houver qualquer suspeita de exposição, revogue a chave imediatamente e gere outra

## Uso responsável

Ao utilizar esta ferramenta:

- confirme que você tem autorização para analisar o domínio
- respeite os limites da API do VirusTotal
- evite divulgar listas de subdomínios ativos sem necessidade real
- trate os resultados como apoio de triagem, não como verdade absoluta

## Relato de problemas de segurança

Se você identificar uma falha neste projeto, prefira não abrir uma issue pública com detalhes sensíveis.

O ideal é reportar de forma privada, incluindo:

- descrição objetiva do problema
- impacto potencial
- passos mínimos para reprodução
- sugestão de correção, se houver

## Diretrizes para manutenção

Antes de publicar alterações:

- revise o que entrou no commit
- confirme que `.env` e arquivos locais não foram incluídos
- evite colocar tokens em linha de comando, exemplos ou documentação
- documente qualquer nova integração externa com clareza

## Observação final

Ferramentas pequenas também merecem cuidado operacional. Em projetos desse tipo, segurança não está só no código, mas também no jeito como o repositório é mantido e como a ferramenta é usada.
