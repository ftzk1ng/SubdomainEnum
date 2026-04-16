# Política de Segurança

## Escopo

Este projeto foi criado para apoiar enumeração passiva e validação inicial de superfície web a partir de dados do VirusTotal. Ele não foi pensado para exploração, fuzzing, brute force ou qualquer forma de teste agressivo.

O uso deve ocorrer apenas em ambientes autorizados, dentro de contexto legítimo de pesquisa, defesa, auditoria interna ou avaliação previamente aprovada.

## Tratamento de segredos

- nunca versione o arquivo `.env`
- nunca publique sua `VT_API_KEY` em commits, prints, issues ou pull requests
- prefira revogar e gerar uma nova chave caso exista qualquer suspeita de exposição
- use `.env.example` apenas como modelo, sem valores reais

## Uso responsável

Ao utilizar esta ferramenta:

- confirme que você tem autorização para analisar o domínio em questão
- respeite limites de uso da API do VirusTotal
- evite divulgar listas de subdomínios ativos sem necessidade operacional
- interprete os resultados com cautela, especialmente em ambientes de terceiros

## Relato de vulnerabilidades

Se você identificar um problema de segurança neste projeto, o ideal é não abrir uma issue pública com detalhes sensíveis.

Prefira um contato privado com um resumo objetivo do problema, incluindo:

- descrição do comportamento observado
- impacto potencial
- passos mínimos para reproduzir
- sugestão de correção, se houver

## Boas práticas para quem for manter o projeto

- revise dependências antes de atualizar o ambiente
- mantenha segredos fora do código-fonte
- valide o `.gitignore` antes de publicar o repositório
- teste o fluxo com uma chave própria e revogável
- documente claramente qualquer nova integração externa

## Aviso final

Ferramentas de enumeração podem parecer simples, mas ainda assim lidam com ativos sensíveis. A utilidade do projeto depende tanto do código quanto da forma como ele é operado.
