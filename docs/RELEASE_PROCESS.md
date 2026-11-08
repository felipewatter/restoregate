# Procedimento de publicação e release

## Pré-requisitos

- Aprovação explícita do mantenedor para criar o repositório **público**.
- Credenciais GitHub autorizadas para criar repositório, modificar workflow e publicar releases.
- CI remoto funcional na branch principal.

## Ordem obrigatória

1. Rodar `python -m compileall -q src tests` e `python -m unittest discover -s tests -v` localmente.
2. Examinar e validar README, licença, configurações, exemplos, nenhum segredo/backup real versionado.
3. Publicar **somente após aprovação** do mantenedor em `felipewatter/restoregate` com descrição e topics apropriados.
4. Confirmar que o GitHub Actions iniciou na branch principal e aguardar os 12 jobs concluírem sem falhas. Em caso de falha, corrigir o código e repetir antes de release.
5. Após CI verde, executar **manualmente** o workflow `Release (manual, CI-gated)` em `main`, com `tag=v0.1.0`. O workflow verifica novamente testes e resultado do CI no mesmo SHA e cria tag/release com ZIP e SHA-256.
6. Validar link de release, artefatos, hash local e correspondência entre tag, branch e código aprovado.

Nenhum relatório local de testes deve ser apresentado como prova de CI remoto. Se o conector não tiver permissão de criação de repositório/release, utilizar `gh` após aprovação; jamais alegar publicação não executada.
