# Política de segurança

## Divulgação responsável

Não envie provas de conceito sensíveis, arquivos de backup reais ou segredos em issues públicas. Para suspeitas de vulnerabilidade, use **Report a vulnerability** na aba Security do repositório, se disponível, ou entre em contato privadamente com o mantenedor por um canal confiável definido no perfil GitHub [@felipewatter](https://github.com/felipewatter).

Inclua uma descrição reproduzível **apenas com arquivos sintéticos**, versão do Python, SO, impacto técnico, comportamento esperado e resultado observado. Não compartilhe dados de clientes nem caminhos internos.

## Escopo de suporte

| Versão | Estado |
| --- | --- |
| `0.1.x` | Linha inicial de manutenção, após sua publicação |
| versões anteriores | Não existentes |

## Recomendações para operadores

- Execute a inspeção como usuário sem privilégios, com rede desabilitada quando possível.
- Use limites de recursos e VM/container para arquivos recebidos de terceiros.
- Não armazene backups em diretórios públicos nem anexe relatórios sensíveis em issues.
- Valide a procedência do arquivo de backup por controles externos confiáveis.
