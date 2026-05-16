# abletonKeyGen - O que é isto?

Esta é uma implementação de código aberto do patch R2R e do `R2RLIVE.dll` do Ableton Live, escrita em Python.

Resolvi facilitar esse processo para as pessoas terem um acesso confiavel, e sem necessidade de gastar dinheiro como vejo todos em tutoriais do YouTube cobrando.

Fiz também um video explicativo, o link vai estar abaixo
[Youtube](https://www.youtube.com/watch?v=jcAoUUYkmOU)

Assim como o `R2RLIVE.dll`, este script usa apenas a chave de assinatura da Team R2R.

## Aviso

Este script não é resultado de engenharia reversa do Ableton Live, e a saída deste script **não** irá burlar a proteção de uma cópia **não modificada** do Ableton Live.

## Baixar Instaladores do Ableton

Você pode baixar os instaladores do Ableton diretamente dos servidores da Ableton. Existe um arquivo HTML do devilapi para facilitar isso para você.

[AbletonLinks](https://kassielm.github.io/AbletonLinks/)

## Compatibilidade

- Funciona no Windows e Linux (com wine)
- Deve funcionar para todas as versões do Ableton Live acima do Live 9 (9,10,11,12)
- Todas as edições também funcionam (Lite, Intro, Standard, Suite)

## Guia de Início Rápido

1. Encontre seu HWID do Ableton: Abra o Ableton e pressione "Authorize Ableton offline". Você encontrará seu HWID.
2. Clique com o botão direito em `quickstart.cmd` e selecione `Run as Administrator`.
3. Quando o script perguntar se você quer editar o arquivo de configuração, selecione `y`.
4. Você só precisará alterar as 3 variáveis do topo. Informe seu HWID, a versão e a edição do Live e **salve o arquivo (Ctrl+S)**
5. O script agora perguntará se você quer executar o patcher. Selecione `y`.
6. Selecione a instalação do Ableton que você deseja aplicar o patch
7. O script agora perguntará se você quer abrir a pasta onde `Authorize.auz` está localizado. Selecione `y`
5. Execute o Ableton e arraste o arquivo `Authorize.auz` para a janela de ativação

#### Viva, você terminou!

## Argumentos de Linha de Comando
| Parameter | Type | Description | Default/Config |
|-----------|------|-------------|----------------|
| `--undo` | flag | Reverter o patch (troca as signkeys e ignora o arquivo de autorização) | Usa os valores de config.json |
| `--file_path` | string | Caminho para o executável do Ableton Live ou "auto" para detecção automática | config.json: `file_path` |
| `--old_signkey` | string | Signkey antiga (string hex) | config.json: `old_signkey` |
| `--new_signkey` | string | Signkey nova (string hex) | config.json: `new_signkey` |
| `--hwid` | string | ID de hardware (24 caracteres hex ou 6 grupos de 4) | config.json: `hwid` |
| `--edition` | string | Edição do Ableton (Lite, Intro, Standard, Suite) | config.json: `edition` |
| `--version` | integer | Versão do Ableton (ex.: 12) | config.json: `version` |
| `--authorize_file_output` | string | Caminho de saída para Authorize.auz ou "auto" | config.json: `authorize_file_output` |
| `--config_file` | string | Caminho onde o arquivo de configuração está localizado. | `config.json` |
| `--help` | flag | Mostrar mensagem de ajuda | N/A |

## Solução de Problemas
#### Não tenho permissões de administrador no meu PC.
1. Copie seu executável do Ableton para a mesma pasta onde `patch_ableton.py` está localizado.
2. Em config.json, altere seu caminho de arquivo de "auto" para o novo caminho do seu executável do Ableton.
3. Tente novamente
4. Agora deve funcionar. Depois, copie seu executável do Ableton de volta para a pasta de onde ele veio.

## Créditos

A implementação do KeyGen foi feita por [rufoa](https://github.com/rufoa/ableton) Passa la pra dar uma moral.
