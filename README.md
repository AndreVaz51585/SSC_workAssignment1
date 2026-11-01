# SSC — Work Assignment 1

Streaming de vídeo MP4 com um canal autenticado e cifrado entre o proxy e o
servidor. O browser recebe a página e o vídeo por HTTP a partir do proxy.

```text
Browser -- HTTP --> Proxy -- protocolo seguro --> Stream Server
          :8080                                  :8082
```

Implementação em Kotlin/JVM, com JDK 21 e Gradle. O handshake usa segredos
previamente partilhados, DH efémero no grupo ffdhe2048 e HKDF-SHA256. Os registos
são protegidos por AES-GCM, ChaCha20-Poly1305 ou AES-CTR com HMAC, conforme o XML.
A proteção cobre o troço proxy–servidor; a ligação ao browser continua a usar HTTP.

## 1. Obter o projeto

```sh
git clone https://github.com/AndreVaz51585/SSC_workAssignment1.git
cd SSC_workAssignment1
```

Executar os comandos seguintes nesta pasta, onde estão `gradlew` e `compose.yaml`.

- Para executar com Docker: Docker com Compose.
- Para compilar ou executar os testes localmente: JDK 21. O Gradle Wrapper está incluído.
- Para preparar os segredos: OpenSSL e um editor de texto.

Os comandos assumem macOS/Linux. A primeira compilação precisa de Internet para
descarregar as dependências.

## 2. Preparar a configuração e os vídeos

Numa cópia limpa, criar os dois XML a partir dos templates. Para AES-256-GCM:

```sh
cp config/profiles/aes256-gcm/proxy.config.example config/profiles/aes256-gcm/proxy.config
cp config/profiles/aes256-gcm/server.config.example config/profiles/aes256-gcm/server.config
openssl rand -hex 32
```

Substituir `REPLACE_WITH_64_HEX_DIGITS` em `SKey` pelo valor gerado, nos dois ficheiros.
O proxy e o servidor usam a mesma PSK. Os restantes campos já estão preparados
para este perfil. Se os XML já estiverem preenchidos, não é necessário copiá-los de novo.

As chaves de tráfego são derivadas num novo handshake por pedido; não são a PSK
copiada para a sessão. Os XML privados são ignorados pelo Git. Os valores em
`src/test/resources/` são públicos e destinam-se exclusivamente aos testes.

Criar a pasta de media e colocar nela pelo menos um MP4 compatível com o browser:

```sh
mkdir -p media
```

Por exemplo, `media/sintel.mp4`, com vídeo H.264 e áudio AAC. Os vídeos não estão
incluídos no repositório. Nos comandos seguintes, substituir `sintel.mp4` pelo
nome do ficheiro utilizado.

## 3. Arrancar com Docker

```sh
docker compose up -d
```

Abrir http://localhost:8080/, escolher um vídeo e iniciar a reprodução. Testar também
o avanço e recuo na barra do vídeo.

```sh
docker compose ps
docker compose logs -f proxy
```

O Compose inicia `stream-server` e `proxy`. O proxy liga-se a `stream-server:8082`
na rede Docker. Só a porta 8080 do proxy é publicada no host. Os XML e os vídeos
são montados externamente, só para leitura.

Parar os serviços:

```sh
docker compose down
```

Depois de alterar código, reconstruir a imagem com `docker compose up -d --build`.
Depois de editar XML, usar `docker compose up -d --force-recreate` para recarregar
os ficheiros. Alterar os parâmetros criptográficos não exige recompilar ou
reconstruir a imagem. Se 8080 estiver ocupada, usar
`PROXY_PORT=8085 docker compose up -d` e abrir http://localhost:8085/.

## 4. Escolher outro perfil

Cada pasta em `config/profiles/` contém um template para o proxy e outro para o
servidor. Copiar ambos para `proxy.config` e `server.config`, como no passo 2,
e preencher os segredos com os tamanhos correspondentes:

| Pasta | SKey | MacKey | Tag dos registos |
| --- | --- | --- | --- |
| `aes128-gcm` | 16 bytes | — | 128 bits |
| `aes192-gcm` | 24 bytes | — | 128 bits |
| `aes256-gcm` | 32 bytes | — | 128 bits |
| `chacha20-poly1305` | 32 bytes | — | 128 bits |
| `aes128-ctr-hmac-sha256` | 16 bytes | 32 bytes | 256 bits |
| `aes192-ctr-hmac-sha256` | 24 bytes | 32 bytes | 256 bits |
| `aes256-ctr-hmac-sha256` | 32 bytes | 32 bytes | 256 bits |
| `aes256-ctr-hmac-sha384` | 32 bytes | 48 bytes | 384 bits |
| `aes256-ctr-hmac-sha512` | 32 bytes | 64 bytes | 512 bits |

Gerar cada segredo com `openssl rand -hex N`, onde N é o número de bytes da tabela.
Nos perfis CTR, gerar SKey e MacKey separadamente. Copiar a mesma SKey e a mesma
MacKey para os dois extremos do par. O hexadecimal tem dois caracteres por byte.

Para selecionar o par preparado, por exemplo:

```sh
CRYPTO_PROFILE=chacha20-poly1305 docker compose up -d --force-recreate
```

É utilizada a mesma imagem. Os processos reiniciam e leem os novos XML; as ligações
em curso são interrompidas. Para manter a escolha nos comandos seguintes, definir
`CRYPTO_PROFILE` num ficheiro `.env`, usando `.env.example` como referência.

O servidor confirma ou rejeita a proposta autenticada do proxy. Ambos têm de usar
configurações compatíveis e os mesmos segredos; não há negociação de listas ou
fallback automático. O conteúdo do XML seleciona o algoritmo, não o nome da pasta.

O carregamento rejeita XML malformado, DTD/entidades externas e campos inesperados.
A validação verifica combinações, tamanhos de chave, parâmetros e suporte no JDK
antes de abrir sockets. Os perfis usam `Padding=NULL/NoPadding` e `IV=NULL`, com
IVs/nonces geridos pelo protocolo. AEAD exige os campos MAC adicionais a NULL;
CTR exige HMAC e uma MacKey independente.

## 5. Executar os testes

Com JDK 21, sem arrancar Docker nem preparar XML privados ou vídeos:

```sh
./gradlew test --console=plain
```

Os testes usam configurações públicas e dados temporários. O relatório HTML fica
em `build/reports/tests/test/index.html`. Incluem vetores criptográficos conhecidos,
validação XML, codecs, handshake, proteção dos registos e integração HTTP nos nove
perfis, com verificação dos bytes recebidos e dos estados HTTP.

Só os cenários de atacante:

```sh
./gradlew test --tests 'ssc.adversarial.adversarialTest' --console=plain
```

Os ataques são representados nos testes Kotlin: um filtro altera os frames antes
de os entregar pelo socket ao recetor. O código de receção e validação é o mesmo
da aplicação. Não é necessário modificar o código de produção ou usar scripts externos.

| Casos | O que é alterado | Resultado esperado |
| --- | --- | --- |
| C0 | Nenhuma alteração; participantes com configuração correta | Conteúdo recebido igual ao original |
| A1 | PSK incorreta ou MacKey incorreta em CTR | Handshake rejeitado |
| A2 | Proposta, pública DH, tags, random ou ordem do handshake | Mensagem rejeitada; servidor não inicia o stream |
| A3 | Ciphertext, tag DATA ou metadados | Registo adulterado não é encaminhado |
| A4 | DATA repetido ou mensagem 2/3 de outra sessão | Sequência ou contexto de sessão rejeitado |
| A5 | Remoção ou troca de ordem de DATA | Sequência inesperada; resposta incompleta |
| A6 | END removido ou adulterado | Transferência não termina com sucesso |
| A7 | Comprimento excessivo, header incompleto ou tipo desconhecido | Erro de framing; comprimento excessivo rejeitado antes de alocar o payload |

Um teste negativo passa quando a operação inválida é rejeitada. No HTML é possível
abrir a classe `adversarialTest` e consultar os 22 métodos separadamente.
Uma execução filtrada gera apenas o relatório desse subconjunto; executar de novo
`./gradlew test --console=plain` para obter o relatório completo.

## 6. Validar a reprodução e as métricas

Com Docker ativo, abrir três janelas em http://localhost:8080/, selecionar vídeos
e iniciar a reprodução em simultâneo. As três janelas usam o mesmo proxy. Procurar
outra posição num vídeo deve continuar a permitir a reprodução nas restantes janelas.

Para comparar uma transferência completa com o ficheiro original:

```sh
mkdir -p build
curl --fail http://localhost:8080/video/sintel.mp4 -o build/received.mp4
shasum -a 256 media/sintel.mp4 build/received.mp4
docker compose logs --no-log-prefix --tail 4 proxy
```

Os hashes devem coincidir. Em Linux pode usar-se `sha256sum`. Para uma transferência
completa, o log deve indicar `[STREAM OK]`, HTTP 200, volume encaminhado igual ao
comprimento esperado e o mesmo número de blocos DATA autenticados e encaminhados.

Para verificar um intervalo de 1024 bytes:

```sh
curl --fail --silent --show-error --dump-header build/range-headers.txt \
  --range 0-1023 http://localhost:8080/video/sintel.mp4 -o build/range.bin
cat build/range-headers.txt
wc -c < build/range.bin
```

Esperado: HTTP 206, `Content-Length: 1024` e `Content-Range: bytes 0-1023/TOTAL`,
onde TOTAL é o tamanho original. O ficheiro recebido deve ter 1024 bytes.

Os logs mostram volume encaminhado/esperado, tamanho original, blocos DATA
autenticados/encaminhados, volume do protocolo, duração e MB/s. O volume do protocolo
inclui frames, sequências, tags, metadados e END; exclui handshake e TCP/IP.
A duração começa após o handshake e inclui leitura, autenticação, decifragem e
escrita para o browser. kB e MB são decimais; throughput = bytes encaminhados / duração.

Um `Broken pipe` pode resultar de o browser cancelar um pedido ao fazer seek.
Os contadores podem diferir numa interrupção: um bloco pode ter sido autenticado
sem a escrita para o browser terminar. O recetor mantém um bloco pendente até
validar o seguinte ou END. Estes contadores não representam pacotes TCP.

Para obter contagens exatas em vez dos valores arredondados:

```sh
METRICS_FORMAT=detailed docker compose up -d --force-recreate
docker compose logs --no-log-prefix proxy
```

Para regressar ao resumo, repetir o primeiro comando com `METRICS_FORMAT=summary`.
Distinguir downloads completos, ranges e cancelamentos ao comparar resultados.

### Várias instâncias do proxy

Para executar proxies independentes contra o mesmo servidor, manter o Compose
normal ativo e iniciar cada proxy adicional num terminal separado:

```sh
# Segundo proxy: porta 8085 do host.
docker compose run --rm --publish 8085:8080 proxy
```

```sh
# Terceiro proxy: porta 8086 do host.
docker compose run --rm --publish 8086:8080 proxy
```

Abrir http://localhost:8080/, http://localhost:8085/ e http://localhost:8086/ e
reproduzir vídeos diferentes em simultâneo. Aguardar a mensagem de arranque de
cada proxy antes de abrir a página. Cada container tem o seu próprio processo,
sockets e sessões; todos usam `stream-server:8082`. A porta interna 8080 pode ser
igual porque os containers são distintos. Se o perfil foi alterado, manter a mesma
configuração `.env` ou variável `CRYPTO_PROFILE` nas três invocações.

Ctrl+C termina cada proxy adicional. `docker compose down` termina os dois serviços
normais. As janelas na mesma porta e os processos em portas diferentes permitem
verificar, respetivamente, vários clientes e várias instâncias do proxy.

## 7. Compilar e executar sem Docker

```sh
./gradlew build
```

Servidor, no primeiro terminal:

```sh
./gradlew run --args="secure-server 8082 media config/profiles/aes256-gcm/server.config"
```

Proxy, no segundo:

```sh
./gradlew run --args="secure-proxy 8080 localhost 8082 config/profiles/aes256-gcm/proxy.config"
```

Parar os containers que ocupem as mesmas portas antes de arrancar os processos
locais. Para mudar de perfil, parar os processos e indicar outro par de XML.

### Executar em duas máquinas

Nas duas máquinas, com JDK 21 e uma cópia do projeto:

```sh
./gradlew installDist
```

Preparar um par de XML compatível, com os mesmos segredos. A máquina do servidor
precisa dos vídeos e de `server.config`; a do proxy precisa de `proxy.config`.
Transferir os segredos por um canal de confiança. Apenas o servidor precisa da pasta media.

Na máquina A, executar o servidor:

```sh
build/install/SSC_workAssignment/bin/SSC_workAssignment secure-server 8082 media config/profiles/aes256-gcm/server.config
```

Na máquina B, substituir `192.168.1.20` pelo endereço acessível de A:

```sh
build/install/SSC_workAssignment/bin/SSC_workAssignment secure-proxy 8080 192.168.1.20 8082 config/profiles/aes256-gcm/proxy.config
```

Permitir TCP 8082 de B para A na rede/firewall. Em B, abrir http://localhost:8080/.
Num terceiro computador, usar o endereço de B e permitir acesso à sua porta 8080.
Verificar reprodução, seek e uma transferência completa, comparando o SHA-256 com
o original em A. `localhost` identifica sempre a máquina onde o processo corre.

## 8. Baseline e organização do código

A baseline sem proteção continua disponível. Executar em terminais separados,
sem outros processos a ocupar as mesmas portas:

```sh
./gradlew run --args="server 8081 media"
./gradlew run --args="proxy 8080 localhost 8081 0"
```

O último argumento desativa o atraso artificial de 2000 ms/read da referência.
O código Java fornecido está preservado em `reference/WA1-Materials/`.

| Componente | Responsabilidade |
| --- | --- |
| `SecureProxyServer` / `SecureStreamServer` | Sockets, pedidos e integração com o stream |
| `CryptoConfigLoader` / validadores | Leitura do XML e validação antes do arranque |
| `ProxyHandshake` / `ServerHandshake` | Autenticação, proposta/confirmação e estabelecimento da sessão |
| `HandshakeKeySchedule` / `MessageProtection` | Derivação de chaves e proteção AEAD ou Encrypt-then-MAC |
| Codecs em `ssc/protocol` | Representação binária de headers e payloads |
| `SecureStreamSender` / `SecureStreamReceiver` | Metadados, DATA, sequência e END |
| `SecureMediaSource` / `MediaRanges` | Seleção de ficheiros e intervalos de bytes |
| `StreamMetrics` | Contagens, volumes, duração e throughput |

O protocolo usa Types 1/2/3 no handshake, Type 4 para metadados e DATA protegidos,
Type 5 para END e Type 255 para alertas do handshake. As públicas DH, randoms,
tags, Range e metadados complementam os campos de referência. Cada pedido cria
uma sessão nova; cada registo é associado à sua sequência e ao contexto da sessão.
