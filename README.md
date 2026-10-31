# SSC — Work Assignment 1

Streaming de ficheiros MP4 entre um servidor e um proxy, com um canal autenticado
e cifrado. O browser recebe o vídeo por HTTP a partir do proxy.

Implementação em Kotlin/JVM, com JDK 21 e Gradle. Suporta AES-GCM,
ChaCha20-Poly1305 e AES-CTR com HMAC, selecionados por XML.

## 1. Obter o projeto

```sh
git clone https://github.com/AndreVaz51585/SSC_workAssignment1.git
cd SSC_workAssignment1
```

Executar os comandos seguintes nesta pasta, onde estão `gradlew` e `compose.yaml`.
Para arrancar com Docker basta Docker com Compose. Para compilar ou executar os
testes fora de Docker é necessário JDK 21; o Gradle Wrapper está incluído.
A primeira compilação precisa de acesso à Internet para descarregar dependências.
Os comandos assumem um terminal macOS/Linux. A preparação dos segredos usa OpenSSL
e um editor de texto para preencher os XML.

## 2. Preparar a configuração e o vídeo

Numa cópia limpa, os XML privados ainda não existem. Para começar com AES-256-GCM:

```sh
cp config/profiles/aes256-gcm/proxy.config.example config/profiles/aes256-gcm/proxy.config
cp config/profiles/aes256-gcm/server.config.example config/profiles/aes256-gcm/server.config
openssl rand -hex 32
```

Guardar o valor gerado no campo `SKey` dos **dois** ficheiros, substituindo
`REPLACE_WITH_64_HEX_DIGITS`. Usar o mesmo valor no proxy e no servidor.
Os restantes campos destes templates já estão preparados para este perfil.
Se os ficheiros já estiverem configurados, não é necessário voltar a copiá-los.

A SKey é o segredo inicial partilhado (PSK). As chaves de tráfego são derivadas
num novo handshake com DH; não são simplesmente a PSK copiada para cada sessão.
Os XML privados são ignorados pelo Git. Os ficheiros em `src/test/resources/`
contêm valores públicos exclusivamente para testes.

Colocar pelo menos um MP4 compatível com o browser diretamente em `media/`.
Por exemplo, `media/sintel.mp4`, com vídeo H.264 e áudio AAC. Os vídeos não estão
incluídos no repositório. Nos comandos abaixo, substituir `sintel.mp4` pelo nome
real do ficheiro utilizado.

## 3. Arrancar com Docker

```sh
docker compose up -d
```

Abrir http://localhost:8080/, escolher um vídeo e iniciar a reprodução. Testar também
avanço/recuo na barra do vídeo.

```sh
docker compose ps
docker compose logs -f proxy
```

O Compose inicia `stream-server` e `proxy`. A ligação segura usa
`stream-server:8082` dentro da rede Docker. Só a porta 8080 do proxy é publicada.
Os vídeos e os XML são montados externamente, só para leitura.

Parar a aplicação:

```sh
docker compose down
```

Depois de alterar código, reconstruir a imagem com `docker compose up -d --build`.
Depois de editar XML, usar `docker compose up -d --force-recreate` para recarregar
os ficheiros. A alteração de parâmetros criptográficos não exige reconstrução.
Se 8080 estiver ocupada, usar `PROXY_PORT=8085 docker compose up -d` e abrir 8085.

## 4. Escolher outro perfil

Preparar os dois XML da pasta pretendida e executar, por exemplo:

```sh
CRYPTO_PROFILE=chacha20-poly1305 docker compose up -d --force-recreate
```

Existem nove pares de exemplo: AES-GCM com 128/192/256 bits, ChaCha20-Poly1305,
AES-CTR com 128/192/256 bits e HMAC-SHA256, e AES-CTR-256 com HMAC-SHA384/512.
Os perfis CTR precisam também de um MacKey independente, igual nos dois peers.
Tamanhos e comandos de preparação: [config/README.md](config/README.md).

Ambos os lados têm de confirmar a mesma configuração e possuir os mesmos segredos.
O servidor aceita ou rejeita a proposta do proxy; não há seleção entre listas nem
fallback automático. Os algoritmos suportados constam do catálogo da implementação.

## 5. Executar os testes

Com JDK 21, sem precisar de arrancar Docker nem preparar XML privados ou vídeos:

```sh
./gradlew test
```

Os testes usam configurações públicas e dados temporários. O relatório HTML fica em
`build/reports/tests/test/index.html`.

Só os cenários de atacante:

```sh
./gradlew test --tests 'ssc.adversarial.adversarialTest' --console=plain
```

A classe contém C0 (transferência autorizada) e casos separados para segredos
incorretos, substituição DH, alteração, replay, remoção, reordenação, truncamento e
mensagens malformadas. Um teste negativo passa quando a operação inválida é
rejeitada segundo as verificações do caso. Os testes não atacam serviços externos.

Guia dos casos e resultados esperados: [matriz de ameaças](docs/matriz-ameacas.md).
Uma execução filtrada gera apenas o relatório desse subconjunto; executar novamente
`./gradlew test` para obter o relatório da suite completa.

## 6. Validação manual e métricas

Abrir três janelas do browser e reproduzir vídeos simultaneamente valida clientes
concorrentes no mesmo proxy. A validação manual já confirmada está em
[validacao-manual.md](docs/validacao-manual.md). Isto não corresponde a três
processos distintos de proxy.

Para executar um segundo proxy contra o mesmo servidor Docker, manter o Compose
normal ativo e, noutro terminal, executar:

```sh
docker compose run --rm --publish 8085:8080 proxy
```

Abrir 8080 e 8085 em browsers, selecionar vídeos diferentes e observar a reprodução
simultânea. Aguardar a mensagem de arranque do segundo proxy antes de abrir 8085.
Ctrl+C termina o segundo proxy; `docker compose down` termina o conjunto
normal. Usar os mesmos valores de CRYPTO_PROFILE nas duas invocações se mudaram do
default. O resultado deste cenário deve ser registado quando for efetivamente testado.

Os logs mostram o resultado de cada transferência, volume encaminhado/esperado,
tamanho original, blocos autenticados/encaminhados, volume do protocolo, duração e
MB/s. Um Broken pipe pode resultar de o browser cancelar um pedido ao fazer seek;
a transferência fica marcada como interrompida.

Para comparar uma transferência completa com o original:

```sh
mkdir -p build
curl --fail http://localhost:8080/video/sintel.mp4 -o build/received.mp4
shasum -a 256 media/sintel.mp4 build/received.mp4
```

Os dois hashes devem coincidir. Em Linux pode usar-se `sha256sum`.
Para obter contagens exatas em vez dos valores arredondados do resumo:

```sh
METRICS_FORMAT=detailed docker compose up -d --force-recreate
docker compose logs --no-log-prefix proxy
```

Para regressar ao resumo, repetir o primeiro comando com `METRICS_FORMAT=summary`.
A duração do proxy começa após o handshake e inclui leitura, autenticação,
decifragem e escrita para o browser. kB e MB são decimais. Distinguir downloads
completos, ranges e cancelamentos ao comparar resultados.

Definições dos campos: [stream-metrics.md](docs/stream-metrics.md).
Procedimentos de medição: [performance.md](docs/performance.md).

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

Parar o proxy Docker antes de usar a mesma porta 8080. Os caminhos indicados são
explícitos porque os XML privados dos comandos por omissão não existem num clone.

Para executar sem invocar Gradle em cada arranque:

```sh
./gradlew installDist
build/install/SSC_workAssignment/bin/SSC_workAssignment secure-server 8082 media config/profiles/aes256-gcm/server.config
```

O launcher aceita os mesmos argumentos. Para o sistema distribuído em dois
computadores, substituir `localhost` pelo endereço do servidor e seguir
[as instruções de execução distribuída](docs/secure-browser.md#run-on-two-physical-machines).

## 8. Baseline e documentação do protocolo

A baseline sem proteção continua disponível. Executar em terminais separados:

```sh
./gradlew run --args="server 8081 media"
./gradlew run --args="proxy 8080 localhost 8081 0"
```

O último argumento desativa o atraso artificial de 2000 ms/read da referência.
Evitar conflitos de portas com a execução segura. O código Java fornecido está
preservado em `reference/WA1-Materials/`.

O protocolo usa Types 1/2/3 para o handshake, Type 4 para metadados/dados protegidos,
Type 5 para END e Type 255 para alertas. A serialização binária, os campos DH/random
adicionais e os subtipos de Type 4 são decisões documentadas da implementação.

- [Handshake e derivação de chaves](docs/handshake.md)
- [Streaming e integração HTTP/Range](docs/secure-browser.md)
- [Configuração e proteção AEAD/Encrypt-then-MAC](docs/crypto-profiles.md)
- [Modelo de ameaças e evidência](docs/threat-model.md)
- [Detalhes da execução Docker](docs/docker.md)
