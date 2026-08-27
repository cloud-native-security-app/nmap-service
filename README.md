# nmap-service

`ms-nmap`: microservicio de escaneo dentro de una plataforma de
ciberseguridad blue/red team. Recibe una solicitud de escaneo (IP, usuario de
red y permisos) a través del Broker, se conecta por SSH al objetivo, ejecuta
`nmap` para detectar puertos abiertos, servicios, versiones y
vulnerabilidades, persiste el resultado en MongoDB (`db-nmap`) y lo publica
de vuelta hacia el Broker para que otro servicio (`ms-analisis`) genere el
informe final con IA.

Este repo implementa **únicamente** `ms-nmap`. `ms-usuarios`, `ms-analisis`,
el Gateway y el Broker viven en otros repos.

Stack: Rust (async con `tokio`), persistencia en MongoDB, tests de
integración con `testcontainers`.

## Desarrollo

El repositorio se desarrolla guiado por agentes de IA sobre un arnés
documental (`AGENTS.md`, `feature_list.json`, `docs/`, `CHECKPOINTS.md`).
Antes de tocar código, lee `CLAUDE.md`.
