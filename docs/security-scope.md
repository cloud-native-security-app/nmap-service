# Alcance de seguridad y autorización

> `nmap-service` (`ms-nmap`) es una herramienta ofensiva real: se conecta por
> SSH a máquinas de terceros y ejecuta escaneo activo de puertos, servicios y
> vulnerabilidades. Este documento define los límites duros que aplican tanto
> al desarrollo (tests, ejemplos, datos de prueba) como al diseño del propio
> servicio. No es un documento legal — es la guía práctica que un agente de
> código debe seguir antes de tocar cualquier feature relacionada con SSH o
> escaneo.

## Alcance autorizado

- `ms-nmap` **solo** escanea el objetivo (IP + usuario de red) que llega en un
  `ScanRequest` válido a través del Broker — nunca un objetivo hardcodeado,
  inventado, ni "solo para probar".
- La autorización del objetivo (que el usuario final tiene permiso sobre esa
  IP/red) se asume ya verificada aguas arriba (Gateway / Identity Provider /
  `ms-usuarios`) antes de que el mensaje llegue al Broker. `ms-nmap` no
  reimplementa esa verificación, pero tampoco debe escanear nada que no venga
  acompañado de un `ScanRequest`.
- Si en algún momento se necesita que `ms-nmap` también valide el objetivo
  (allowlist de rangos IP, confirmación explícita, etc.), eso es una decisión
  de producto que se discute con el usuario y se documenta como una feature
  nueva en `feature_list.json` — no se improvisa dentro de otra feature.

## Desarrollo y tests

- **Nunca** se escanea, ni en un test ni en un ejemplo, una IP real fuera de
  un laboratorio explícitamente controlado por quien desarrolla (VM propia,
  contenedor local, red aislada). Nunca una IP de terceros, ni pública, ni
  "solo para ver si funciona".
- Los tests de `ssh` y `scanner` corren contra un servidor SSH de prueba
  local (contenedor o servidor embebido para tests), no contra infraestructura
  real.
- Los fixtures de XML de `nmap` en `tests/fixtures/` deben venir de escaneos
  hechos contra objetivos de laboratorio propios, no contra terceros.

## Credenciales y secretos

- Las credenciales SSH (`ssh_credentials_ref` en `ScanRequest`) se tratan como
  secreto en todo momento: nunca se escriben en logs (`tracing`), nunca en
  mensajes de error, nunca se persisten en texto plano en MongoDB.
- La configuración (`src/config.rs`) lee credenciales/tokens desde variables
  de entorno o un gestor de secretos — nunca hardcodeadas en el repo.

## Identidad del objetivo (host key SSH)

- La conexión SSH usa Trust On First Use (TOFU): la primera vez que se
  conecta a un host se guarda su fingerprint; si en una conexión posterior el
  fingerprint no coincide, la conexión se **rechaza** (no se continúa "por si
  acaso" ni se loggea solo como advertencia).
- Nunca se debe deshabilitar la verificación de host key para "hacerlo
  funcionar más rápido" durante desarrollo — eso reabre exactamente el riesgo
  de MITM que TOFU busca mitigar.

## Escalación de privilegios (sudo)

- `nmap -O` y otros scripts que requieren root remoto **solo** se ejecutan si
  `ScanRequest.has_sudo` lo indica explícitamente, usando `sudo -n`
  (no interactivo). Nunca se intenta adivinar o forzar privilegios que no
  fueron declarados en la solicitud.

## Límite de las capacidades de escaneo

- `ms-nmap` hace **detección**: descubrimiento de puertos, servicios,
  versiones y NSE de categoría `vuln` (detección pasiva de vulnerabilidades
  conocidas). No incluye módulos de explotación activa (fuerza bruta,
  payloads, scripts NSE de categoría `exploit`/`intrusive` que puedan alterar
  o dañar el objetivo).
- Si una futura feature requiere explotación activa, se documenta y discute
  explícitamente con el usuario antes de implementarse — no se añade como
  efecto secundario de otra feature.

### Enriquecimiento de vulnerabilidades (Exploit-DB, feature `vuln_enrichment`)

- Tras el escaneo, `ms-nmap` cruza el `service`+`version` de cada puerto
  detectado contra el CSV `files_exploits.csv` de Exploit-DB y añade
  `VulnFinding`s (`source: exploit_db`). Es **detección pasiva**: buscar
  exploits/CVE *conocidos* para versiones ya detectadas, la misma categoría que
  `nmap --script vuln`. **No ejecuta exploits.**
- El adaptador `ExploitDbEnricher` es un **lookup local sin egress de red**: el
  CSV se bundlea en la imagen (pineado a un commit), se indexa en memoria al
  arrancar y todas las consultas se resuelven localmente. No contacta a
  Exploit-DB ni a ninguna API en tiempo de ejecución.
- El matcher es deliberadamente conservador para no inundar el informe de falsos
  positivos, pero los falsos positivos siguen siendo un riesgo conocido: los
  hallazgos `exploit_db` son pistas a verificar, no confirmaciones.
- Los **adaptadores de API futuros** (NVD, Vulners, ...) sí harían egress de red
  (HTTP saliente + posible caché en Mongo). Cuando se implementen se añadirá aquí
  su análisis de alcance (a qué endpoints se conecta, qué datos se envían — sólo
  producto/versión/CPE, nunca IP del objetivo ni credenciales); hoy no existen.
- La intensidad de escaneo (`-T`) usa un valor por defecto conservador para
  minimizar el riesgo de degradar el servicio del objetivo (evitar
  timing agresivo tipo `-T4`/`-T5` como default).

## Si algo no está claro

Si una feature de `feature_list.json` roza alguno de estos límites y no está
claro cómo proceder, el agente **para y pregunta al usuario** en vez de
asumir qué está autorizado — igual que cualquier otro bloqueo, se documenta
en `progress/current.md`.
