# Fixtures de XML de `nmap` para `parser`

> `docs/security-scope.md` (§Desarrollo y tests): los fixtures de XML de `nmap`
> deben venir de escaneos hechos contra **objetivos de laboratorio propios**
> (contenedores locales en una red Docker aislada), nunca contra terceros. Todos
> los archivos de esta carpeta se generaron así el 2026-08-27. Ninguno se editó
> a mano salvo donde se indica explícitamente abajo.

## Laboratorio usado

- Red Docker aislada `nmaplab` (bridge local, sin exposición de puertos al host).
- Escáner: imagen `instrumentisto/nmap` (Nmap 7.98), ejecutada dentro de esa red.
- Objetivos (contenedores locales desechables):
  - `tgt-ssh` = `lscr.io/linuxserver/openssh-server:version-9.9_p2-r0` (IP 172.18.0.2)
  - `tgt-web` = `httpd:2.4.49` (IP 172.18.0.3)
  - `tgt-msf` = `tleemcjr/metasploitable2` (IP 172.18.0.4) — imagen de laboratorio
    de vulnerabilidades conocida (Metasploitable 2), la usa la propia
    documentación de Nmap/Metasploit como banco de pruebas.
  - 172.18.0.252 / .253 = IPs sin asignar dentro de `nmaplab` (host caído).
  - 10.99.99.99 = IP sin asignar dentro de una segunda red aislada `nmaplab2`
    (con `-Pn` nmap la marca `up` y sus puertos quedan `filtered` / `open|filtered`
    por falta de respuesta).

Todos los contenedores y la red se destruyeron al terminar de generar los
fixtures.

## Archivos

| Archivo | Comando (dentro de `nmaplab`) | Qué cubre |
|---|---|---|
| `open_ports_service_version.xml` | `nmap -sV -Pn -p 2222,22,80 -oX - tgt-ssh` | host up, puerto abierto con servicio+versión (`OpenSSH 9.9`, `protocol 2.0`), puertos cerrados |
| `no_open_ports.xml` | `nmap -Pn -p 21,23,25,110,143 -oX - tgt-ssh` | host up sin ningún puerto abierto (todos `closed`) |
| `filtered_ports.xml` | `nmap -sS -sU -Pn -p T:22,80,U:53,161 -oX - 10.99.99.99` (red `nmaplab2`) | puertos TCP en `filtered` y puertos UDP en `open|filtered` (multi-estado, TCP+UDP en un mismo `<host>`) |
| `host_down.xml` | `nmap -v -p 22 -oX - 172.18.0.253` | `<host>` presente con `status state="down"` |
| `no_host_element.xml` | `nmap -p 22 -oX - 172.18.0.252` | escaneo válido de un objetivo caído: `<nmaprun>` sin ningún `<host>` |
| `multiple_hosts.xml` | `nmap -v -p 22,2222 -oX - 172.18.0.253 172.18.0.2` | `<nmaprun>` con dos `<host>` (uno down, uno up) |
| `vuln_findings.xml` | `nmap -sV --script vuln -p 21,6667 -oX - tgt-msf` | hallazgos de `--script vuln`: `ftp-vsftpd-backdoor` (estado NSE `VULNERABLE (Exploitable)`, `CVE-2011-2523`) y `vulners` (lista de CVEs con CVSS); `irc-unrealircd-backdoor` sólo devuelve un error de conexión (no es hallazgo) |

Ningún fixture fue recortado ni modificado. Son la salida `-oX` literal de Nmap
7.98.

## `exploitdb_sample.csv` — fixture del enricher de Exploit-DB (feature 13)

CSV pequeño (20 filas de datos + cabecera) para los tests de
`nmap_service::enrichment::ExploitDbEnricher`. **Todas las filas son reales**:
se extrajeron literalmente (sin editar ni un carácter) de
`/usr/share/exploitdb/files_exploits.csv` del paquete `exploitdb` instalado en la
máquina de desarrollo, seleccionando por la primera columna (`id` / EDB-ID):

```sh
ids="16929 19046 49757 17491 16270 5814 49719 16922 13853 27407 \
     18011 40136 40888 39569 45939 42060 16320 37262 50383 14611"
{ head -1 files_exploits.csv; \
  for i in $ids; do awk -F, -v id="$i" '$1==id' files_exploits.csv; done; } \
  > exploitdb_sample.csv
```

La cabecera es la del CSV oficial:
`id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url`.

Cobertura buscada:

- `vsftpd 2.3.4` → EDB 49757 (`codes = CVE-2011-2523`) y EDB 17491
  (`codes = OSVDB-73573;CVE-2011-2523`, para probar la extracción del primer CVE
  cuando hay códigos no-CVE por delante). Es el servicio del puerto 21 de
  `vuln_findings.xml`.
- `UnrealIRCd 3.2.8.1` → EDB 16922 y 13853 (`CVE-2010-2075`), EDB 27407
  (`UnrealIRCd 3.x`, `CVE-2006-1214`) y EDB 18011 (`codes = OSVDB-83430`, sin
  CVE → `VulnFinding.id = None`). Es el servicio del puerto 6667 de
  `vuln_findings.xml`; nmap no reporta versión para él, así que el enricher
  matchea sólo por tokens.
- `vsftpd 2.3.2` / `2.0.5` / `3.0.3` → casos de versión que NO debe casar con
  `2.3.4` (uno de ellos, EDB 49719, con `codes` vacío).
- `OpenSSH 7.2*`, `Samba`, `ProFTPd 1.3.5`, `Apache 2.4.49`, entradas AIX y
  Windows → ruido realista / casos de "sin match".
