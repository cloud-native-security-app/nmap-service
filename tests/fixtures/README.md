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
