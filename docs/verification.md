# Verificación — Cómo demostrar que el trabajo funciona

> Regla de oro: **el agente no dice "funciona", lo demuestra**.
> Toda feature termina con evidencia ejecutable, no con afirmaciones.

## Niveles de verificación

### Nivel 0 — Documentación de código (obligatorio)

```bash
cargo doc --no-deps
```

Todo ítem público sin rustdoc (`///`) es motivo de `CHANGES_REQUESTED` en
revisión, no solo un nice-to-have.

### Nivel 1 — Tests unitarios (obligatorio)

Toda función pública de lógica pura (`domain`, `parser`, `config`) tiene al
menos un test que:

1. Cubre el camino feliz.
2. Cubre al menos un camino de error si la función puede fallar.

Comando:
```bash
cargo test
```

### Nivel 2 — Lints y formato (obligatorio)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Ningún warning de clippy se ignora en silencio; si es un falso positivo,
se documenta con `#[allow(...)]` y un comentario explicando por qué.

### Nivel 3 — Tests de integración (obligatorio para ssh, scanner, repository, messaging)

- `ssh`/`scanner`: contra un contenedor Docker con `sshd` levantado vía el
  crate `testcontainers` en el propio test. Nunca contra una IP real fuera de
  un laboratorio controlado — ver `docs/security-scope.md`.
- `repository`: contra el contenedor MongoDB oficial levantado vía
  `testcontainers`, nunca contra `db-nmap` de producción.
- `parser`: contra fixtures de XML real guardadas en `tests/fixtures/`, no
  contra XML inventado a mano que no representa la salida real de `nmap`.
- Todo test de esta categoría se marca `#[ignore = "requiere Docker"]` (ver
  `docs/conventions.md`), se ejecuta con `cargo test -- --ignored`, y
  requiere Docker disponible (local o en CI). Si falla por falta de Docker,
  se documenta como bloqueo en `progress/current.md` — no se reemplaza por
  un mock.

### Nivel 4 — Smoke test end-to-end (obligatorio para la feature `scan_pipeline_wiring`, opcional para el resto)

Ejecuta el pipeline completo (`consumer -> ssh -> scanner -> parser ->
repository -> publisher`) contra los stubs/servidores de prueba locales y
verifica que un `ScanRequest` válido termina publicando un `ScanResult`.

## Anti-patrones (no hacer)

- ❌ "Añadí el parser, debería funcionar." → falta test ejecutable con
  fixture real.
- ❌ Test que solo verifica que la función no devuelve `Err`. → tiene que
  comprobar el contenido concreto del resultado.
- ❌ Probar `ssh`/`scanner` contra una IP real, propia o ajena, fuera de un
  entorno de laboratorio explícitamente autorizado.
- ❌ Silenciar un warning de `clippy` con `#[allow(...)]` sin comentario.
- ❌ Marcar la feature como `done` sin pasar `./init.sh`.

## Verificación final antes de cerrar

```bash
./init.sh           # debe terminar con [OK] Entorno listo
```

Si `./init.sh` está rojo, **no** marques nada como `done`. Anota el bloqueo
en `progress/current.md` y pon `"status": "blocked"` en `feature_list.json`.
