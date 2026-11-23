# Arquitectura

```
cmd/repoguard/      CLI: opciones, local o GitHub, códigos de salida
internal/rules/     reglas por línea: patrón, palabras clave, gravedad y por qué importa
internal/scan/      recorrido concurrente, binarios, ocultamiento, Unicode, analizadores por archivo,
                    correlación y ajuste por contexto
internal/remote/    validar el nombre del repo y clonarlo de forma segura
internal/report/    texto (agrupado), JSON y SARIF 2.1.0
internal/finding/   tipo Finding, veredicto y recorte seguro de la evidencia
```

## Decisiones

**Nunca ejecutar.** Es la regla central. Ni siquiera se usan herramientas del ecosistema analizado
(`npm`, `pip`) para leer metadatos: `package.json` se interpreta con `encoding/json`.

**Señales, no firmas.** En lugar de buscar hashes de malware conocido (que cambian en cada versión), se
buscan comportamientos: descargar y ejecutar, esconder código, leer credenciales, mandar datos afuera.

**Correlación por archivo.** Leer `~/.aws/credentials` puede ser legítimo (una herramienta de nube) y usar
un webhook de Discord también (notificaciones). Las dos cosas juntas en el mismo archivo son el patrón de
un ladrón de credenciales, y ahí la gravedad sube a crítica. Solo cuentan accesos reales, no menciones.

**Contexto antes que volumen.** Cada ajuste está escrito en la propia señal ("aparece en un comentario",
"corre en CI, no en tu máquina"), así el usuario entiende por qué tiene ese nivel.

**Sin supresiones en el repo analizado.** A diferencia de un linter, el autor del código revisado es
potencialmente el atacante: por eso no hay comentarios del estilo `repoguard:allow`. Quien usa la
herramienta puede excluir rutas con `--exclude`.

## Escala de gravedad

| Gravedad | Cuándo |
|---|---|
| Crítica | Comportamiento malicioso casi sin explicación legítima, o una combinación que lo es |
| Alta | Comportamiento muy usado por malware, pero con usos legítimos posibles |
| Media | Práctica riesgosa o señal débil |
| Baja / info | Contexto: menciones, documentación, pruebas |
