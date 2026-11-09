# Evidencias de ejecución

Medición realizada: 2026-11-09T00:29:54+00:00 (UTC).

Se ejecutó el cliente de pruebas de Flask con una base SQLite y logs en un directorio temporal.
Cada escenario produjo tres solicitudes HTTP fallidas y una ejecución real del detector.
La respuesta fue un bloqueo simulado confirmado automáticamente; los tiempos son diferencias entre marcas reales del reloj, no valores inventados.
Los archivos temporales con usuarios, hash y eventos no se publican.

## Validación y autenticación

| Comprobación | Estado HTTP observado |
| --- | ---: |
| Registro válido | 201 |
| Usuario inválido | 400 |
| Correo inválido | 400 |
| Contraseña corta | 400 |
| Usuario duplicado | 409 |
| Correo duplicado | 409 |
| Hash distinto de la clave y verificable con Werkzeug | Sí |
| Eventos observados (9 fallidos, 3 correctos) | 12 |
| Respuestas USUARIO_BLOQUEADO registradas | 3 |

## Tiempos medidos

| Prueba | MTTD (segundos) | MTTR (segundos) |
| --- | ---: | ---: |
| 1 | 0.302679 | 0.000029 |
| 2 | 0.336643 | 0.000025 |
| 3 | 0.315760 | 0.000023 |
| **Promedio** | **0.318361** | **0.000026** |

Fórmulas verificadas con las marcas ISO UTC: MTTD = detección − primer fallo; MTTR = respuesta − detección.
Al ejecutar otra vez el detector, informó que no había incidentes nuevos.

## Salida real del detector

### Escenario 1

```text
=== ALERTA DE SEGURIDAD ===
Usuario afectado: prueba_01
Intentos fallidos: 3
Primer intento fallido: 2026-11-09T00:29:52.845523+00:00
Momento de detección: 2026-11-09T00:29:53.148202+00:00
MTTD: 0.302679 segundos
Acción de respuesta: USUARIO_BLOQUEADO (simulado)
Momento de respuesta: 2026-11-09T00:29:53.148231+00:00
MTTR: 0.000029 segundos

RESUMEN DE PRUEBAS
Prueba        MTTD (s)     MTTR (s)
1             0.302679     0.000029
MTTD promedio: 0.302679 segundos
MTTR promedio: 0.000029 segundos
```

### Escenario 2

```text
=== ALERTA DE SEGURIDAD ===
Usuario afectado: prueba_01
Intentos fallidos: 3
Primer intento fallido: 2026-11-09T00:29:53.451783+00:00
Momento de detección: 2026-11-09T00:29:53.788426+00:00
MTTD: 0.336643 segundos
Acción de respuesta: USUARIO_BLOQUEADO (simulado)
Momento de respuesta: 2026-11-09T00:29:53.788451+00:00
MTTR: 0.000025 segundos

RESUMEN DE PRUEBAS
Prueba        MTTD (s)     MTTR (s)
1             0.302679     0.000029
2             0.336643     0.000025
MTTD promedio: 0.319661 segundos
MTTR promedio: 0.000027 segundos
```

### Escenario 3

```text
=== ALERTA DE SEGURIDAD ===
Usuario afectado: prueba_01
Intentos fallidos: 3
Primer intento fallido: 2026-11-09T00:29:54.079107+00:00
Momento de detección: 2026-11-09T00:29:54.394867+00:00
MTTD: 0.315760 segundos
Acción de respuesta: USUARIO_BLOQUEADO (simulado)
Momento de respuesta: 2026-11-09T00:29:54.394890+00:00
MTTR: 0.000023 segundos

RESUMEN DE PRUEBAS
Prueba        MTTD (s)     MTTR (s)
1             0.302679     0.000029
2             0.336643     0.000025
3             0.315760     0.000023
MTTD promedio: 0.318361 segundos
MTTR promedio: 0.000026 segundos
```
