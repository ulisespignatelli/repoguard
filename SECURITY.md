# Seguridad

## Reportar una vulnerabilidad

Usá **Security → Report a vulnerability** en GitHub (aviso privado). Si encontrás una forma de evadir la
detección con un patrón de malware real, también es bienvenida: ayuda a mejorar las reglas.

## Modelo de amenazas

repoguard analiza, por diseño, código que puede ser malicioso. El primer requisito es que analizarlo no
ponga en riesgo a quien lo usa.

| Riesgo | Cómo se mitiga |
|---|---|
| Ejecutar código del repo analizado | Nunca se ejecuta, se compila ni se importa nada: solo se lee como texto o bytes. |
| Hooks o filtros de git | El clon usa `core.hooksPath` apuntando a una carpeta vacía, sin submódulos (`--no-recurse-submodules`), con `protocol.file.allow=never` y sin LFS. Se recomienda mantener git actualizado. |
| Enlaces simbólicos hacia archivos del sistema | No se siguen: se informan como señal. |
| Archivos enormes o líneas gigantes | Tope de 5 MB por archivo y de tamaño de línea; las expresiones regulares de Go (RE2) son de tiempo lineal. |
| Instrucciones escondidas para saltear el análisis | No existe ningún comentario o archivo de configuración dentro del repo que desactive reglas: el autor del repo analizado no puede silenciar a repoguard. |
| Filtrar datos de terceros en el informe | Los tokens de webhooks y bots se enmascaran en la evidencia, y los bloques codificados se recortan. |
| Cadena de suministro propia | Cero dependencias externas, `govulncheck` en CI y binarios publicados con sumas SHA-256. |
| Falsa sensación de seguridad | El veredicto "sin señales" lo aclara siempre: no es una garantía. |
