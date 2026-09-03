# Actividad 3: Auditor de Seguridad y Entropía de Contraseñas

## Descripción
Este script evalúa de manera exhaustiva la robustez de una contraseña basándose en los estándares internacionales de ciberseguridad (NIST SP 800-63B y OWASP).

### Métricas de Evaluación
1. **Entropía de la Información (Bits)**: Mide la impredecibilidad y el espacio de búsqueda total mediante la fórmula:
   $$E = L \times \log_2(R)$$
   *(donde $L$ es la longitud de la contraseña y $R$ es el tamaño del conjunto de caracteres posibles: minúsculas, mayúsculas, dígitos, símbolos).*
2. **Detección de Patrones y Secuencias**: Identifica repeticiones obvias (ej. `aaaa`, `1111`) y secuencias contiguas de teclado o abecedario (ej. `qwerty`, `12345`, `abcd`).
3. **Lista Negra / Diccionario de Filtraciones**: Compara la clave contra una base de datos local de contraseñas vulnerables y comúnmente filtradas (`common_passwords.txt`).
4. **Tiempo Estimado de Ruptura (Brute Force)**: Calcula el tiempo teórico que tardaría un atacante con hardware moderno (100 GH/s) en quebrar la clave.
5. **Generador Criptográficamente Seguro**: Generador de contraseñas de alta entropía usando el módulo nativo `secrets` de Python.

---

## Modos de Uso

### 1. Menú Interactivo
Ejecuta:
```bash
python password_auditor.py
```
Opciones:
- Evaluar contraseña de forma oculta en consola (`getpass`).
- Evaluar contraseña en texto visible.
- Generar contraseñas seguras personalizadas.

### 2. Línea de Comandos (CLI)
- **Auditar una contraseña específica:**
  ```bash
  python password_auditor.py -p "Password123"
  ```
- **Generar una contraseña de 20 caracteres y auditarla:**
  ```bash
  python password_auditor.py --generate --length 20
  ```
