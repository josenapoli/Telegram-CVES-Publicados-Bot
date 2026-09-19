# Telegram Cybersecurity CVE Notifier Bot

Un bot automatizado para **GitHub Actions** desarrollado en Python que recopila vulnerabilidades recientes (CVEs) de la base de datos oficial de NIST NVD (API v2), filtra el spam de modificaciones antiguas y notifica las alertas críticas en un grupo o canal de Telegram en tiempo real.

---

## 🚀 Características Principales

*   **Filtrado Personalizado por Palabras Clave (`keywords.json`)**: Permite especificar qué marcas, protocolos o productos monitorear (`include`) y cuáles bloquear (`exclude`) para evitar saturar el canal de Telegram. El filtrado es insensible a mayúsculas/minúsculas y busca con límites de palabra (evitando falsos positivos como que `rdp` coincida con `wordpress` o `edge` coincida con `knowledge`).
*   **Búsqueda en Descripciones y CPE**: La comparación de palabras clave se hace tanto en la descripción en inglés como en las configuraciones de productos (CPE) de la vulnerabilidad (ej. `cpe:2.3:o:cisco:ios_xe`), logrando una precisión absoluta.
*   **Consulta por Fecha de Modificación**: El bot rastrea modificaciones de vulnerabilidades en lugar de solo publicaciones, lo que permite capturar re-evaluaciones de score y adiciones de exploit.
*   **Caché de Envío Inteligente**: Mantiene un historial de los CVEs procesados en los últimos 30 días en `state.json` para evitar notificaciones duplicadas por modificaciones menores (como enlaces de referencias nuevos).
*   **Alertas de Actualización de Severidad**: Si una vulnerabilidad se publica inicialmente sin puntaje (`AWAITING_ANALYSIS`) y es evaluada más tarde como `HIGH` o `CRITICAL`, el bot detecta el cambio de estado y envía una alerta de actualización (`🔄 Actualización de CVE`).
*   **Filtro de Antigüedad de Publicación**: Ignora modificaciones en CVEs antiguos de meses o años pasados, enfocándose únicamente en vulnerabilidades recientes.
*   **Mensajería HTML Segura**: Utiliza formateo HTML enriquecido para Telegram. Escapa automáticamente caracteres especiales (`<`, `>`, `&`) en las descripciones de las vulnerabilidades para prevenir bloqueos de entrega de la API de Telegram.
*   **Auto-Mantenimiento**: Poda automáticamente del archivo `state.json` los registros que superen los 30 días de antigüedad para optimizar el almacenamiento y rendimiento.

---

## 🛠️ Variables de Configuración

Puedes controlar el comportamiento del bot mediante variables de entorno (GitHub Secrets y Variables):

### Credenciales (GitHub Secrets)
*   `TELEGRAM_BOT_TOKEN`: *(Requerido)* Token de API de tu bot de Telegram obtenido a través de `@BotFather`.
*   `TELEGRAM_CHAT_ID`: *(Requerido)* ID numérico de tu grupo o canal de Telegram (ej. `-100xxxxxxxxxx`).
*   `NVD_API_KEY`: *(Opcional)* Clave de API de NVD. Muy recomendada para incrementar el límite de tasa de la API de NIST (de 5 peticiones/30s a 50 peticiones/30s) y asegurar la confiabilidad del bot.

### Filtros (GitHub Variables)
*   `MIN_SEVERITY`: *(Opcional)* Nivel mínimo de severidad CVSS para reportar (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL` o `NONE`). Por defecto es `MEDIUM`.
*   `REPORT_UNSCORED`: *(Opcional)* `true` o `false`. Determina si se notifican vulnerabilidades recién publicadas que aún no han sido analizadas por NIST (`AWAITING_ANALYSIS`). Por defecto es `true`.
*   `MAX_PUBLISHED_AGE_DAYS`: *(Opcional)* Número máximo de días de antigüedad que puede tener la publicación original de un CVE para ser reportado. Por defecto es `14`.

---

## 📁 Estructura del Proyecto

```text
├── .github/
│   └── workflows/
│       └── cve_notifier.yml    # Workflow de GitHub Actions (Ejecución horaria)
├── cve_notifier.py             # Script principal de Python
├── keywords.json               # Configuración de palabras clave (Inclusiones/Exclusiones)
├── requirements.txt            # Dependencias del proyecto (requests)
├── state.json                  # Archivo de estado persistente (Caché + Timestamp)
├── test_cve_notifier.py        # Suite de pruebas unitarias
├── .gitignore                  # Exclusiones de Git (Ignora pycache y archivos locales)
└── README.md                   # Documentación del proyecto
```

---

## ⚙️ Configuración y Despliegue en GitHub

### Paso 1: Configurar Secrets y Variables en GitHub
Ve a tu repositorio en GitHub y dirígete a **Settings** > **Secrets and variables** > **Actions**:

1.  En la pestaña **Secrets**, haz clic en *New repository secret* y añade:
    *   `TELEGRAM_BOT_TOKEN`
    *   `TELEGRAM_CHAT_ID`
2.  En la pestaña **Variables**, haz clic en *New repository variable* y añade:
    *   `MIN_SEVERITY` con el valor `HIGH` (para ignorar severidades bajas).
    *   `REPORT_UNSCORED` con el valor `false` (si no deseas alertas preliminares).
    *   `MAX_PUBLISHED_AGE_DAYS` con el valor `14` (para omitir CVEs de más de dos semanas de antigüedad).

### Paso 2: Subir el Proyecto
Sube todos los archivos (incluyendo la carpeta oculta `.github/` y el archivo `.gitignore`) a la rama principal de tu repositorio.

El flujo de trabajo se ejecutará **automáticamente a cada hora**. Puedes dispararlo manualmente en cualquier momento desde la pestaña **Actions** > **Telegram CVE Notifier** > **Run workflow**.

---

## 🧪 Desarrollo y Pruebas Locales

### Instalación de dependencias
```bash
pip install -r requirements.txt
```

### Ejecutar Pruebas Unitarias
El proyecto cuenta con un entorno de pruebas simulado que verifica la lógica de filtros y caché sin enviar peticiones reales:
```bash
python -m unittest test_cve_notifier.py
```

### Ejecutar un Dry-Run (Prueba en Consola)
Puedes probar el comportamiento del bot de forma local y ver las salidas por consola sin afectar al canal de Telegram y sin guardar cambios de estado:
```bash
# Simular envío buscando modificaciones en las últimas 12 horas
python cve_notifier.py --dry-run --hours 12
```
