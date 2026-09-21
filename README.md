# Wireless Audit Pro v3.3.1

Aplicación integrada para auditoría wireless en Windows 10/11 sin WSL, Kali
WSL2 y Kali/Linux nativo.

## Inicio

En Windows, ejecutar `INICIAR_WIRELESS_AUDIT_SILENCIOSO.vbs` para abrir sin
ninguna consola. También se conserva `INICIAR_WIRELESS_AUDIT.bat` como respaldo.

Inicio manual:

```powershell
python .\WirelessAuditPro.py
```

En Kali/Linux:

```bash
python3 WirelessAuditPro.py
```

Autodiagnóstico sin abrir la interfaz:

```powershell
python .\WirelessAuditPro.py --self-test
python .\WirelessAuditPro.py --gui-smoke
python .\WirelessAuditPro.py --diagnose
```

## Interfaz principal

- **Radar:** contactos 802.11 animados por intensidad, proximidad, canal y seguridad.
- **Mapa y Wardriving:** ruta GPS, inventario continuo, métricas en vivo y
  exportación WiGLE CSV, KML, GeoJSON y mapa HTML.
- Analizador de espectro visual separado para 2.4 GHz y 5/6 GHz, con curvas
  por BSSID, ocupación estimada, AP en vista y nuevas redes por minuto.
- **Reconocimiento:** SSID, BSSID, fabricante, RSSI, radio, canal, cifrado y score.
- **Auditoría wireless:** riesgos de configuración y Wifite avanzado en una
  sección interna, sin añadir otra pestaña principal.
- **Alfa:** inventario separado de la radio de Internet, preparación Kali,
  dominio regulatorio, validación física y validación monitor/inyección.
- **Claves Wi-Fi:** visor protegido que distingue PSK guardada, red abierta y
  autenticación Enterprise/802.1X sin presentar puntos falsos.

La fuente automática prioriza la Alfa en este orden:

1. Alfa con driver nativo de Windows (`netsh ... interface=<Alfa>`), sin WSL.
2. Alfa ya adjunta a Kali mediante `nl80211`.
3. Wi-Fi integrada de Windows.

El modo automático no intenta transferir la Alfa a WSL durante cada escaneo.
La transferencia sólo ocurre al pulsar **Preparar Alfa en Kali**, evitando pausas
largas y la impresión de que el radar o el mapa se congelaron.

## Estabilidad visual

- Procesos externos ocultos; no se abren consolas auxiliares.
- Radar, escaneo, GPS y descargas de mapa trabajan fuera del hilo visual.
- Teselas con timeout, cuatro descargas simultáneas como máximo y caché SQLite WAL.
- Máximo de 120 marcadores y 18 cambios visuales por ciclo; el inventario completo
  continúa guardándose en SQLite y en las exportaciones.
- Botones Inicio/Detener con estado real: la acción pulsada pasa a gris, se
  bloquean dobles ejecuciones y Detener permanece inactivo al finalizar.

## Alfa AWUS1900

Conectar la antena por USB y abrir **Alfa**. La aplicación detecta la AWUS1900
aunque la conexión a Internet continúe en Intel. En Windows puede usar directamente
la interfaz Alfa para radar, espectro, reconocimiento y wardriving. Para monitor,
inyección y Wifite se prepara explícitamente en Kali.

Validación física de este equipo: `Wi-Fi 2`, Realtek 8814AU,
MAC `00-C0-CA-B6-A2-30`, driver `1030.52.731.2025`; escaneo dirigido validado en
2.4 y 5 GHz.

## Antes de una ruta

En **Mapa y Wardriving**, seleccionar GPS y pulsar **Precargar mapa** mientras exista conexión.
Se precarga aproximadamente un radio de 1.3 km (zoom 13-17) y las redes se siguen
guardando en SQLite aunque durante el recorrido no haya Internet.

Los puntos del mapa no muestran etiquetas permanentes para evitar saturar la
interfaz. Al pulsar un marcador se presenta SSID, BSSID, RSSI, canal y seguridad
en la barra superior del mapa. La ruta visual elimina el ruido GPS menor de 3 m.

En este equipo ya quedó instalado dentro de Kali WSL2 el conjunto `iw`, Wifite,
Aircrack-ng, hcxdumptool/hcxtools, TShark y Hashcat. La pestaña **Adaptador**
comprueba por separado el USB, el driver RTL8814AU, la interfaz `wlan`, el modo
monitor y la inyección; por ello no presenta una Alfa meramente detectada como
si ya tuviera capacidades RF operativas.

La AWUS1900 de este equipo quedó validada físicamente como `wlan0`, con escaneo
real en 2.4/5 GHz, modo monitor e inyección funcionales. Debido a que WSL2 monta
su árbol de módulos como una capa temporal, la aplicación conserva el módulo
8814au compilado en `/opt/wireless-audit/8814au.ko` y lo recupera silenciosamente
al volver a conectar la Alfa. El perfil regulatorio predeterminado es `GT`.

El botón **Validar conexión Alfa** descarta cualquier caché y diferencia entre
hardware físicamente presente y una entrada persistida de USBIPD. Si la antena
está disponible como interfaz, también ejecuta un escaneo real y muestra cuántos
BSSID recibió; tener instalado el driver ya no equivale a estar conectada.

## Privacidad

- El GPS pide permiso explícito antes de cada ruta.
- Las coordenadas se guardan solo en SQLite y exportaciones locales.
- Las contraseñas se revelan una por una y no entran en logs ni reportes.
- En Windows, mostrar una PSK guardada solicita UAC de forma explícita y reabre
  la interfaz con `pythonw`, sin lanzar una consola. La lista de perfiles no
  requiere elevación.
- Las redes abiertas muestran **No aplica** y las Enterprise indican
  **sin PSK compartida**; sólo los perfiles Personal con PSK aparecen ocultos.
- En Kali/Linux, NetworkManager clasifica también redes abiertas, OWE,
  Enterprise, WPA/WPA2-Personal y WPA3-Personal antes de permitir revelarlas.
- El portapapeles se limpia a los 30 segundos si todavía contiene la clave.
- Exportar evidencia no abre automáticamente navegadores ni terminales.

## Datos locales

- `captures/`: PCAP/PCAPNG.
- `data/wardrive.sqlite3`: historial de rutas.
- `data/map_tiles.sqlite`: caché del mapa.
- `exports/`: WiGLE, GeoJSON, KML y mapas.
- `reports/`: reportes técnicos HTML.
