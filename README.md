# Obligatorio de Seguridad en Redes de Datos - ORT

## **Fecha de entrega 03/12/2025  -  21Hs**  
**Profesor:** Mauricio Campiglia  
**Estudiantes:** Federico Morra (143394) – Pablo Rizzo (181374)

## 1. Descripción general

Este repositorio contempla todos los requerimientos, configuraciones básicas y limitaciones a tener presente para
la implementacion de una infraestructura de red segura para una empresa local que ha decidido migrar parte de su
infraestructura on-premise hacia la cloud. El foco del proyecto sera siempre la seguridad de la red y el correcto
uso y gestion de las identidades de usuarios de la misma, siendo hoy en dia el principal vector de un ataque cibernetico.

Nosotros asumimos que los temas que no son requeridos por el cliente en este proyecto, estan saneados y correctamente configurados,
dado que si alguna otra capa o control de seguridad ajeno a este proyecto, falla, la infraestructura de red sugerida
se vera vulnerada con consecuencias directas sobre la continuidad del negocio de la empresa Fosil S.A..

---

## 2. Presentación del problema por parte del cliente

Fósil Energías Renovables S.A.(fosil.uy) es una empresa uruguaya del sector energético con más de cinco
décadas de trayectoria. Su origen se remonta a la década de 1970, cuando fue fundada bajo el nombre Fósil
S.A., dedicada a la importación, almacenamiento y distribución de hidrocarburos en el mercado nacional.
Durante varias décadas fue un actor relevante en la cadena de suministro de combustibles fósiles, atendiendo
tanto a clientes industriales como residenciales.

En el año 2015, en el marco de la transición energética global y los compromisos del Uruguay en materia de
energías limpias, la compañía adoptó un nuevo modelo de negocio y un cambio de identidad corporativa,
pasando a denominarse Fósil Energías Renovables. Este rebranding no fue solo simbólico: implicó una fuerte
inversión en la diversificación de su matriz energética, incorporando proyectos de generación a partir de fuentes
solares y eólicas.

Hoy en día, la empresa combina la gestión de infraestructuras tradicionales—oleoductos, plantas de
almacenamiento y distribución de combustibles con parques solares y aerogeneradores ubicados
principalmente en el interior del país. Esta dualidad convierte a Fósil Energías Renovables en un actor híbrido,
con el desafío de mantener la operación crítica de sus sistemas legados mientras impulsa soluciones innovadoras
en el ámbito de la energía sustentable.

Con una plantilla aproximada de 500 colaboradores, la organización cuenta con un centro de datos en
Montevideo para sus sistemas de gestión, así como plataformas en la nube orientadas a clientes corporativos y
usuarios residenciales. Además, opera soluciones de telemetría e IoT para el control de la generación renovable,
consolidando su papel como un actor estratégico en el proceso de transformación energética del país.

Alcance:

Su equipo es el responsable de la implementación de los controles de seguridad que se detallan en este alcance.

1. Redes Privadas Virtuales (VPN)

   - Deberá implementar la interconexión entre el centro de datos de Montevideo y la infraestructura
      en nube. Para esta solución no será necesario tener en cuenta la redundancia.
   - Deberá también implementar acceso administrativo seguro para los administradores de red y
      sistemas (usuarios privilegiados).

      - La protección de este canal de acceso deberá tener en cuenta los desafíos y riesgos
         actuales de autenticación e identidad digital.
      - Se espera que esta solución permita asignar políticas granulares de acceso
         dependiendo de la identidad de quien se conecte.

2. Protección de Aplicaciones Web (WAF y API Gateway)

   - Deberá implementar una solución de API Gateway que permita proteger la infraestructura de
      soporte de telemetría y aplicaciones.
   - Deberá configurar una solución WAF que pueda detectar y detener los ataques comunes del
      OWASP Top Ten en tiempo real sin afectar la funcionalidad del portal web.

      - Se espera que esta solución se integre con el SIEM
      - Se le pide que configure al menos dos reglas personalizadas

3. Monitoreo y Respuesta (SIEM)

   - Deberá desplegar un SIEM para monitoreo, detección y respuesta.

      - Deberá integrarse con el resto de la maqueta, recibiendo alertas de las soluciones de
         WAF, VPN y la plantilla GNU/Linux endurecida.
      - Deberá configurar 3 casos de uso personalizados, al menos uno de ellos relacionado
         con autenticación.

4. Gestión de Identidad y Accesos (IAM)

   - Deberá implementar o configurar un proveedor de identidad centralizado para los usuarios de la
      organización (interno).

      - Deberá poder proveer un punto de autenticación y autorización utilizando protocolos
         estándares (OAuth2 u OpenIDC).
      - Deberá poder integrarse o soportar analítica de comportamiento de usuarios para
         detectar patrones de uso (autenticación) anómalos.

5. Plantilla de Servidor endurecida

   - Deberá proponer una forma de estandarizar el proceso de endurecimiento del sistema operativo
      GNU/Linux utilizado como base para el despliegue de la infraestructura de la organización.

      - Deberá tomar como referencia los CIS CSC Benchmark L1.
      - El entregable deberá poder replicarse con cada despliegue de servidor. Se espera que
         entregue los scripts asociados, no una plantilla o imagen.
      - Como mínimo, el endurecimiento deberá contemplar:

         1. Firewall local
         2. Auditoría del sistema
         3. Acceso administrativo seguro
         4. Integración con el SIEM

---

## 3. Análisis y propuesta de la solucion

Aca faltan aclarar varios temas.......

**Como resumen tecnico la solución propuesta provee:**

- Un servidor ubicado en el borde entre las zonas DMZ e Internet que cumplira funciones de Firewall (PFsense con OpenVPN)
- Un servidor en la zona DMZ que cumplira funciones de WAF (Apache ModSecurity)
- Un servidor en la zona DMZ que cumplira funciones de  API Gateway (Kong API Gateway)
- Un servidor en la zona SERVIDORES que cumplira funciones de web server (Apache)
- Un servidor en la zona SERVIDORES que cumplira funciones de SIEM (Wazuh)
- Un servidor en la zona SERVIDORES que cumplira funciones de autenticacion (OpenLDAP y Free Radius)
- La solución del Firewall se montará en un servidor con sistema operativo FreeBSD, en los demas servidores se usará la distribución Debian 12.

A los efectos practicos de demostrar el funcionamiento de todos estos servicios, y cumpliendo con los requerimientos de letra,
la maqueta presentada seran 4 VMs que agruparan varios servicios, pero que claramente en un ambiente de produccion no podrian
compartir hardware ni direccionamiento IP.

---

## 4. Redes Privadas Virtuales (VPN)

*Guia detallada de configuracion de un firewall PFsense con el servicio de OpenVPN*

Para la implementacion de un acceso seguro a la empresa, por parte de los colaboradores que acceden a traves de internet, hemos optado por un firewall PFsense (version 2.7) el cual ya tiene incluido de fabrica el paquete OpenVPN. Dicho paquete nos permitira configurar una VPN Client-Access para dichos colaboradores y como segundo factor de autenticacion hemos optado por un certificado que se instalara en el dispositivo remoto de cada usuario que la vaya a utilizar.

A los efectos practicos, autogeneramos un certificado local, el cual no tiene validez en internet, pero si servira para establecer las VPNs Client-access requeridos por la organizacion. Al momento de llevarlo al ambiente de produccion, la empresa Fosil debera costear dicho certificado con una CA reconocida.

En la topologia de red sugerida existiran 2 tipos de conexiones VPN, una de ellas sera del tipo Client-Access para los colaboradores remotos que necesitan utilizar servicios internos de la empresa, y el segundo tipo de VPN sera site-to-site y sera para unir el sitio central en Montevideo, con los nuevos servicios que la empresa desea levantar en la Cloud de AWS. Solo se mostrara la configuracion de una VPN Client-Access en el firewall PFsense de borde, y si el lector desea, puede consultar la documentacion de OpenVPN/PFsense para obtener los pasos de configuracion de una VPN site-to-site.

---

## 5. Proteccion de Aplicaciones Web (WAF y API Gateway)

*Guia detallada de configuracion de ambos servicios*

---

## 6. Monitoreo y Respuesta (SIEM)

*Guia detallada de configuracion del servidor con la herramienta Wazuh, para recibir alertas del resto de los servicios de la infraestructura*

### Casos de uso personalizados

#### Caso 1

#### Caso 2

#### Caso 3

---

## 7. Gestion de Identidad y Accesos (IAM)

---

## 8. Plantilla de Servidor endurecida

*Guia detallada del hardening de un servidor Debian tomando como referencia los CIS CSC Benchmark L1*

El script de hardening de este repositorio (hardening.sh) cumple con el fortalecimiento de 4 areas criticas de un servidor Debian teniendo como referencia el CIS CSC Benchmark. Una vez finalizada la ejecucion de los distintos comandos en cada area, se procede a reiniciar los servicios involucrados y configurar la ejecucion de los mismos desde el inicio del sistema operativo. 

A nivel de **Firewall local** se configura lo siguiente:

- Instalar el paquete nftables (evolucion del firewall iptables).
- Limpiar reglas de firewall existentes.
- Crear regla "Deny all" por defecto si no hay trafico especifico definido.
- Permitir solamente acceso SSH y puertos del servidor Wazuh (1514 y 1515) en sentido entrante al servidor.
- Permitir conexiones cuyo estado sea "Established" y "Related", vinculadas a sesiones ya iniciadas desde el servidor.
- Permitir trafico saliente irrestricto para asegurar actualizaciones del sistema operativo del servidor.
- Deshabilitar protocolos de red inseguros como DCCP, SCTP, RDS y TIPC bloqueando la carga manual de estos modulos (/bin/true).
- Desinstalar protocolos de red inseguros (DCCP, SCTP, RDS y TIPC) si estuvieran instalados en el servidor.

A nivel de **Auditorioa del sistema** se configura lo siguiente:

- Instalar el paquete de auditoria auditd y sus plugins audispd-plugins.
- Habilitar el servicio de auditoria desde el gestor de arranque GRUB.
- Aplicar reglas de auditoria relativas a cambios de identidad (Usuarios, Grupos y Contrasenias) generando logs ante cualquier cambio.
- Aplicar reglas de auditoria relativas a comandos de privilegio (sudo y su) generando logs ante cualquier uso de los mismos.
- Aplicar reglas de auditoria relativas a la configuracion de red (Hostname, dominio y direccionamiento IP) generando logs con los detalles de cada cambio.
- Configurar politica de retencion de logs de auditoria por tamanio maximo, sin sobreescritura y notificacion via mail al admin si el HDD no tiene espacio fisico.
- Configurar el modo inmutable para todas las reglas de auditoria creadas para impedir su modificacion o borrado intencional.

A nivel de **Acceso administrativo seguro** se configura lo siguiente:

- Deshabilitar el acceso SSH al servidor utilizando el usuario **root**
- Deshabilitar el acceso SSH al servidor utilizando usuario y contrasenia, debiendo utilizarse claves publicas SSH para el acceso seguro.
- Forzar SSH version 2.
- Ignorar archivo de **hosts** y deshabilitar acceso SSH basado en dicho archivo.
- Limitar intentos fallidos de acceso SSH al servidor. 
- Configurar timeout de sesiones SSH inactivas.
- Limitar tiempo de login de una sesion SSH.
- Cambiar el nivel de registro de eventos SSH al nivel **Verbose**
- Deshabilitar el reenvio de interfaces graficas a traves de SSH (X11).
- Bloquear variables de entorno personalizadas durante el login SSH.
- Limitar conexiones simultaneas en una sesion SSH para evitar un ataque de denegacion de servicio.
- Deshabilitar reenvios de puertos TCP en una sesion SSH.
- Establecer banner informativo legal que se desplegara por pantalla antes de cada login SSH.

A nivel de **Integracion con el SIEM** se configura lo siguiente:

- Descargar e instalar agente Wazuh en el servidor.
- En la configuracion del agente Wazuh, configurar la direccion IP del servidor Wazuh (SIEM), al cual el agente enviara los logs.

Cabe destacar que antes de aplicar el script de hardening a un servidor Debian con una instalacion limpia, desde cero, el nivel de seguridad CIS CSC segun el agente Wazuh es del XXX% y una vez aplicado el script de hardening, dicho nivel de seguridad aciende a XXX%. De todos modos, si el lector experimentado decide editar el script de hardening para sumar controles de hardening y asi elevar el nivel de seguridad de un servidor Debian, adjuntamos en este repositorio el documento PDF completo de CIS CSC Benchmark para un servidor Debian 12.

---

## 9. Diagramas de la infraestructura sugerida

*Diagrama de la topologia sugerida*

![Diagrama general de la topologia](images/image1.jpg)

---

## 10. Software necesario para la maqueta virtual

*No se incluye licenciamiento de software dado que se opto por software de licenciamiento libre*

- Distribucion Linux Debian 12
- Wazuh version 4.13.1
- PFsense version 2.7
- VirtualBOX version 7.0
- Apache web server version 2.4
- Apache ModSecurity version 2.9

---

## 11. Troubleshooting

*Se detallan posibles errores y soluciones que el equipo fue encontrando durante el desarrollo de la solucion*

---

## 12. Capturas de funcionamiento de la maqueta virtual

*En esta seccion se muestran capturas que evidencian el funcionamiento en un entorno virtual*

### 12.B Pruebas de ataques WEB para deteccion y bloqueo de WAF

---

## 13. Posibles mejoras de la infraestructura sugerida

*Aqui se detallan posibles mejoras del despliegue que fueron apareciendo durante la creacion del mismo pero no nos dio el tiempo para ponerlos en produccion*

---

## 14. Referencias bibliograficas

- Documentacion del sitio oficial de Debian (https://www.debian.org/doc/)
- Documentacion del sitio oficial de OpenVPN (https://openvpn.net/community-docs/)
- Documentacion del sitio oficial de PFsense (https://docs.netgate.com/pfsense/)
- Documentacion del sitio oficial de Wazuh (https://documentation.wazuh.com/)
- Wazuh: sintaxis para generar reglas: (https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- Wazuh: controles SCA para Hardening: (https://documentation.wazuh.com/current/getting-started/use-cases/configuration-assessment.html)
- Documentacion de Apache ModSecurity (https://docs.cpanel.net/)
- Repositorio de CRS (Core Ruleset) de OWASP para configuracion de reglas de WAF (https://github.com/coreruleset/coreruleset)
- Material del curso Seguridad en Redes y Dato disponible en la web Aulas de la Facultad ORT (https://aulas.ort.edu.uy)

### Uso de Inteligencia Artificial Generativa

- Prompts puntuales con consultas de errores y troubleshooting de la maqueta en ChatGPT
- -->
- -->
- -->
- Prompts de configuracion en Google Gemini
- --> "modificar el script que tenemos hasta el momento para que se ajuste a los controles de cis benchmarks de debian realizados por el modulo sca de wazuh. A continuación te compartimos el script y el archivo de configuracion yml"
