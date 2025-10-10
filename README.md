# Obligatorio de Seguridad en Redes de Datos - ORT

**Fecha de entrega 03/12/2025  -  21Hs**  
**Profesor:** Mauricio Campiglia  
**Alumnos:** Federico Morra (143394) – Pablo Rizzo (181374)
---

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

    ○ Deberá implementar la interconexión entre el centro de datos de Montevideo y la infraestructura
      en nube. Para esta solución no será necesario tener en cuenta la redundancia.
    ○ Deberá también implementar acceso administrativo seguro para los administradores de red y
      sistemas (usuarios privilegiados).
       ■ La protección de este canal de acceso deberá tener en cuenta los desafíos y riesgos
          actuales de autenticación e identidad digital.
       ■ Se espera que esta solución permita asignar políticas granulares de acceso
          dependiendo de la identidad de quien se conecte.

3. Protección de Aplicaciones Web (WAF y API Gateway)

    ○ Deberá implementar una solución de API Gateway que permita proteger la infraestructura de
      soporte de telemetría y aplicaciones.
    ○ Deberá configurar una solución WAF que pueda detectar y detener los ataques comunes del
      OWASP Top Ten en tiempo real sin afectar la funcionalidad del portal web.
       ■ Se espera que esta solución se integre con el SIEM
       ■ Se le pide que configure al menos dos reglas personalizadas

5. Monitoreo y Respuesta (SIEM)

    ○ Deberá desplegar un SIEM para monitoreo, detección y respuesta.
       ■ Deberá integrarse con el resto de la maqueta, recibiendo alertas de las soluciones de
          WAF, VPN y la plantilla GNU/Linux endurecida.
       ■ Deberá configurar 3 casos de uso personalizados, al menos uno de ellos relacionado
          con autenticación.

7. Gestión de Identidad y Accesos (IAM)

    ○ Deberá implementar o configurar un proveedor de identidad centralizado para los usuarios de la
      organización (interno).
       ■ Deberá poder proveer un punto de autenticación y autorización utilizando protocolos
          estándares (OAuth2 u OpenIDC).
       ■ Deberá poder integrarse o soportar analítica de comportamiento de usuarios para
          detectar patrones de uso (autenticación) anómalos.

9. Plantilla de Servidor endurecida

    ○ Deberá proponer una forma de estandarizar el proceso de endurecimiento del sistema operativo 
      GNU/Linux utilizado como base para el despliegue de la infraestructura de la organización.
       ■ Deberá tomar como referencia los CIS CSC Benchmark L1.
       ■ El entregable deberá poder replicarse con cada despliegue de servidor. Se espera que
          entregue los scripts asociados, no una plantilla o imagen.
       ■ Como mínimo, el endurecimiento deberá contemplar:
            1. Firewall local
            2. Auditoría del sistema
            3. Acceso administrativo seguro
            4. Integración con el SIEM 
---

## 3. Análisis y propuesta de la solucion

Aca faltan aclarar varios temas.......

**Como resumen tecnico la solución propuesta provee:**

- Un servidor FreeBSD ubicado en el borde entre las zonas DMZ e Internet que cumplira funciones de Firewall (PFsense con OpenVPN)
- Un servidor Debian ubicado en la zona DMZ que cumplira funciones de WAF (Apache Mod Security)
- Un servidor Debian ubicado en la zona DMZ que cumplira funciones de  API Gateway (Kong API Gateway)
- Un servidor Debian ubicado en la zona SERVIDORES que cumplira funciones de web server (Apache)
- Un servidor Debian ubicado en la zona SERVIDORES que cumplira funciones de SIEM (Wazuh)
- Un servidor Debian ubicado en la zona SERVIDORES que cumplira funciones de autenticacion (OpenLDAP y Free Radius)

A los efectos practicos de demostrar el funcionamiento de todos estos servicios, y cumpliendo con los requerimientos de letra,
la maqueta presentada seran 4 VMs que agruparan varios servicios, pero que claramente en un ambiente de produccion no podrian 
compartir hardware ni direccionamiento IP. 

---

## 4. Redes Privadas Virtuales (VPN)

*Guia detallada de configuracion de un firewall PFsense con el servicio de OpenVPN*

---

## 5. Proteccion de Aplicaciones Web (WAF y API Gateway)

*Guia detallada de configuracion de ambos servicios*

---

## 6. Monitoreo y Respuesta (SIEM)

*Guia detallada de configuracion de un servidor Wazuh para recibir alertas del resto de los servicios de la infraestructura*

---

## 7. Gestion de Identidad y Accesos (IAM)

---

## 8. Plantilla de Servidor endurecida

*Guia detallada del hardening de un servidor Debian tomando como referencia los CIS CSC Benchmark L1*

---

## 9. Diagramas de la infraestructura sugerida

*Diagrama de la topologia sugerida*

![Diagrama general de la topologia](images/image2.jpg)

---

## 10. Software necesario para la maqueta virtual 

*No se incluye licenciamiento de software dado que se opto por software de licenciamiento libre*

---

## 11. Troubleshooting

*Se detallan posibles errores y soluciones que el equipo fue encontrando durante el desarrollo de la solucion*

---

## 12. Capturas de funcionamiento de la maqueta virtual 

*En esta seccion se muestran capturas que evidencian el funcionamiento en un entorno virtual*

---

## 13. Posibles mejoras de la infraestructura sugerida

*Aqui se detallan posibles mejoras del despliegue que fueron apareciendo durante la creacion del mismo pero no nos dio el tiempo para ponerlos en produccion*

---

## 14. Referencias bibliograficas

- Documentacion del sitio oficial de Debian (https://www.debian.org/doc/)
- Material del curso Seguridad en Redes y Dato disponible en la web Aulas de la Facultad ORT (https://aulas.ort.edu.uy)


### Uso de Inteligencia Artificial Generativa

- Prompts puntuales con consultas de errores y troubloshooting de la maqueta en ChatGPT
- -->
- -->
- -->
