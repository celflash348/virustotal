# virustotal
script para hacer busqueda masiva en virustotal 

USO


Consultar un dominio específico:

virustotal.py -api TU_CLAVE_API -type domain -value ejemplo.com

Consultar un archivo con múltiples dominios:

virustotal.py -api TU_CLAVE_API -type domain -p path/to/domains.txt

Consultar un hash específico:

virustotal.py -api TU_CLAVE_API -type hash -value abc123hash

Consultar una dirección IP específica:

virustotal.py -api TU_CLAVE_API -type ip -value 192.168.1.1

Consultar un archivo con múltiples direcciones IP:

virustotal.py -api TU_CLAVE_API -type ip -p path/to/ips.txt
