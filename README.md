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

python virustotal.py -api TU_API_KEY -type hash -value b8e05afefe13155e0e0e43fbca1b0c332a92c1b4a4daf6f26009ebe1978785c6 --debug

