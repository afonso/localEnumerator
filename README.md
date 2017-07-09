<b>localEnumerator</b>

![Enumerate](Images/enumerate.png)

Programa hecho en bash para enumerar toda la información de un host Linux. Bastante adecuado para la búsqueda de elevación de privilegios en una máquina. El programa detecta cualquier tipo de "anomalía" en el sistema. En caso de que la contraseña root pueda obtenerse de alguna forma o sea encontrada en algún archivo sensible seremos notificados.

Podemos correrlo de la siguiente forma -> <b>./localEnumerator</b> si queremos realizar un escaneo simple. 

Algunas de las opciones incorporadas en el programa usan filtros con palabras clave pasadas como parámetros para encontrar determinados ficheros. Para ello, podemos correr el programa de la siguiente forma en caso de que queramos pasarle palabras clave -> <b>./localEnumerator -k miPalabraClave</b>

El escaneo en sí ha sido configurado para que actúe como informe, de manera que podemos darle un nombre al escaneo para que posteriormente todos los resultados sean guardados en el directorio local con el nombre del informe y la fecha adjunta para que sepamos cuándo se realizó dicho informe. Para ello -> <b>./localEnumerator -r miInforme</b>

En caso de que queramos cambiar la ubicación de la exportación del informe, podemos indicárselo a través de la opción <b>-e</b>, de la siguiente manera -> <b>./localEnumerator -r miInforme -e /home/user/Desktop/misInformes</b>

Algunas de las opciones incorporadas en el programa demoran cierto tiempo... es por ello que sólo funcionará si tenemos el escaneo profundo activado. Para ello simplemente incorporamos al final de nuestro gusto de opciones lo siguiente -> <b>-t</b>

Para ver su uso: <b>./localEnumerator -h</b>
