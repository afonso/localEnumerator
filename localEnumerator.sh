#!/bin/bash
#Script hecho para enumerar la información local de un host Linux. Bastante adecuado para la búsqueda de elevación de Privilegios
#en una máquina

#Función de Ayuda
usage ()
{
echo -e "\n\e[00;31m#####################################################################\e[00m"
echo -e "\e[00;31m#\e[00m" "\e[00;33mEnumeración Local de Linux & Script para Elevación de Privilegios\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#####################################################################\e[00m"
echo -e "\e[00;33m# www.mundohackers.es | Twitter @MundoHackersX \e[00m"
echo -e "\e[00;33m# Ejemplo: ./localEnumerator.sh -k keyword -r report -e /tmp/ -t \e[00m\n"

		echo -e "Opciones:\n"
		echo "-k	Introducir palabra clave"
		echo "-e	Introducir ubicación de exportación"
		echo "-t	Incluir pruebas exhaustivas (largas)"
		echo "-r	Introducir nombre del informe"
		echo "-h	Mostrar este texto de ayuda"
		echo -e "\n"
		echo "Correr el programa sin opciones = escaneados limitados/sin archivos de salida"

echo -e "\e[00;31m############################################################################\e[00m"
}
while getopts "h:k:r:e:t" option; do
 case "${option}" in
	  k) keyword=${OPTARG};;
	  r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
	  e) export=${OPTARG};;
	  t) thorough=1;;
	  h) usage; exit;;
	  *) usage; exit;;
 esac
done

echo -e "\n\e[00;31m#####################################################################\e[00m" |tee -a $report 2>/dev/null
echo -e "\e[00;31m#\e[00m" "\e[00;33mEnumeración Local de Linux & Script para Elevación de Privilegios\e[00m" "\e[00;31m#\e[00m" |tee -a $report 2>/dev/null
echo -e "\e[00;31m#####################################################################\e[00m" |tee -a $report 2>/dev/null
echo -e "\e[00;33m# www.mundohackers.es\e[00m" |tee -a $report 2>/dev/null
