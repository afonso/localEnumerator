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
echo -e "\e[00;33m# www.mundohackers.es\e[00m\n" |tee -a $report 2>/dev/null

echo "Información de depuración" |tee -a $report 2>/dev/null
echo -e "--------------------------\n" |tee -a $report 2>/dev/null

if [ "$keyword" ]; then
	echo "Palabra clave = $keyword" |tee -a $report 2>/dev/null
else
	:
fi

if [ "$report" ]; then
	echo "Nombre del informe = $report" |tee -a $report 2>/dev/null
else
	:
fi

if [ "$export" ]; then
	echo "Localización de exportación = $export" |tee -a $report 2>/dev/null
else
	:
fi

if [ "$thorough" ]; then
	echo "Prueba minuciosa = activada" |tee -a $report 2>/dev/null
else
	echo "Prueba minuciosa = desactivada" |tee -a $report 2>/dev/null
fi

sleep 2

if [ "$export" ]; then
  mkdir $export 2>/dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir $format 2>/dev/null
else
  :
fi

who=`whoami` 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

echo -e "\e[00;33mEscaneo empezado a las:"; date |tee -a $report 2>/dev/null
echo -e "\e[00m\n" |tee -a $report 2>/dev/null

echo -e "\e[00;33m### SISTEMA ##############################################\e[00m" |tee -a $report 2>/dev/null

#Información básica del kernel
unameinfo=`uname -a 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "\e[00;31mInformación del kernel:\e[00m\n$unameinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  echo -e "\e[00;31mInformación del kernel (continuado):\e[00m\n$procver" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Buscar todos los archivos de liberación para la información de la versión
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  echo -e "\e[00;31mInformación de liberación específica:\e[00m\n$release" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Información del hostname en cuestión
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "\e[00;31mHostname:\e[00m\n$hostnamed" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi
