#!/bin/bash

#Script hecho para enumerar la información local de un host Linux. Bastante adecuado para la búsqueda de elevación de Privilegios
#en una máquina.
#
#Las enumeraciones llevadas a cabo son las básicas aconsejables en todo sistema y las más recomendadas, focalizándome en el análisis
#de cada una de ellas para obtener todo lo necesario.
#
#Copyright 2017 www.mundohackers.es

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
		echo "-t	Incluir escaneado exhaustivo (largo)"
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
	echo "Escaneo profundo = activado" |tee -a $report 2>/dev/null
else
	echo "Escaneo profundo = desactivado" |tee -a $report 2>/dev/null
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

echo -e "\e[00;33m### Usuario/Grupo ##########################################\e[00m" |tee -a $report 2>/dev/null

#Detalles del usuario actual
currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;31mInformación actual usuario/grupo:\e[00m\n$currusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Información de los últimos usuarios logeados en el sistema
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31mUsuarios que se han conectado recientemente al sistema:\e[00m\n$lastlogedonusrs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Usuarios logeados actualmente activos
loggedonusrs=`w 2>/dev/null`
if [ "$loggedonusrs" ]; then
  echo -e "\e[00;31mUsuarios logeados actualmente activos:\e[00m\n$loggedonusrs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Listado de todas las id's y grupos respectivos (group memberships)
grpinfo=`for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done 2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "\e[00;31mGroup members:\e[00m\n$grpinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Comprobación de hashes almacenados en /etc/passwd (método de almacenamiento depreciado *nix)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;33mParece que tenemos hashes de contraseñas en /etc/passwd!\e[00m\n$hashesinpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Localizar cuentas de usuario personalizadas con algún tipo de uids 'por defecto'
readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
if [ "$readpasswd" ]; then
  echo -e "\e[00;31mMuestras de entrada en /etc/passwd (buscando para valores uid 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m\n$readpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
else
  :
fi

#Comprobar si se puede leer el fichero shadow
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;33m***El fichero shadow puede leerse***\e[00m\n$readshadow" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
else
  :
fi

#Comprobar si el fichero /etc/master.passwd puede ser leido (BSD 'shadow' variante)
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;33m***El fichero master.passwd puede leerse***\e[00m\n$readmasterpasswd" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
else
  :
fi

#Todas las cuentas root (uid 0)
echo -e "\e[00;31mCuentas superusuario:\e[00m" | tee -a $report 2>/dev/null; grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#Sacando información vital del archivo sudoers
sudoers=`cat /etc/sudoers 2>/dev/null | grep -v -e '^$' 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;31mConfiguración Sudoers:\e[00m$sudoers" | tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$sudoers" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
else
  :
fi

#Comprobar si podemos ser sudo sin ser necesario introducir una contraseña
sudoperms=`echo '' | sudo -S -l 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;33m***¡¡Podemos ser sudo sin proporcionar contraseña!!***\e[00m\n$sudoperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Conocidos buenos binarios de desglose
sudopwnage=`echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'emacs'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "\e[00;33m***Posible sudo [PWNAGE]***\e[00m\n$sudopwnage" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Comprobación del directorio home del root para ver si es accesible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "\e[00;33m***Podemos leer el directorio home del root***\e[00m\n$rthmdir" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Mostrar permisos en el directorio /home - comprobar - comprobar si alguno es lax
homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
  echo -e "\e[00;31mPermisos del directorio /home:\e[00m\n$homedirperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Buscar archivos que podamos escribir los cuales no nos pertenecen
if [ "$thorough" = "1" ]; then
  grfilesall=`find / -writable -not -user \`whoami\` -type f -not -path "/proc/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$grfilesall" ]; then
    echo -e "\e[00;31mArchivos no pertenecientes al usuario pero con capacidad de escritura para los grupos:\e[00m\n$grfilesall" |tee -a $report 2>/dev/null
    echo -e "\n" |tee -a $report 2>/dev/null
  else
    :
  fi
fi

#Buscar archivos legibles dentro de /home - dependiendo del número de directorios y archivos en /home esto puede tomar un tiempo... por lo que sólo está activado con el escaneo exhaustivo
if [ "$thorough" = "1" ]; then
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
	if [ "$wrfileshm" ]; then
		echo -e "\e[00;31mArchivos legibles dentro del directorio /home:\e[00m\n$wrfileshm" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wrfileshm" ]; then
		mkdir $format/wr-files/ 2>/dev/null
		for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#Listar el contenido actual del directorio home de los usuarios en el sistema
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ 2>/dev/null`
	if [ "$homedircontents" ] ; then
		echo -e "\e[00;31mContenido de los directorios home:\e[00m\n$homedircontents" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#Comprobar si algunos archivos ssh son accesibles - Esto puede tomar un tiempo, por lo que sólo se hará con escaneado exhaustivo
if [ "$thorough" = "1" ]; then
sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;`
	if [ "$sshfiles" ]; then
		echo -e "\e[00;31mInformación de llaves/host SSH encontradas en las siguientes localizaciones:\e[00m\n$sshfiles" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
  :
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$sshfiles" ]; then
		mkdir $format/ssh-files/ 2>/dev/null
		for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#Comprobar si el login de root vía ssh está permitido
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "\e[00;31mSe le permite a Root conectarse vía SSH:\e[00m" |tee -a $report 2>/dev/null; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### AMBIENTAL #######################################\e[00m" |tee -a $report 2>/dev/null

#Información del ambiente
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "\e[00;31mInformación del ambiente:\e[00m\n$envinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Configuración de ruta actual
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  echo -e "\e[00;31mInformación de la ruta:\e[00m\n$pathinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Mostrar shells disponibles
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "\e[00;31mShells Disponibles:\e[00m\n$shellinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Valor umask actual con salida octal y simbólica
umask=`umask -S 2>/dev/null & umask 2>/dev/null`
if [ "$umask" ]; then
  echo -e "\e[00;31mValor umask actual:\e[00m\n$umask" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Valor como umask en /etc/login.defs
umaskdef=`cat /etc/login.defs 2>/dev/null |grep -i UMASK 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$umaskdef" ]; then
  echo -e "\e[00;31mValor umask como se especifica en /etc/login.defs:\e[00m\n$umaskdef" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Información de la política de contraseñas tal y como viene almacenado en /etc/login.defs
logindefs=`cat /etc/login.defs 2>/dev/null | grep "PASS_MAX_DAYS\|PASS_MIN_DAYS\|PASS_WARN_AGE\|ENCRYPT_METHOD" 2>/dev/null | grep -v "#" 2>/dev/null`
if [ "$logindefs" ]; then
  echo -e "\e[00;31mContraseñas e información de almacenamiento:\e[00m\n$logindefs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### Trabajos/Tareas ##########################################\e[00m" |tee -a $report 2>/dev/null

#En el sistema operativo Unix, cron es un administrador regular de procesos en segundo plano que ejecuta
#procesos o guiones a intervalos regulares. Los procesos que deben ejecutarse y la hora en la que deben hacerlo
#se especifican en el fichero crontab. Analizamos por tanto cada uno de los ficheros para sonsacar información interesante.

#Comprobar si hay trabajos 'cron' configurados
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "\e[00;31mTrabajos cron:\e[00m\n$cronjobs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Comprobar si podemos manipular estos trabajos de alguna manera
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "\e[00;33m***Trabajos 'cron' con capacidad de escritura y contenido de archivos***:\e[00m\n$cronjobwwperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Contenidos crontab
crontab=`cat /etc/crontab 2>/dev/null`
if [ "$crontab" ]; then
  echo -e "\e[00;31mContenidos crontab:\e[00m\n$crontab" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "\e[00;31mCosas interesantes en /var/spool/cron/crontabs:\e[00m\n$crontabvar" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "\e[00;31mTrabajos Anacron y permisos de asociación de archivos:\e[00m\n$anacronjobs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "\e[00;31m¿Cuándo se ejecutaron los trabajos por última vez? (contenido /var/spool/anacron):\e[00m\n$anacrontab" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Extraer nombres de cuentas de /etc/passwd y ver si algún usuario tiene algún trabajo cron asociado (priv command)
cronother=`cat /etc/passwd | cut -d ":" -f 1 | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "\e[00;31mTrabajos realizados por todos los usuarios:\e[00m\n$cronother" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### Red  ##########################################\n\e[00m" |tee -a $report 2>/dev/null

#Información nic
nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "\e[00;31mRed e información IP:\e[00m\n$nicinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

arpinfo=`arp -a 2>/dev/null`
if [ "$arpinfo" ]; then
  echo -e "\e[00;31mHistorial ARP:\e[00m\n$arpinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Opciones DNS
nsinfo=`cat /etc/resolv.conf 2>/dev/null | grep "nameserver"`
if [ "$nsinfo" ]; then
  echo -e "\e[00;31mNombre de los servidores:\e[00m\n$nsinfo" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Configuración route predeterminada
defroute=`route 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "\e[00;31mRoute por defecto:\e[00m\n$defroute" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Escuchando TCP
tcpservs=`netstat -antp 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "\e[00;31mEscuchando TCP:\e[00m\n$tcpservs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Escuchando UDP
udpservs=`netstat -anup 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "\e[00;31mEscuchando UDP:\e[00m\n$udpservs" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### Servicios #############################################\e\n[00m" |tee -a $report 2>/dev/null

#Procesos corriendo
psaux=`ps aux 2>/dev/null`
if [ "$psaux" ]; then
  echo -e "\e[00;31mProcesos corriendo:\e[00m\n$psaux" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Proceso de búsqueda de ruta binaria y permisos
procperm=`ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null`
if [ "$procperm" ]; then
  echo -e "\e[00;31mProcesos binarios y permisos asociados (de la lista anterior):\e[00m\n$procperm" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$procperm" ]; then
procpermbase=`ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null`
  mkdir $format/ps-export/ 2>/dev/null
  for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
else
  :
fi

#Cosas interesantes de utilidad en inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
  echo -e "\e[00;31mContenido de /etc/inetd.conf:\e[00m\n$inetdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$inetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
else
  :
fi

#Comando áspero para extraer binarios asociados de inetd.conf y mostrar los permisos de cada una
inetdbinperms=`cat /etc/inetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
  echo -e "\e[00;31mPermisos binarios inetd relacionados:\e[00m\n$inetdbinperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
  echo -e "\e[00;31mContenido de /etc/xinetd.conf:\e[00m\n$xinetdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$xinetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
else
  :
fi

xinetdincd=`cat /etc/xinetd.conf 2>/dev/null |grep "/etc/xinetd.d" 2>/dev/null`
if [ "$xinetdincd" ]; then
  echo -e "\e[00;31m/etc/xinetd.d se incluye en /etc/xinetd.conf - permisos binarios asociados listados a continuación:\e[00m" ls -la /etc/xinetd.d 2>/dev/null |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Comando áspero para extraer binarios asociados de xinetd.conf y mostrar permisos de cada uno de ellos
xinetdbinperms=`cat /etc/xinetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  echo -e "\e[00;31mPermisos binarios relacionados con xinetd:\e[00m\n$xinetdbinperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
if [ "$initdread" ]; then
  echo -e "\e[00;31mPermisos binarios de /etc/init.d/:\e[00m\n$initdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Archivos init.d NO pertenecientes a root
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initdperms" ]; then
  echo -e "\e[00;31mArchivos en /etc/init.d/ no pertenecintes a root (uid 0):\e[00m\n$initdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
  echo -e "\e[00;31mPermisos binarios en /etc/rc.d/init.d:\e[00m\n$rcdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Archivos init.d NO pertenecientes a root (Notar que cambiamos de directorio)
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$rcdperms" ]; then
  echo -e "\e[00;31mPermisos binarios en /etc/rc.d/init.d no pertenecientes a root (uid 0):\e[00m\n$rcdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
  echo -e "\e[00;31mPermisos binarios en /usr/local/etc/rc.d:\e[00m\n$usrrcdread" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi


#Archivos rc.d no pertenecientes a root
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
  echo -e "\e[00;31mArchivos en /usr/local/etc/rc.d no pertenecientes a root (uid 0):\e[00m\n$usrrcdperms" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### Software #############################################\e[00m\n" |tee -a $report 2>/dev/null

#sudo version - comprobar si existe algún tipo de vulnerabilidad conocida
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
  echo -e "\e[00;31mSudo version:\e[00m\n$sudover" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Detalles mysql - Siempre que esté instalado
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
  echo -e "\e[00;31mMYSQL version:\e[00m\n$mysqlver" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Comprobar si root/root nos vachecks to see if root/root nos proporcionará una conexión
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
  echo -e "\e[00;33m***Nos podemos conectar al servicio MYSQL local usando root/root como credenciales***\e[00m\n$mysqlconnect" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Detalles de versión mysql
mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
  echo -e "\e[00;33m***Nos podemos conectar al servicio local MYSQL como root sin necesidad de contraseña***\e[00m\n$mysqlconnectnopass" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Detalles postgres - En caso de que esté instalado
postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
  echo -e "\e[00;31mVersión Postgres:\e[00m\n$postgver" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Comprobar si alguna contraseña postgres existe y conecta con la DB 'template0'
postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
  echo -e "\e[00;33m***Nos podemos conectar a Postgres DB 'template0' como usuario 'postgres' sin contraseña***:\e[00m\n$postcon1" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
  echo -e "\e[00;33m***Nos podemos conectar a Postgres DB 'template1' como usuario 'postgres' sin contraseña***:\e[00m\n$postcon11" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  echo -e "\e[00;33m***Nos podemos conectar a Postgres DB 'template0' como usuario 'psql' sin contraseña***:\e[00m\n$postcon2" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  echo -e "\e[00;33m***Nos podemos conectar a Postgres DB 'template1' como usuario 'psql' sin contraseña***:\e[00m\n$postcon22" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Detalles de apache - Si está instalado
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
  echo -e "\e[00;31mVersión de Apache:\e[00m\n$apachever" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

#Bajo qué cuenta se está ejecutando apache
apacheusr=`cat /etc/apache2/envvars 2>/dev/null |grep -i 'user\|group' 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
if [ "$apacheusr" ]; then
  echo -e "\e[00;31mConfiguración de usuario de apache:\e[00m\n$apacheusr" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
else
  :
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
else
  :
fi

echo -e "\e[00;33m### Archivos interesantes ####################################\e[00m\n" |tee -a $report 2>/dev/null

#Comprobar si varios archivos están instalados
echo -e "\e[00;31mLocalización de archivos de utilidad:\e[00m" |tee -a $report 2>/dev/null; which nc 2>/dev/null |tee -a $report 2>/dev/null; which netcat 2>/dev/null |tee -a $report 2>/dev/null; which wget 2>/dev/null |tee -a $report 2>/dev/null; which nmap 2>/dev/null |tee -a $report 2>/dev/null; which gcc 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#Búsqueda limitada para compiladores instalados
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
if [ "$compiler" ]; then
  echo -e "\e[00;31mCompiladores instalados:\e[00m\n$compiler" |tee -a $report 2>/dev/null
  echo -e "\n" |tee -a $report 2>/dev/null
 else
  :
fi

#Comprobación manual - Listado de archivos sensibles, que podamos leer/modificar, etc.
echo -e "\e[00;31mPodemos leer/escribir archivos sensibles:\e[00m" |tee -a $report 2>/dev/null; ls -la /etc/passwd 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/group 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null |tee -a $report 2>/dev/null; ls -la /etc/master.passwd 2>/dev/null |tee -a $report 2>/dev/null
echo -e "\n" |tee -a $report 2>/dev/null

#Buscar archivos suid - Esto puede tomar un tiempo, por lo que sólo usando escaneo profundo podremos realizar la búsqueda
if [ "$thorough" = "1" ]; then
findsuid=`find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$findsuid" ]; then
		echo -e "\e[00;31mArchivos SUID:\e[00m\n$findsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$findsuid" ]; then
		mkdir $format/suid-files/ 2>/dev/null
		for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#Listado de archivos suid interesantes
if [ "$thorough" = "1" ]; then
intsuid=`find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'emacs'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la 2>/dev/null`
	if [ "$intsuid" ]; then
		echo -e "\e[00;33m***Posibles archivos SUID interesantes***:\e[00m\n$intsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi

#Listado de archivos suid con permisos de escritura
if [ "$thorough" = "1" ]; then
wwsuid=`find / -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwsuid" ]; then
		echo -e "\e[00;31mArchivos SUID con permisos de escritura:\e[00m\n$wwsuid" |tee -a $report 2>/dev/null
		echo -e "\n" |tee -a $report 2>/dev/null
	else
		:
	fi
  else
	:
fi
