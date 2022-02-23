#!/usr/bin/env bash
clear
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"$

############################## SKRIPTLER #####################################
clear

#=================================================
#   Ustanowka edip bolýan OSlar: CentOS 6+/Debian 6+/Ubuntu 14.04+
#   Düşündiriş: Shadowsock scripti stanowka et
#   Wersiýasy: 1.0.26
#   Awtor: Alparslan
#   Telegram: @alparslan_93
#=================================================

sh_ver="3.0"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ssr_folder="/usr/local/shadowsocksr"
config_file="${ssr_folder}/config.json"
config_user_file="${ssr_folder}/user-config.json"
config_user_api_file="${ssr_folder}/userapiconfig.py"
config_user_mudb_file="${ssr_folder}/mudb.json"
ssr_log_file="${ssr_folder}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"


Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m" && Blue='\033[34m' && Purple='\033[35m' && Ocean='\033[36m' && Black='\033[37m' && Morg="\033[5m" && Reverse="\033[7m" && Font="\033[1m"
Info="${Green_font_prefix}[Maglumat]${Font_color_suffix}"
Error="${Red_font_prefix}[Ýalňyşlyk]${Font_color_suffix}"
Tip="${Green_font_prefix}[Bellik]${Font_color_suffix}"
Separator_1="——————————————————————————————"

# Ýönekeý OpenVPN
Openvpnnyr_install(){
#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
# Copyright (c) 2013 Nyr. Released under the MIT License.

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Green="\033[32m" && Red="\033[31m" && Yellow="\033[33m" && Blue='\033[34m' && Purple='\033[35m' && Ocean='\033[36m' && Black='\033[37m' && Morg="\033[5m" && Reverse="\033[7m" && Font="\033[1m"
sh_ver="10.0"

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'Skripti BASH komandaň komegi bilen başlaň'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "Sistemany täzeleň (obnowit ediň)"
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "Sistema götermeýär."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubunty wersiýasy kone (hökmany iň pes wersiýa: Ubuntu 18.04+)"
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Skript üçin hökmany Debian 9+ bolmaly."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "Skript üçin hökmany Centos 7+ bolmaly."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sudo su ýa-da sudo (skriptin ady) komandany ýazyň"
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "TUN driwer ustanowka edilmedik."
	exit
fi

adduser(){
	echo -e "Döretmegiň görnüşi: 
  1. Yzyna aý gün hasaby goşup
  2. Aý gün hasapsyz"
  echo && read -e -p "Sistemaň saýlaýany [1]: " num
case "$num" in
	1)
	echo
	echo "Ulanyjynyň adyny saýlan:"
	read -p "Ady: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		echo "$client: Saýlan adyňyz öňem bar."
		read -p "Ady: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	done
	client=$(echo "${client}_$(date +"%d-%m")")	
	cd /etc/openvpn/server/easy-rsa/
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	# Generates the custom client.ovpn
	new_client
	echo
  linktofile="$(curl -F "file=@/root/$client.ovpn" "https://file.io" | cut -b 46-73)"
	echo "--------------------------------"
	echo "-------------------------"
	echo "----------------"
	echo "---------"
	echo -e "$linktofile - Ulanyjynyň konfigrasiýa faýlynyň ssylkasy $client"
	echo "---------"
	echo "----------------"
	echo "-------------------------"
	echo "--------------------------------"
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTER düwmä basyň..."
   ovpn_menu
	;;
	2)
	echo
	echo "Ulanyjy üçin at saýlaň:"
	read -p "Ady: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		echo "$client: Saýlan adyňyz öň bar."
		read -p "Ady: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	done
	client=$(echo "${client}")	
	cd /etc/openvpn/server/easy-rsa/
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	# Generates the custom client.ovpn
	new_client
	echo
  linktofile="$(curl -F "file=@/root/$client.ovpn" "https://file.io" | cut -b 46-73)"
	echo "--------------------------------"
	echo "-------------------------"
	echo "----------------"
	echo "---------"
	echo -e "$linktofile - Ulanyjynyň konfigrasiýa faýlynyň ssylkasy $client"
	echo "---------"
	echo "----------------"
	echo "-------------------------"
	echo "--------------------------------"
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTER düwmä basyň..."
   ovpn_menu
	;;
	*)
		echo
	echo "Ulanyjy üçin at saýlaň:"
	read -p "Ady: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		echo "$client: Saýlan adyňyz öň bar."
		read -p "Ady: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	done
	client=$(echo "${client}_$(date +"%d-%m")")	
	cd /etc/openvpn/server/easy-rsa/
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	# Generates the custom client.ovpn
	new_client
	echo
    linktofile="$(curl -F "file=@/root/$client.ovpn" "https://file.io" | cut -b 46-73)"
	echo "--------------------------------"
	echo "-------------------------"
	echo "----------------"
	echo "---------"
	echo -e "$linktofile - Ulanyjynyň konfigrasiýa faýlynyň ssylkasy $client"
	echo "---------"
	echo "----------------"
	echo "-------------------------"
	echo "--------------------------------"
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTER düwmä basyň..."
   ovpn_menu
   ;;
esac
}
get_users_list(){
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$number_of_clients" = 0 ]]; then
		echo
		echo "Dost ulanyjy ýoga, nädip pozjak?!"
			read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTER düwma basyň..."
   ovpn_menu
	fi
		echo
		clear
		echo "Serwerdäki ulanyjylar:"
		tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTER düwmä basyň..."
   ovpn_menu
}
deleteuser(){
				number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "Dost ulanyjy ýoga, nädip pozjak?!"
				exit
			fi
			echo
			echo "Pozmaga degişli ulanyjy:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Ulanyjy: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: Ýalňyş girizdiň."
				read -p "Ulanyjy: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Dost çyndanam yok etjekmaý şony $client ? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: ýalňyş girizdiň."
				read -p "Dost çyndanam yok etjekmaý şony $client ? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				rm "/root/$client.ovpn" 
				clear
				echo "$client pozuldy!"
				read -e -p "Ýenede ulanyjy pozjakmy?[Y/n]:" delyn
				[[ -z ${delyn} ]] && delyn="y"
				if [[ ${delyn} == [Nn] ]]; then
                	 ovpn_menu
				else
					echo -e "${Info} Ulanyjy pozmak dowam edilýär..."
					deleteuser
				fi
			else
				echo
				echo " $client - i pozmak ýatyryldy!"
			fi
			exit
}
showlink(){
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$number_of_clients" = 0 ]]; then
		echo
		echo "Dost ýok ulanyjynyň ssylkasyny alyp bolmaýar?!"
		exit
	fi
		echo
		echo "Haýsy ulanyjynyň ssylkasyny alasyn gelýär?:"
		tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
		read -p "Ulanyjy: " client_number
		until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
			echo "$client_number: Ýalnyş girizdiň."
			read -p "Ulanyjy: " client_number
		done
		client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
		echo
		linktofile="$(curl -F "file=@/root/$client.ovpn" "https://file.io" | cut -b 46-73)"
		clear
		echo -e "$linktofile - Ulanyjynyň ssylkasy $client" && echo
		read -e -p "ýene ssylka gerekmi?[Y/n]: " delyn
		[[ -z ${delyn} ]] && delyn="y"
		if [[ ${delyn} == [Nn] ]]; then
				ovpn_menu
		else
				echo -e "${Info} ýene ssylka bermek dowam edilýär..."
				showlink
		fi
}
uninstallovpn(){
				echo
			read -p "OpenVpni çyndanam pozjakmy?? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: ýalňyş girizdiň."
				read -p "OpenVpni çyndanam pozjakmy?? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -rf /etc/openvpn/server
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
				fi
				echo
				rm -r "/var/log/openvpn"
				cd "/root" && rm *.ovpn
				echo "OpenVPN pozuldy!"
			else
				echo
				echo "OpenVPNi pozmak ýatyryldy!"
			fi
			exit
}
fastexit(){
	exit
}
new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}
if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	apt install at
	clear
	echo 'Alparslanyň OpenVpn skriptine hoş geldin dost!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	    echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)';
		echo
		echo  -e "Serweriň ${Green_background_prefix}IPsini ýada DOMENi${Font_color_suffix} giriz"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Nähili IPV6 ulanmaly?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 адрес [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 адрес [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Dost OpenVPN haýsy protokoly ulansyn?"
	echo "   1) UDP"
	echo "   2) TCP"
	read -p "Protokol [Adaty ýagdaýda: UDP]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: ýalňyş girizdiň."
		read -p "Protokol [Adaty ýagdaýda: UDP]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo
	echo "OpenVPN üçin port saýla"
	read -p "PORT [adaty ýagdaýda: 1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: ýalňyş girizdiň."
		read -p "PORT [adaty ýagdaýda: 1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Ulanyjy üçin DNS serverem bir saýlap goýber dost (Meň maslahatyma: 1):"
	echo "   1) Häzirki DNS server"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [adaty ýagdaýda: 1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [adaty ýagdaýda: 1]: " dns
	done
	echo
	echo "Ilkinji ulanyjy üçin at saýla:"
	read -p "Ady [adaty ýagdaýda: Admin]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="Admin"
	echo
	echo "OpenVPN ustanowka goýberilmäne taýýar."
	# Install a firewall in the rare case where one is not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Islendik düwmäni basyň..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate key for tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Generate server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	# Generates the custom client.ovpn
	new_client
	echo
	echo "ustanowka üstünlikli tamamlandy!"
	echo
	echo "Täze ulanyjynyň faýly:" ~/"$client.ovpn ýerde ýerleşýär" && echo
	linktofile="$(curl -F "file=@/root/$client.ovpn" "https://file.io")"
	echo -e "$linktofile - Ulanyjy faýlynyň ssylkasy $client" && echo
	echo "Täze ulanyjy goşmak üçin skripti täzeden goýber."
else
	clear
ovpn_menu(){
	Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
	}
	Get_IP
	clear
	number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	number_of_active=$(cat /var/log/openvpn/openvpn-status.log | grep CLIENT_LIST | tail -n +2 | grep -c CLIENT_LIST)
	echo  -e " 
${Yellow}╭━━━╮╱╱╱╱╱╱╱╭╮╱╱╭┳━━━┳━╮╱╭╮
┃╭━╮┃╱╱╱╱╱╱╱┃╰╮╭╯┃╭━╮┃┃╰╮┃┃
┃┃╱┃┣━━┳━━┳━╋╮┃┃╭┫╰━╯┃╭╮╰╯┃
┃┃╱┃┃╭╮┃┃━┫╭╮┫╰╯┃┃╭━━┫┃╰╮┃┃
┃╰━╯┃╰╯┃┃━┫┃┃┣╮╭╯┃┃╱╱┃┃╱┃┃┃
╰━━━┫╭━┻━━┻╯╰╯╰╯╱╰╯╱╱╰╯╱╰━╯
╱╱╱╱┃┃
╱╱╱╱╰╯${Font_color_suffix}"
	echo
echo -e "Salam dostlar. hormatlamak bilen Alparslan!
  Jemi seýredäki ulanyjylaryň sany:${Green_font_prefix} ${number_of_clients} ${Font_color_suffix}"
echo -e "  Ulgamdaky ulanyjylaryň sany:${Green_font_prefix} ${number_of_active} ${Font_color_suffix}"
  echo -e "
  Serveriň IPsi: ${Ocean}${ip}${Font_color_suffix}

  ${Green_font_prefix}0.${Font_color_suffix} Baş menýuwa dolanmak
 ————————————
  ${Green_font_prefix}1.${Font_color_suffix} Ulanyjy goşmak
  ${Green_font_prefix}2.${Font_color_suffix} Ulanyjy pozmak
 ———————————— 
  ${Green_font_prefix}3.${Font_color_suffix} Ulanyjylaryň sanawy
  ${Green_font_prefix}4.${Font_color_suffix} Faýl üçin ssylka almak
 ———————————— 
  ${Green_font_prefix}7.${Font_color_suffix} OpenVPN-i pozmak
  ${Green_font_prefix}8.${Font_color_suffix} Çykyş
 ———————————— 
 "
	read -p "sany saýlaň: " option
	case "$option" in
		0)
		clear
   		bash $HOME/vpn.sh
   		;;
		1)
		clear
		adduser
		;;
		2)
		clear
		deleteuser
		;;
		3)
		clear
		get_users_list
		;;
		4)
		clear
		showlink
		;;
		7)
		clear
		uninstallovpn
		;;
		8)
		clear
		fastexit
		;;
		*)
		clear
		ovpn_menu
		;;
	esac
}
ovpn_menu
fi
}
######################################################


check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} Dost skript root ulanyjynyň adyndan goýberilmedi. Gaýrat etde ${Green_background_prefix} sudo su ${Font_color_suffix} yazda täzeden goýber." && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} krontab ýok: CentOS ustanowka etmek üçin yum install crond -y diýip ýaz , Debian/Ubuntu: apt-get install cron -y !" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR! tapylmady" && clear && exit 1
}

# brandmaueri sazlamak
Add_iptables(){
	if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}

Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} Ulanyjy barada maglumat alyp bolmady ${Green_font_prefix}[Порт: ${ssr_port}]${Font_color_suffix} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(çäklendirilmedik)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
	#u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="çäklendirilmedik"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	#echo "transfer_port=${transfer_port}"
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	#echo "all_port=${all_port}"
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	#echo "port_num=${port_num}"
	port_num_1=$(echo $((${port_num}-1)))
	#echo "port_num_1=${port_num_1}"
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	#echo "transfer_enable_1=${transfer_enable_1}"
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	#echo "u_1=${u_1}"
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	#echo "d_1=${d_1}"
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	#echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	#echo "transfer_enable_Used_1=${transfer_enable_Used_1}"
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	#echo "transfer_enable=${transfer_enable}"
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	#echo "u=${u}"
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	#echo "d=${d}"
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	#echo "transfer_enable_Used=${transfer_enable_Used}"
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
	#echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
}
Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSurl}"
	ss_link=" SS link : ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS QR kod : ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSRurl}"
	ssr_link=" SSR link: ${Purple}${SSRurl}${Font_color_suffix} \n SSR QR kod : ${Purple}${SSRQRcode}${Font_color_suffix} \n "
}
ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
# konfigrasiya barada magluamt
View_User(){
	clear
	SSR_installation_status
	List_port_user
	while true
	do
		echo -e "akkaunt üçin port giriz"
		read -e -p "Port: " View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "Goýbolsun..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			break
		else
			echo -e "${Error} Dogry port giriz !"
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
	clear
	main_menu
		fi
	done
}
View_User_info(){
	clear
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e " [${user_name}] ulanyjy barada maglumat ：" && echo
	echo -e " IP\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " Port\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " Parol\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " Şifrleme : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " Protokol   : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " Obfs\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e " Enjam sany : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e " Açaryň umumy tizligi : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e " Her ulanyjynyň birikme tizligi : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e " Gadagan portlar : ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e " Ulanylan Trafik : Upload: ${Green_font_prefix}${u}${Font_color_suffix} + Download: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"
	echo -e " Galan Trafik : ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e " Umumy trafik : ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e "${ssr_link}"
	echo -e " ${Green_font_prefix} Düşündiriş: ${Font_color_suffix}
 QR kody almak üçin ssylkany brawzerda açyň。"
	echo && echo "==================================================="
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
	clear
	main_menu
}
View_User_info1(){
	clear
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e " [${user_name}] ulanyjy barada maglumat ：" && echo
	echo -e " IP\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " Port\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " Parol\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " Şifrleme : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " Protokol   : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " Obfs\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e " Enjam sany : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e " Açaryň umumy : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e " Her ulanyjylaryň birikme tizligi : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e " Gadagan portlar : ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e " Ulanylan Trafik : Upload: ${Green_font_prefix}${u}${Font_color_suffix} + Download: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"
	echo -e " Galan Trafik : ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e " Umumy trafik : ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e "${ssr_link}"
	echo -e " ${Green_font_prefix} Подсказка: ${Font_color_suffix}
 QR kody almak üçin ssylkany brawzerda açyň。"
	echo && echo "==================================================="
}
# Konfigrasiýa baradaky maglumaty sazlamak
Set_config_user(){
	echo -e "${Tip} Atlar gaýtalanmaly däl!"
	echo -e "
 ${Green_font_prefix}1.${Font_color_suffix} ulanyjy ady (aý gün bilen)
 ${Green_font_prefix}2.${Font_color_suffix} ulanyjy ady (aý günsiz)"
	read -e -p "(adaty ýagdaýda: 1): " num
	case "$num" in
	1)
	read -e -p "(adaty ýagdaýda: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    ulanyjy ady : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
	2)
	read -e -p "(adaty ýagdaýda: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}"|sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    ulanyjy ady : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
	*)
	read -e -p "(adaty ýagdaýda: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    ulanjy ady : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
esac
}
Set_config_port(){
	echo -e "port
 ${Green_font_prefix}1.${Font_color_suffix} awto
 ${Green_font_prefix}2.${Font_color_suffix} özüň girizmek" 
	read -e -p "adaty ýagdaýda (1.awto): " how_to_port
	[[ -z "${how_to_port}" ]] && how_to_port="1"
	if [[ ${how_to_port} == "1" ]]; then
		echo -e "Port awtomat usulda girizildi."
		ssr_port=$(shuf -i 1000-9999 -n 1)
		while true
		do
		echo $((${ssr_port}+0)) &>/dev/null
		if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "    Port: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Port giriz(1-65535)"
		fi
	else
		echo -e "${Error} Port giriz(1-65535)"
	fi
	done
	elif [[ ${how_to_port} == "2" ]]; then
		while true
		do
			read -e -p "Port: " ssr_port
			[[ -z "$ssr_port" ]] && break
			echo $((${ssr_port}+0)) &>/dev/null
			if [[ $? == 0 ]]; then
				if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
					echo && echo ${Separator_1} && echo -e "    Port: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
					break
				else
					echo -e "${Error} Port giriz(1-65535)"
				fi
			else
				echo -e "${Error} Port giriz(1-65535)"
			fi
		done
	else 
		echo -e "Port awtomat usulda girizildi."
		ssr_port=$(shuf -i 1000-9999 -n 1)
		while true
		do
		echo $((${ssr_port}+0)) &>/dev/null
		if [[ $? == 0 ]]; then
			if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "    Port: : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
			else
			echo -e "${Error} Port giriz(1-65535)"
			fi
		else
		echo -e "${Error} Port giriz(1-65535)"
		fi
		done
	fi
}
Set_config_password(){
	echo -e "Parol:
 ${Green_font_prefix}1.${Font_color_suffix} Parol = Port
 ${Green_font_prefix}2.${Font_color_suffix} Tötänleýin parol"
	read -e -p "(adaty ýagdaýda: 2. Tötänleýin parol): " how_to_pass
	[[ -z "${how_to_pass}" ]] && how_to_pass="2"
	if [[ ${how_to_pass} == "1" ]]; then
		ssr_password=${ssr_port}
	elif [[ ${how_to_pass} == "2" ]]; then
		ssr_password=$(date +%s%N | md5sum | head -c 16)
	else 
		ssr_password=$(date +%s%N | md5sum | head -c 16)
	fi
	echo && echo ${Separator_1} && echo -e "    Parol : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
	echo -e "Şifrleme görnüşi:
————————————    
 ${Green_font_prefix} 1.${Font_color_suffix} none
————————————
 ${Green_font_prefix} 2.${Font_color_suffix} rc4
 ${Green_font_prefix} 3.${Font_color_suffix} rc4-md5
 ${Green_font_prefix} 4.${Font_color_suffix} rc4-md5-6
————————————
 ${Green_font_prefix} 5.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 6.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} aes-256-ctr
————————————
 ${Green_font_prefix} 8.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix}10.${Font_color_suffix} aes-256-cfb
————————————
 ${Green_font_prefix}11.${Font_color_suffix} aes-128-cfb8
 ${Green_font_prefix}12.${Font_color_suffix} aes-192-cfb8
 ${Green_font_prefix}13.${Font_color_suffix} aes-256-cfb8
————————————
 ${Green_font_prefix}14.${Font_color_suffix} salsa20
 ${Green_font_prefix}15.${Font_color_suffix} chacha20
 ${Green_font_prefix}16.${Font_color_suffix} chacha20-ietf
————————————"
	read -e -p "(adaty ýagdaýda: 16. chacha20-ietf): " ssr_method
	[[ -z "${ssr_method}" ]] && ssr_method="16"
	if [[ ${ssr_method} == "1" ]]; then
		ssr_method="none"
	elif [[ ${ssr_method} == "2" ]]; then
		ssr_method="rc4"
	elif [[ ${ssr_method} == "3" ]]; then
		ssr_method="rc4-md5"
	elif [[ ${ssr_method} == "4" ]]; then
		ssr_method="rc4-md5-6"
	elif [[ ${ssr_method} == "5" ]]; then
		ssr_method="aes-128-ctr"
	elif [[ ${ssr_method} == "6" ]]; then
		ssr_method="aes-192-ctr"
	elif [[ ${ssr_method} == "7" ]]; then
		ssr_method="aes-256-ctr"
	elif [[ ${ssr_method} == "8" ]]; then
		ssr_method="aes-128-cfb"
	elif [[ ${ssr_method} == "9" ]]; then
		ssr_method="aes-192-cfb"
	elif [[ ${ssr_method} == "10" ]]; then
		ssr_method="aes-256-cfb"
	elif [[ ${ssr_method} == "11" ]]; then
		ssr_method="aes-128-cfb8"
	elif [[ ${ssr_method} == "12" ]]; then
		ssr_method="aes-192-cfb8"
	elif [[ ${ssr_method} == "13" ]]; then
		ssr_method="aes-256-cfb8"
	elif [[ ${ssr_method} == "14" ]]; then
		ssr_method="salsa20"
	elif [[ ${ssr_method} == "15" ]]; then
		ssr_method="chacha20"
	elif [[ ${ssr_method} == "16" ]]; then
		ssr_method="chacha20-ietf"
	else
		ssr_method="chacha20-ietf"
	fi
	echo && echo ${Separator_1} && echo -e "    Şifrleme : ${Green_font_prefix}${ssr_method}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_protocol(){
	ssr_protocol="origin"
}
Set_config_obfs(){
	ssr_obfs="plain"
}
Set_config_protocol_param(){
	while true
	do
	echo -e "${Tip} Näçe enjamda ulanmakçy:"
	read -e -p "(adaty ýagdaýda: çäklendirilmedi): " ssr_protocol_param
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			echo && echo ${Separator_1} && echo -e "    enjam sany : ${Green_font_prefix}${ssr_protocol_param}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Dogry sany bellesene(1-9999)"
		fi
	else
		echo -e "${Error} Dogry nomer bellesene(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	echo -e "Porta tizligi çäklendirmek (ölçeg birligi: КB/s)"
	read -e -p "(adaty ýagdaýda: çäklendirilmedik): " ssr_speed_limit_per_con
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "    Porta tizligi çäklendirmek : ${Green_font_prefix}${ssr_speed_limit_per_con} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Dogry nomer bellesene(1-131072)"
		fi
	else
		echo -e "${Error} Dogry nomer bellesene(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	echo -e "Bir enjamyn tizligini çäklendirmek (ölçeg birligi: КB/s)"
	read -e -p "(adaty ýagdaýda: çäklendirilmedik): " ssr_speed_limit_per_user
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "    Bir enjamyn tizligini çäklendirmek : ${Green_font_prefix}${ssr_speed_limit_per_user} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Dogry nomer bellesene(1-131072)"
		fi
	else
		echo -e "${Error} Dogry nomer bellesene(1-131072)"
	fi
	done
}
Set_config_transfer(){
	while true
	do
	echo
	echo -e "Port trafik boýunça çäklendirmek (От 1 GB dan 838868 GB a çenli)"
	read -e -p "(adaty ýagdaýda: limitsiz): " ssr_transfer
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && echo && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			echo && echo ${Separator_1} && echo -e "    Umumy trafik : ${Green_font_prefix}${ssr_transfer} GB${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Dogry nomer bellesene(1-838868)"
		fi
	else
		echo -e "${Error} Dogry nomer bellesene(1-838868)"
	fi
	done
}
Set_config_forbid(){
	ssr_forbid=""
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ssr_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} Bu portuň ýapyk statusyny almak başartmady [${ssr_port}]!" && exit 1
			ssr_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ssr_port}','|awk -F ":" '{print $1}')
			echo -e "ssr_port_num=${ssr_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} Bu portyň setir sanyny almak başartmady[${ssr_port}]!" && exit 1
			ssr_enable_num=$(echo $((${ssr_port_num}-5)))
			echo -e "ssr_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "[${ssr_port}] portyň：${Green_font_prefix}açyk${Font_color_suffix} ýagdaýyny ${Red_font_prefix}ýapyk${Font_color_suffix} ýagdaýa geçirmek ?[Y/n]"
		read -e -p "(adaty ýagdaýda: Y): " ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="0"
		else
				read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
				clear
	main_menu
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "[${ssr_port}] portuň：${Green_font_prefix}отключен${Font_color_suffix} ýagdaýyny ,  ${Red_font_prefix}açyk${Font_color_suffix} ýagdaýa geçmek ?[Y/n]"
		read -e -p "(adaty ýagdaýda: Y): " ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="1"
		else
			read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
			clear
	main_menu
		fi
	else
		echo -e "${Error} akkauntda bir ýalňyşlyga bar [${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Serweriň IP salgysyny almak başartmady！" && exit 1
		else
			echo -e "${Info} Şu wagtky IP： ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "Serweriň IP salgysyny giriz"
	read -e -p "(ENTER düwmäni basanda IPni awtomat usulda saýlaýar): " ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Serweriň IP salgysyny öziň giriz!" ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} Boş bolmaýar！"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e "   serweriň IP salgysy : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_user_fast(){
	echo -e "${Tip} Atlar gaýtalanmaly däl!"
	echo -e "
 ${Green_font_prefix}1.${Font_color_suffix} Ulanyjy ady (aý gün bilen)
 ${Green_font_prefix}2.${Font_color_suffix} alanyjy ady (aý günsiz)"
	read -e -p "(adaty ýagdaýda: 1): " num
	case "$num" in
	1)
	read -e -p "(adaty ýagdaýda: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m/%y")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    ulanyjy ady : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
	2)
	read -e -p "(adaty ýagdaýda: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}"|sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    ulanyjy ady : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
	*)
	read -e -p "(adaty ýagdaýda: Admin): " ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_$(date +"%d/%m/%y")" |sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "    ulanyjy ady : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
	;;
esac
}
Set_config_port_fast(){
	ssr_port=$(shuf -i 1000-65432 -n 1)
	echo $((${ssr_port}+0)) &>/dev/null
	[[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]
}
Set_config_password_fast(){
	ssr_password=$(date +%s%N | md5sum | head -c 16)
}
Set_config_method_fast(){
	ssr_method="chacha20-ietf"
}
Set_config_protocol_fast(){
	ssr_protocol="origin"
}
Set_config_obfs_fast(){
	ssr_obfs="plain"
}
Set_config_protocol_param_fast(){
	ssr_protocol_param="1"
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	[[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]
}
Set_config_speed_limit_per_con_fast(){
	ssr_speed_limit_per_con="0"
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	[[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]
}
Set_config_speed_limit_per_user_fast(){
	ssr_speed_limit_per_user="0"
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	[[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]
}
Set_config_transfer_fast(){
	ssr_transfer="838868"
	echo $((${ssr_transfer}+0)) &>/dev/null
	[[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]
}
Set_config_forbid_fast(){
	ssr_forbid=""
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
}	
Set_config_all_fast(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password_fast
		Set_config_method_fast
		Set_config_protocol_fast
		Set_config_obfs_fast
		Set_config_protocol_param_fast
		Set_config_speed_limit_per_con_fast
		Set_config_speed_limit_per_user_fast
		Set_config_transfer_fast
		Set_config_forbid_fast
	else
		Set_config_user_fast
		Set_config_port_fast
		Set_config_password_fast
		Set_config_method_fast
		Set_config_protocol_fast
		Set_config_obfs_fast
		Set_config_protocol_param_fast
		Set_config_speed_limit_per_con_fast
		Set_config_speed_limit_per_user_fast
		Set_config_transfer_fast
		Set_config_forbid_fast
	fi
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
# kanfigrasiýa barada maglumat özgertmek
Modify_config_password(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} ulanyjynyň parolyny üýtgedip bolmady ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Ulanyjynyň paroly üstünlikli üýtgedildi ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Modify_config_method(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Şifrlemäni üýtgedip bolmady ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Şifrleme üstünlikli üýtgedildi ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
	clear
	main_menu
	fi
}
Modify_config_protocol(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Protokoly üýtgedip bolmady ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Prototkol üýtgedildi ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Modify_config_obfs(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Obfs plagini üýtgedip bolmady ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Obfs plagin üýtgedildi ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Modify_config_protocol_param(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Enjemyň limitini üýtgedip bolmady ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Enjemyň limiti üýtgedildi ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Modify_config_speed_limit_per_con(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Açaryň tizligini üýtgedip bolmady ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Açaryň tizligi üýtgedildi ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Modify_config_speed_limit_per_user(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Ulanyjynyň tizligini üýtgedip bolmady ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Ulanyjynyň tizligi üýtgedildi ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Modify_config_connect_verbose_info(){
	clear
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Ulanyjynyň umumy trafigini üýtgedip bolmady ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Ulanyjynyň umumy trafigi üýtgedildi ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Modify_config_forbid(){
	clear
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Gadagan edilen Porty üýtgedip bolmady ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Gadagan edilen Port üýtgedildi ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (10 sekunt ýaly wagtyňy almagy mümkin)"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Modify_config_enable(){
	clear
	sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	clear
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
	clear
	main_menu
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} Python ustanowka edilmedik, etmäne başlaýan..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
# ShadowsocksRy ýüklemek
Download_SSR(){
	cd "/usr/local"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR serwerini göçürip almak başa barmady !" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} ShadowsocksR serweriden arhiw almak başa barmady !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} ShadowsocksR serweri arhiwden çykarmak başa barmady !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} ShadowsocksR serweriň adyny üýtgedip bolmady !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ssr_folder}/config.json" "${config_user_file}"
	cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} ShadowsocksR üçin apiconfig.py göçürip bolmady  !" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	#sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	echo -e "${Info} ShadowsocksR üstünlikli ustanowka edildi !"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR üçin skripti ýükläp bolmady!" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR dolandyrmak üçin skripti ýükläp bolmady !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} ShadowsocksRi dolandyrmak üçin skript üstünlikli ustanowka edildi !"
}

JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error}  JQ adyny üýtgedip bolmady !" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} JQ ustanowka edildi, dowamy..." 
	else
		echo -e "${Info} JQ ustanowka edildi..."
	fi
}

Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} unzip ustanowka edilmedi !" && exit 1
	Check_python
	#echo "nameserver 8.8.8.8" > /etc/resolv.conf
	#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SSR(){
	clear
	check_root
	[[ -e ${ssr_folder} ]] && echo -e "${Error} Barlaň!! ShadowsocksR papka eýýäm bar (Eger ustanowka başa barmasa ýada köne wersiýasy bar bolsa ilki pozuň) !" && exit 1
	echo -e "${Info} ShadowsocksR konfigrasiýasyny sazlamana başlaň..."
	Set_user_api_server_pub_addr
	Set_config_all
	echo -e "${Info} Ustanowka başla / ShadowsocksRa bagly sazalama..."
	Installation_dependency
	echo -e "${Info} Ýüklemane başlaň / ShadowsocksR faýly ustanowka..."
	Download_SSR
	echo -e "${Info} Ýüklemane başla / ShadowsocksR(init) kömekçi skript..."
	Service_SSR
	echo -e "${Info} Ýüklemäne başla / JSNO JQ ustanowka..."
	JQ_install
	echo -e "${Info} Başdaky ulanyjylary goşup başlan..."
	Add_port_user "install"
	echo -e "${Info} Iptables ekranlanan tor arabaglanyşygynyň sazlamasyna başlaň..."
	Set_iptables
	echo -e "${Info} Iptables Brandmaweriň düzgünlerini goşmaga başlaň..."
	Add_iptables
	echo -e "${Info} Iptables Brandmaweriň düzgünlerini ýatda saklap başlaň..."
	Save_iptables
	echo -e "${Info} Hemme ädimler ustanowka edildi, ShadowsocksR serweri goýberyäris..."
	Start_SSR
	Get_User_info "${ssr_port}"
	View_User_info
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
	clear
	main_menu
}

Uninstall_SSR(){
	clear
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR ustanowka edilmedi !" && exit 1
	echo "ShadowsocksRi poz？[y/N]" && echo
	read -e -p "(adaty ýagdaýda: n): " unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo " ShadowsocksR üstünlikli ustanowka edildi !" && echo
	else
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
	main_menu
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} libsodium soňky wersiýasyny algama başla..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} Libsodium soňky wersiýasy: ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
}
Install_Libsodium(){
	clear
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium ozal ustanowka edilen, Obnawit etjekmi？[y/N]"
		read -e -p "(adaty ýagdaýda: n): " yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "Goýbolsun..." && exit 1
		fi
	else
		echo -e "${Info} libsodium ustanowka edilmedik, ustanowka başlaýan..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} Şeýle şeýle şeýle..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} ýüklenilýär..."
		#https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} arhiwden çykarylýar..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} ustanowka..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} şeýle şeýle şeýle..."
		apt-get install -y build-essential
		echo -e "${Info} ýüklenýär..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} arhiwden çykarylýar..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} ustanowka..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} libsodium ustanowka edilmedi !" 
	echo && echo -e "${Info} libsodium üstünlikli ustanowka edildi !" && echo
}
# Çatylandygy barada maglumat
debian_View_user_connection_info(){
	clear
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Ulanyjy: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix} Port: ${Green_font_prefix}"${user_port}"${Font_color_suffix} IP sany: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix} Baglanan ulanyjylar: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Bar ulanyjylar: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Umumy IP salgylaryň sany: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
	clear
	main_menu
}
centos_View_user_connection_info(){
	clear
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} "|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Ulanyjy: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix} Port: ${Green_font_prefix}"${user_port}"${Font_color_suffix} IP sany: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix} Baglanan ulanyjylar: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Bar ulanyjylar: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Umumy IP salgylar: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
	clear
	main_menu
}
View_user_connection_info(){
	clear
	SSR_installation_status
	echo && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} (ipip.net) bellige alyndy，Eger IP salgy köp bolsa, köp wagt almagy mümkin ..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} Gerek sany saýla(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	clear
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	#echo "user_IP_1=${user_IP_1}"
	if [[ ! -z ${user_IP_1} ]]; then
	#echo "user_IP_total=${user_IP_total}"
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			#echo "IP=${IP}"
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			#echo "IP_address=${IP_address}"
			user_IP="${user_IP}\n${IP}(${IP_address})"
			#echo "user_IP=${user_IP}"
			sleep 1s
		done
	fi
}
# Ulanyjynyň Konfigurasiýasyny üýtgetmek
Modify_port(){
	clear
	List_port_user
	while true
	do
		echo -e "Akkauntuny uýtgetmeli ulanyjynyň portyny saýla"
		read -e -p "(adaty ýagdaýda: goýbolsun): " ssr_port
		[[ -z "${ssr_port}" ]] && echo -e "Goýbolsun..." && exit 1
		Modify_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${ssr_port}"',')
		if [[ ! -z ${Modify_user} ]]; then
			break
		else
			echo -e "${Error} Dogry port giriz !"
		fi
	done
}
######################Özümden goşdum##########################
List_port_user2(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Ulanyjy: ${Green_font_prefix} "${user_username}"${Font_color_suffix} Port: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\n"
	done
	echo -e ${user_list_all}
}
##########################################
Modify_Config(){
	clear
	SSR_installation_status
	echo && echo -e "
${Green_font_prefix}—————————————————————————————————————————————${Font_color_suffix}
 ${Green_font_prefix}0.${Font_color_suffix} Esasy menýuwa çykmak
${Green_font_prefix}—————————————————————————————————————————————${Font_color_suffix}
 ${Green_font_prefix}1.${Font_color_suffix} Ulanyjy goşmak
 ${Green_font_prefix}2.${Font_color_suffix} Ulanyjy pozmak
${Green_font_prefix}—————${Font_color_suffix} Ulanyjynyň konfigurasiýasyny üýtgetmek ${Green_font_prefix}—————${Font_color_suffix}
 ${Green_font_prefix}3.${Font_color_suffix} Ulanyjynyň parolyny üýtgetmek
 ${Green_font_prefix}4.${Font_color_suffix} Açaryň şifrlemesini üýtgetmek
 ${Green_font_prefix}5.${Font_color_suffix} Protokolyny üýtgetmek
 ${Green_font_prefix}6.${Font_color_suffix} obfs plagini üýtgetmek
 ${Green_font_prefix}7.${Font_color_suffix} Enjam sanyny uýtgetmek
 ${Green_font_prefix}8.${Font_color_suffix} Umumy tizliginiň limitini üýtgetmek
 ${Green_font_prefix}9.${Font_color_suffix} Ulanyjynyň tizliginiň limitini üýtgetmek
${Green_font_prefix}10.${Font_color_suffix} Umumy trafigi üýtgetmek
${Green_font_prefix}11.${Font_color_suffix} Gadagan edilen portlery üýtgetmek
${Green_font_prefix}12.${Font_color_suffix} Ähli konfigurasiýalary üýtgetmek
${Green_font_prefix}13.${Font_color_suffix} Konfigurasiýalary özüňçe üýtgetmek
${Green_font_prefix}14.${Font_color_suffix} Ulanyjynyň trafigini arassalamak
${Green_font_prefix}——————————————————${Font_color_suffix} Başgalar ${Green_font_prefix}———————————————————${Font_color_suffix}
${Green_font_prefix}15.${Font_color_suffix} IP salgyny üýtgetmek
${Green_font_prefix}—————————————————————————————————————————————${Font_color_suffix}
 
 ${Tip} Ulanyjynyň adyny we portyny üýtgetmek üçin konfigurasiýany özüňçe üýtgede gir !" && echo
	read -e -p "Sany saýla: " ssr_modify
	[[ -z "${ssr_modify}" ]] && Modify_Config
	if [[ ${ssr_modify} == "0" ]]; then
	main_menu
	elif [[ ${ssr_modify} == "1" ]]; then
		clear
		Add_port_user
	elif [[ ${ssr_modify} == "2" ]]; then
		clear
		Del_port_user
	elif [[ ${ssr_modify} == "3" ]]; then
		Modify_port
		Set_config_password
		Modify_config_password
	elif [[ ${ssr_modify} == "4" ]]; then
		Modify_port
		Set_config_method
		Modify_config_method
	elif [[ ${ssr_modify} == "5" ]]; then
		Modify_port
		Set_config_protocol
		Modify_config_protocol
	elif [[ ${ssr_modify} == "6" ]]; then
		Modify_port
		Set_config_obfs
		Modify_config_obfs
	elif [[ ${ssr_modify} == "7" ]]; then
		Modify_port
		Set_config_protocol_param
		Modify_config_protocol_param
	elif [[ ${ssr_modify} == "8" ]]; then
		Modify_port
		Set_config_speed_limit_per_con
		Modify_config_speed_limit_per_con
	elif [[ ${ssr_modify} == "9" ]]; then
		Modify_port
		Set_config_speed_limit_per_user
		Modify_config_speed_limit_per_user
	elif [[ ${ssr_modify} == "10" ]]; then
		Modify_port
		Set_config_transfer
		Modify_config_transfer
	elif [[ ${ssr_modify} == "11" ]]; then
		Modify_port
		Set_config_forbid
		Modify_config_forbid
	elif [[ ${ssr_modify} == "12" ]]; then
		Modify_port
		Set_config_all "Modify"
		Modify_config_all
	elif [[ ${ssr_modify} == "13" ]]; then
		clear
		Manually_Modify_Config
	elif [[ ${ssr_modify} == "14" ]]; then
		clear
		Clear_transfer
	elif [[ ${ssr_modify} == "15" ]]; then
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
	else
		Modify_Config
	fi
}
List_port_user(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"Ulanyjy: ${Green_font_prefix} "${user_username}"${Font_color_suffix} Port: ${Green_font_prefix}"${user_port}"${Font_color_suffix} Trafik: ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== Bar ulanyjylar: ${Green_background_prefix} "${user_total}" ${Font_color_suffix}"
	echo -e ${user_list_all}
	echo -e "=== Ähli ulanyjylaryň umumy trafigy: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_color_suffix}\n"
}
Add_port_user(){
	clear
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
echo -e "
 ${Green_font_prefix}1.${Font_color_suffix} Çalt (1 enjam)
 ${Green_font_prefix}2.${Font_color_suffix} Sazlamar bilen"
			read -e -p "(adaty ýagdaýda: Çalt): " howtoadd
			[[ -z ${howtoadd} ]] && howtoadd="1"
			if [[ ${howtoadd} == "1" ]]; then
				Set_config_all_fast
			elif [[ ${howtoadd} == "2" ]]; then
				Set_config_all
			else
				Set_config_all_fast
			fi
			match_port=$(python mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} [${ssr_port}] port ozal bar, başgasyny saýla !" && exit 1
			match_username=$(python mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} [${ssr_user}] ulanyjy ady ozal bar, başgasyny saýla !" && exit 1
			match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} Ulanyjy goşup bolmady ${Green_font_prefix}[Ulanyjynyň ady: ${ssr_user} , Port: ${ssr_port}]${Font_color_suffix} "
				break
			else
				Add_iptables
				Save_iptables
				echo -e "${Info} Ulanyjy üstünlikli goşuldy ${Green_font_prefix}[Ulanyjy: ${ssr_user} , Port: ${ssr_port}]${Font_color_suffix} "
				echo
				read -e -p "Ulanyjy sazlamasyny dowam etjekmi？[Y/n]:" addyn
				[[ -z ${addyn} ]] && addyn="y"
				if [[ ${addyn} == [Nn] ]]; then
					Get_User_info "${ssr_port}"
					View_User_info1
					break
				else
					echo -e "${Info} Ulanyjy sazlamasy dowam edilýär..."
				fi
			fi
		done
	fi
}
Del_port_user(){
	clear
	List_port_user
	while true
	do
		echo -e "Ulanyjy pozmak üçin portyny saýla"
		read -e -p "(adaty ýagdaýda: goýbolsun): " del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "Goýbolsun..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} Ulanyjyny pozup bolmady ${Green_font_prefix}[Port: ${del_user_port}]${Font_color_suffix} "
				break
			else
				Del_iptables
				Save_iptables
				echo -e "${Info} Ulanyjy üstýnlikli pozuldy ${Green_font_prefix}[Portт: ${del_user_port}]${Font_color_suffix} "
				echo
				read -e -p "Ulanyjy pozmany dowam etjekmi？[Y/n]: " delyn
				[[ -z ${delyn} ]] && delyn="y"
				if [[ ${delyn} == [Nn] ]]; then
						read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
						clear
						ssr_install
					break
				else
					echo -e "${Info} Ulanyjy pozmak dowam edilýär..."
					Del_port_user
				fi
			fi
			break
		else
			echo -e "${Error} Gerekli porty saýla !"
		fi
	done
}
Manually_Modify_Config(){
	SSR_installation_status
	nano ${config_user_mudb_file}
	echo "ShadowsocksR öçürip ýakmakçymy？[Y/n]" && echo
	read -e -p "(adaty ýagdaýda: y (hawa)): " yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_SSR
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENTERi bas..."
		clear
		ssr_install
	fi
}
Clear_transfer(){
	clear
	SSR_installation_status
	echo && echo -e "
 ${Green_font_prefix}1.${Font_color_suffix} Bir ulanyjynyň ulanan trafigini poz
 ${Green_font_prefix}2.${Font_color_suffix} Ähli ulanyjylaryň trafigini poz
 ${Green_font_prefix}3.${Font_color_suffix} Ulanyjylaryň trafigini öz-özini arassalaýjyny işe goýber
 ${Green_font_prefix}4.${Font_color_suffix} Ulanyjylaryň trafigini öz-özini arassalaýjyny saklamak
 ${Green_font_prefix}5.${Font_color_suffix} Ulanyjylaryň trafigini öz-özini arassalaýjynyň wagtyny sazlamak" && echo
	read -e -p "sany saýlaň: " ssr_modify
	[[ -z "${ssr_modify}" ]] && Clear_transfer
	if [[ ${ssr_modify} == "1" ]]; then
		Clear_transfer_one
	elif [[ ${ssr_modify} == "2" ]]; then
		echo "Siz hakykatdanam Ähli ulanyjylaryň trafigini pozmakçymy？[y/N]" && echo
		read -e -p "(adaty ýagdaýda: n (ýok)): " yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
			Clear_transfer_all
		else
			Clear_transfer
		fi
	elif [[ ${ssr_modify} == "3" ]]; then
		check_crontab
		Set_crontab
		Clear_transfer_all_cron_start
	elif [[ ${ssr_modify} == "4" ]]; then
		check_crontab
		Clear_transfer_all_cron_stop
	elif [[ ${ssr_modify} == "5" ]]; then
		check_crontab
		Clear_transfer_all_cron_modify
	else
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
	clear
	Clear_transfer
	fi
}
Clear_transfer_one(){
	clear
	List_port_user
	while true
	do
		echo -e "Trafigini pozmak üçin ulanyjynyň portyny saýla"
		read -e -p "(adaty ýagdaýda: goýbolsun): " Clear_transfer_user_port
		[[ -z "${Clear_transfer_user_port}" ]] && echo -e "Goýbolsun..." && exit 1
		Clear_transfer_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${Clear_transfer_user_port}"',')
		if [[ ! -z ${Clear_transfer_user} ]]; then
			match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}"|grep -w "clear user ")
			if [[ -z "${match_clear}" ]]; then
				echo -e "${Error} Ulanyjynyň trafigini pozup bolmady! ${Green_font_prefix}[Port: ${Clear_transfer_user_port}]${Font_color_suffix} "
			else
				echo -e "${Info} Ulanyjynyň trafigi üstünlikli pozuldy! ${Green_font_prefix}[Port: ${Clear_transfer_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} Gerekli porty saýlaň !"
		fi
	done
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
	clear
	ssr_install
}
Clear_transfer_all(){
	clear
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		match_clear=$(python mujson_mgr.py -c -p "${user_port}"|grep -w "clear user ")
		if [[ -z "${match_clear}" ]]; then
			echo -e "${Error} Ulanyjynyň trafigini pozup bolmady!  ${Green_font_prefix}[Port: ${user_port}]${Font_color_suffix} "
		else
			echo -e "${Info} Ulanyjynyň trafigi üstünlikli pozuldy! ${Green_font_prefix}[Port: ${user_port}]${Font_color_suffix} "
		fi
	done
	echo -e "${Info} Ulanyjylaryň ähli trafikleri pozuldy !"
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
	clear
	ssr_install
}
Clear_transfer_all_cron_start(){
	clear
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Ulanyjynyň trafigini yzygiderli pozuju işe goýberilmedik !" && exit 1
	else
		echo -e "${Info} Ulanyjynyň trafigini yzygiderli pozuju işe goýberilen !"
	fi
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
	clear
	ssr_install
}
Clear_transfer_all_cron_stop(){
	clear
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Ulanyjylaryň trafigini öz-özini arassalaýjyny saklamak başartmady !" && exit 1
	else
		echo -e "${Info} Ulanyjylaryň trafigini öz-özini arassalaýjyny saklamak başartdy !"
	fi
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
	clear
	ssr_install
}
Clear_transfer_all_cron_modify(){
	Set_crontab
	Clear_transfer_all_cron_stop
	Clear_transfer_all_cron_start
}
Set_crontab(){
	clear
		echo -e "Trafigi arassalamak üçin wagtlaýyn interwaly saýla
 === Formatyň düşündirilişi ===
 * * * * * Minut, sagat, gün, aý, hepde
 ${Green_font_prefix} 0 2 1 * * ${Font_color_suffix} Şul her aýyň 1 nji çislosyny, 2 sagady aňladýar
 ${Green_font_prefix} 0 2 15 * * ${Font_color_suffix} Şul her aýyň 15 nji çislosyny, 2 sagady aňladýar
 ${Green_font_prefix} 0 2 */7 * * ${Font_color_suffix} Şul her 7 gün 2 sagady aňladýar
 ${Green_font_prefix} 0 2 * * 0 ${Font_color_suffix} Her dynç güni aňladýar
 ${Green_font_prefix} 0 2 * * 3 ${Font_color_suffix} Her 3nji güni aňladýar" && echo
	read -e -p "(adaty ýagdaýda: 0 2 1 * * Garaz her aýyň 1 nji çislosyny, 2 sagady aňladýar): " Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR işe goýberilen !" && exit 1
	/etc/init.d/ssrmu start
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
	clear
	ssr_install
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR işe goýberilmedik !" && exit 1
	/etc/init.d/ssrmu stop
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
	clear
	ssr_install
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
	/etc/init.d/ssrmu start
	read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
	clear
	ssr_install
}
View_Log(){
	clear
	SSR_installation_status
	[[ ! -e ${ssr_log_file} ]] && echo -e "${Error} ShadowsocksRyň log ýazgysy ýok !" && exit 1
	echo && echo -e "${Tip} Log ýazgyny gömegi bez etmek üçin ${Red_font_prefix}Ctrl+C${Font_color_suffix} düwmäni basyň" && echo -e "Eger doly log ýazgyny görmek üçin ${Red_font_prefix}cat ${ssr_log_file}${Font_color_suffix}  ýazyň。" && echo
	tail -f ${ssr_log_file}
}
Set_config_connect_verbose_info(){
	clear
	SSR_installation_status
	[[ ! -e ${jq_file} ]] && echo -e "${Error} JQ ýok !" && exit 1
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "Log ýazgynyň şu wagtky tertibi: ${Green_font_prefix}ýönekeý（diňe ýalňyşlar）${Font_color_suffix}" && echo
		echo -e "Siz hakykatdan hem ony ${Green_font_prefix}Jikme-jik(Jikme-jik + ýalňyşlar)${Font_color_suffix} tertibe geçirmek isleýärsiňizmi？[y/N]"
		read -e -p "(adaty ýagdaýda: n (ýok)): " connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
			clear
			ssr_install
		fi
	else
		echo && echo -e "Log ýazgynyň şu wagtky tertibi: ${Green_font_prefix}Jikme-jik(Jikme-jik + ýalňyşlar)${Font_color_suffix}" && echo
		echo -e "Siz hakykatdan hem ony ${Green_font_prefix}ýönekeý（diňe ýalňyşlar）${Font_color_suffix} tertibe geçirmek isleýärsiňizmi？[y/N]"
		read -e -p "(adaty ýagdaýda: n (ýok)): " connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
			clear
			ssr_install
		fi
	fi
}
Set_crontab_monitor_ssr(){
	SSR_installation_status
	crontab_monitor_ssr_status=$(crontab -l|grep "ssrmu.sh monitor")
	if [[ -z "${crontab_monitor_ssr_status}" ]]; then
		echo && echo -e "Monitoringiň hazirki ýagdaýy: ${Green_font_prefix}öçük${Font_color_suffix}" && echo
		echo -e "Siz hakykatdan hem ${Green_font_prefix} ShadowsocksR monitoringini${Font_color_suffix} açmak isleýäňizmi？(SSR öçürseňiz ol awtomat ýagdaýda işe goýberiler)[Y/n]"
		read -e -p "(adaty ýagdaýda: y (hawa)): " crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="y"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_start
		else
			read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
			clear
			ssr_install
		fi
	else
		echo && echo -e "Monitoringin ýagdaýy: ${Green_font_prefix}açyk${Font_color_suffix}" && echo
		echo -e "Siz hakykatdan hem ${Green_font_prefix}ShadowsocksR monitoringini${Font_color_suffix} ýapmak isleýäňizmi？(SSR öçürseňiz ol awtomat ýagdaýda işe goýberiler)[y/N]"
		read -e -p "(adaty ýagdaýda: n (ýok)): " crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="n"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_stop
		else
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
		clear
		ssr_install
		fi
	fi
}
crontab_monitor_ssr(){
	SSR_installation_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] SSR işe goýberilmedik, Işe goýberilýär..." | tee -a ${ssr_log_file}
		/etc/init.d/ssrmu start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR işe goýberip bolmady..." | tee -a ${ssr_log_file} && exit 1
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR üstünlikli işe goýberildi..." | tee -a ${ssr_log_file} && exit 1
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR üstünlikli işleýär..." exit 0
	fi
}
crontab_monitor_ssr_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} ShadowsocksRyň monitoringini işe goýberip bolmady  !"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
		clear
	ssr_install
	else
		echo -e "${Info} ShadowsocksRyň monitoringi üstünlikli işe goýberildi !"
		read -n1 -r -p "Ozalky menýuwa dolanmak üçin ENETRi bas..."
		clear
	ssr_install
	fi
}
crontab_monitor_ssr_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Monitonigiň işleýän ShadowsocksR serweri saklanylýar, başa barmady !" && exit 1
	else
		echo -e "${Info} Monitonigiň işleýän ShadowsocksR serweri saklanylýar, üstünlikli başa bardy !"
	fi
}
# Menýuwyň statusy
menu_status(){
	if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Häzirki ýagdaýy: ${Green_font_prefix}Ustanowka edilen${Font_color_suffix} we ${Green_font_prefix}Işe goýberilen${Font_color_suffix}"
		else
			echo -e " Häzirki ýagdaýy: ${Green_font_prefix}Ustanowka edilen${Font_color_suffix}, ýöne ${Red_font_prefix}Işe goýberilmedik${Font_color_suffix}"
		fi
		cd "${ssr_folder}"
	else
		echo -e " Häzirki ýagdaýy: ${Red_font_prefix}Ustanowka edilmedik${Font_color_suffix}"
	fi
}
#######################
Other_menu(){
	clear
echo -e "${Green_font_prefix}==========================================${Font_color_suffix}
  ${Green_font_prefix}0.${Font_color_suffix} Esasy menýuwa çykmak
${Green}——————————————————— Başgalar ———————————————————${Font_color_suffix}
  ${Green_font_prefix}1.${Font_color_suffix} Log ýazgyň görnüşini üýtgetmek ${Yellow}Shadowsocks/ShadowsocksR${Font_color_suffix}${Font_color_suffix}
  ${Green_font_prefix}2.${Font_color_suffix} Monitoringiň ýagdaýy ${Yellow}Shadowsocks/ShadowsocksR${Font_color_suffix}
${Green_font_prefix}==========================================${Font_color_suffix}
 "
 echo && read -e -p "Gerekli sany saýlaň： " num
case "$num" in
	0)
	clear
	main_menu
	;;
	1)
	clear
	Set_config_connect_verbose_info
	;;
	2)
	clear
	Set_crontab_monitor_ssr
	;;
	*)
	clear
	Other_menu
	;;
esac
}
main_menu(){
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
clear
D=$(date +%d-%m-%Y)
echo -e "Şu gün: ${Ocean}$D${Font_color_suffix}; Skirptiň awtory: ${Yellow}ALPARSLAN${Font_color_suffix}; Telegram: ${Ocean}@alparslan_93${Font_color_suffix}; "
echo -e "${Green_font_prefix}==========================================${Font_color_suffix}
  ${Green_font_prefix}0.${Font_color_suffix} Esasy menýuwa çykmak
${Red}———————————— Ustanowka / Pozmak ————————————${Font_color_suffix}
  ${Green_font_prefix}1.${Font_color_suffix} Ustanowka etmek ${Yellow}Shadowsocks/ShadowsocksR${Font_color_suffix}
  ${Green_font_prefix}2.${Font_color_suffix} Pozmak ${Yellow}Shadowsocks/ShadowsocksR${Font_color_suffix}
${Green}—————————— Konfigurasiýany dolandyrmak ——————————${Font_color_suffix}
  ${Green_font_prefix}3.${Font_color_suffix} Ulanyjylar barada maglumaty görmek
  ${Green_font_prefix}4.${Font_color_suffix} Baglanan IP salgylasry görmek
  ${Green_font_prefix}5.${Font_color_suffix} Konfigurasiýa sazlamalary
  ${Green_font_prefix}6.${Font_color_suffix} Başga funksiýalar
${Yellow}——————————————————— Ýagdaýy ———————————————————${Font_color_suffix}
  ${Green_font_prefix}7.${Font_color_suffix} Işe goýbermek ${Yellow}Shadowsocks/ShadowsocksR${Font_color_suffix}
  ${Green_font_prefix}8.${Font_color_suffix} Saklamak ${Yellow}Shadowsocks/ShadowsocksR${Font_color_suffix}
  ${Green_font_prefix}9.${Font_color_suffix} Öçürip ýakmak ${Yellow}Shadowsocks/ShadowsocksR${Font_color_suffix}
 ${Green_font_prefix}10.${Font_color_suffix} Log ýazgyny görmek ${Yellow}Shadowsocks/ShadowsocksR${Font_color_suffix}
${Ocean}—————————————————— OpenVPN ———————————————————${Font_color_suffix}
 ${Green_font_prefix}11.${Font_color_suffix} ${Ocean}OpenVPN ${Font_color_suffix}
${Green_font_prefix}==========================================${Font_color_suffix}
 "
	menu_status
	echo && read -e -p "Gerekli sany saýlaň: " num
case "$num" in
	0)
	clear
	bash $HOME/vpn.sh
	;;
	1)
	Install_SSR
	Install_Libsodium
	;;
	2)
	Uninstall_SSR
	;;
	3)
	View_User
	;;
	4)
	View_user_connection_info
	;;
	5)
	Modify_Config
	;;
	6)
	Other_menu
	;;
	7)
	Start_SSR
	;;
	8)
	Stop_SSR
	;;
	9)
	Restart_SSR
	;;
	10)
	View_Log
	;;
	11)
	Openvpnnyr_install
	;;
	*)
	ssr_install
	;;
esac
fi
}
main_menu
