#!/bin/bash

##############################################################################
#  certificate-creation.sh version 3.2
#  Recreates all server certificates on OES1, OES2, and OES 11.
#  Copyright (C) 2001, 2008 Novell, Inc.
#  Copyright (C) 2016 Chad Sutton
##############################################################################
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  If you desired to have a copy of the GNU General Public License,
#  write to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#  Authors/Contributors:
#     Jeremy Meldrum (jmeldrum@novell.com)
#	  Chad Sutton (casutton@noctrl.edu) (csutton@chadarius.com)
##############################################################################
fileType="pfx"
dirPath=""
fileName=""
extension=""
serverType=""
filePath=""
lumFileName=""
eDireUserName=""
nam_conf_server=""
ipsmd_conf_dsserver1=""
orgName=""
ldapFQN=""
ouName=""
pass=""
exportPass=""
sameVar="0"
printFilesSame="0"
ipsmdExist="0"
contextOrg="0"
contextFlag="0"
reloadFlag="0"
lumFlag="0"
fileFlag="1"
iprint_g_server=""
continueCode="0"
postCode="0"
certCode="0"





#This will read in each of the parameters
ParseString ()
{
        dirPath=${filePath%/*}
        #dirPath=${dirPath//[[:space:]]/'\ '}
        fileName=${filePath##*/}
        extension=${filePath##*.}
        #echo "The FilePath is $filePath"
        #echo "The Directory Path is $dirPath"
        #echo "The File Name is: $fileName"

}

getEdirUserName ()
{	
	echo ""
	echo -n "Please enter your FQN (Use Dot Notation--Example: admin.novell): "
	read eDireUserName
	echo -n "Please Enter Password: "
	stty -echo
	read pass
	echo ""
	stty echo	
	
	printf "\n"
	#obtains information for the cert.pfx
	echo -n "Please enter the password supplied during certificate export: "
	stty -echo
	read exportPass
	echo ""
	stty echo	
}
setVariables ()
{
	
	
	#This gives us the preferred server's DNS or IP address from the nam.conf
	nam_conf_server=`grep -i preferred-server /etc/nam.conf | cut -d= -f2`
	
	if [ -e /etc/opt/novell/iprint/conf/ipsmd.conf ]; then
		#This gives us the Dsserver1 DNS or IP address from the ipsmd.conf
		ipsmd_conf_dsserver1=`grep -i DSServer1 /etc/opt/novell/iprint/conf/ipsmd.conf | tr -s ' ' | cut -d" " -f2`
		iprint_g_server=` grep -i "#" /etc/opt/novell/iprint/httpd/conf/iprint_g.conf --invert-match | grep -i ServerName | tr -s ' ' | cut -d" " -f3 | cut -d: -f1`
	else
		ipsmdExist="1"
	fi

	#comparing if the the ipsmd.conf file and the name.conf file is the same.
	if [ $nam_conf_server == $ipsmd_conf_dsserver1 ]; then
		sameVar="1"	
	fi
	if [ $iprint_g_server == $ipsmd_conf_dsserver1 ]; then
		printFilesSame="1"	
	fi
	
	#gets the ldap formated context of a user.	
	tmplength=$(echo $eDireUserName | tr -dc '.' | wc -c )
	context_length=`expr $tmplength + 1`	
	cName=$(echo $eDireUserName | cut -d. -f1 )
	orgName=$(echo $eDireUserName | cut -d. -f$context_length )
	
	#concatenates  the FQN together		
	if [ $tmplength = "1" ]; then 	    
	    ldapFQN="cn=${cName},o=${orgName}"
	else
        	ouName=$(echo $eDireUserName | cut -d. -f2-$tmplength | sed 's/\./,ou\=/g')		    
        	ldapFQN="cn=${cName},ou=${ouName},o=${orgName}" 	    
	fi	
	#echo "ldapFQN: $ldapFQN"
	#echo "sameVar: $sameVar"
	#echo "printFilesSame: $printFilesSame"
	#echo "ipsmd_conf_dsserver1: $ipsmd_conf_dsserver1"
	#echo "iprint_g_server: $iprint_g_server"
	#echo "nam_conf_server: $nam_conf_server"
}
testCerts ()
{	
	#sameVar=0
	#printFilesSame=0
	#If both the ipsmd.conf and nam.conf files contain the same server value
	#if [ $sameVar = "1" ]; then	
	if [ $sameVar = "1" ] && [ $printFilesSame = "1" ]; then

	#echo "ldap fqn: $ldapFQN"
		echo "***Checking SSCert.der using $ipsmd_conf_dsserver1 using the ipsmd.conf and nam.conf files................."
		certOut=`/opt/novell/eDirectory/bin/ldapsearch -h $ipsmd_conf_dsserver1 -p 636 -D $ldapFQN -w $pass -b $contextOrg -s base -e /etc/opt/novell/certs/SSCert.der cn 2>&1`
		returnCode="$?"
		echo "/opt/novell/eDirectory/bin/ldapsearch -h $ipsmd_conf_dsserver1 -p 636 -D $ldapFQN -W -b $contextOrg -s base -e /etc/opt/novell/certs/SSCert.der"
		
		
		if [ $returnCode = "0" ] ; then
			echo -e "\033[32mSUCCESSFUL\033[0m  connection over 636 with LDAP"
		else
			if [ $1 == "Precheck" ]; then
				continueCode=1 
			else
				postCode=1
			fi			
			echo -e "\033[31mFAILED\033[0m to connect over 636 with LDAP"
			echo "Command Used: /opt/novell/eDirectory/bin/ldapsearch -h $ipsmd_conf_dsserver1 -p 636 -D $ldapFQN -W -b $contextOrg -s base -e /etc/opt/novell/certs/SSCert.der cn"
		fi	
				
		echo ""
		echo "***Checking SSCert.pem using $nam_conf_server and openssl s_client using the ipsmd.conf, nam.conf and iprint_g.conf files.........."
		certOut=`openssl s_client -connect $nam_conf_server:636 -CAfile /etc/opt/novell/certs/SSCert.pem 2>&1 | grep error`
		returnCode="$?"
		
		if [ $returnCode = "1" ] ; then
			echo -e "\033[32mSUCCESSFUL\033[0m  connection over 636 using openssl"
		else
			if [ $1 == "Precheck" ]; then
				continueCode=1 
			else
				postCode=1
			fi			
			echo -e "\033[31mFAILED\033[0m to connect over 636 using openssl "
			echo "Command Used: openssl s_client -connect $nam_conf_server:636 -CAfile /etc/opt/novell/certs/SSCert.pem" 
		fi		
		
				echo ""
		echo "***Checking SSCert.pem using $nam_conf_server  .........."
		certOut=`openssl verify /etc/opt/novell/certs/SSCert.pem | grep OK`
		returnCode="$?"
		
		if [ $returnCode = "0" ] ; then
			echo ""
			echo -e "\033[32mSUCCESSFUL\033[0m  openssl verification"
		else
			if [ $1 == "Precheck" ]; then
				continueCode=1 
			else
				postCode=1
			fi			
			echo -e "\033[31mFAILED\033[0m to verify certificate using openssl "
			echo "Command Used: openssl verify /etc/opt/novell/certs/SSCert.pem" 
		fi		
	
	else
		#if ipsmd.conf file does exits but the ipsmd and nam.conf file is different.
		if [ $ipsmdExist = "0" ]; then
		
			echo "***Checking SSCert.der using $ipsmd_conf_dsserver1 from the ipsmd.conf file................."
			certOut=`/opt/novell/eDirectory/bin/ldapsearch -h $ipsmd_conf_dsserver1 -p 636 -D $ldapFQN -w $pass -b $contextOrg -s base -e /etc/opt/novell/certs/SSCert.der cn 2>&1`
			returnCode="$?"
			echo "/opt/novell/eDirectory/bin/ldapsearch -h $ipsmd_conf_dsserver1 -p 636 -D $ldapFQN -W -b $contextOrg -s base -e /etc/opt/novell/certs/SSCert.der"
			if [ $returnCode = "0" ] ; then
				echo ""
				echo -e "\033[32mSUCCESSFUL\033[0m  connection over 636 with LDAP"
			else
			if [ $1 == "Precheck" ]; then
				continueCode=1 
			else
				postCode=1
			fi
									
				echo -e "\033[31mFAILED\033[0m to connect over 636 with LDAP" 
				echo "Command Used: /opt/novell/eDirectory/bin/ldapsearch -h $ipsmd_conf_dsserver1 -p 636 -D $ldapFQN -W -b $contextOrg -s base -e /etc/opt/novell/certs/SSCert.der cn"
			fi
			
			#Checking through an LDAP query  whether the ip in the iprint_g.conf works over 636
			echo ""
			echo "***Checking servercert.pem using $iprint_g_server and openssl from the iprint_g.conf file................."
			echo -e "Press the \033[32mEnter\033[0m key"
			certOut=`openssl s_client -connect $iprint_g_server:636 -CAfile /etc/ssl/servercerts/servercert.pem 2>&1 | grep error `			        
			returnCode="$?"				
			printf "\n"
			if [ $returnCode = "1" ] ; then
				echo -e "\033[32mSUCCESSFUL\033[0m  connection over 636 with openssl....................."
			else
			if [ $1 == "Precheck" ]; then
				continueCode=1 
			else
				postCode=1
			fi					
				
				echo -e "\033[31mFAILED\033[0m to connect over 636 with LDAP" 
				echo "Command Used: openssl s_client -connect $iprint_g_server:636 -CAfile /etc/ssl/servercerts/servercert.pem"
			fi
			
			echo ""
			echo "***Checking servercert.pem using $iprint_g_server and openssl verify................."
			certOut=`openssl verify /etc/ssl/servercerts/servercert.pem | grep OK `
			returnCode="$?"
			if [ $returnCode = "0" ] ; then
				echo ""
				echo -e "\033[32mSUCCESSFUL\033[0m  openssl verification"
				
				
			else
			if [ $1 == "Precheck" ]; then
				continueCode=1 
			else
				postCode=1
			fi					
				
				echo -e "\033[31mFAILED\033[0m to verify certificate using openssl" 
				echo "Command Used: openssl verify /etc/ssl/servercerts/servercert.pem | grep OK"
			fi					
		fi
	
		
		
		echo ""
		echo "***Checking servercert.pem using $nam_conf_server from the nam.conf file................"
		echo -e "Press the \033[32mEnter\033[0m key"
			certOut=`openssl s_client -connect $nam_conf_server:636 -CAfile /etc/ssl/servercerts/servercert.pem 2>&1 | grep error`			        
			returnCode="$?"			
			if [ $returnCode = "1" ] ; then
				echo -e "\033[32mSUCCESSFUL\033[0m  connection over 636 with openssl"
			else
			if [ $1 == "Precheck" ]; then
				continueCode=1 
			else
				postCode=1
			fi					
				
				echo -e "\033[31mFAILED\033[0m to connect over 636 with LDAP" 
				echo "Command Used: openssl s_client -connect $nam_conf_server:636 -CAfile /etc/ssl/servercerts/servercert.pem"
			fi
	
	fi	
	#echo "continueCode: $continueCode"
	if [ $continueCode == "0" ] && [ $1 = "Precheck" ] ; then
		echo '#===========Precheck a Success ============================================#'
		echo "All LDAP and openssl connections were successfully made over 636 using the IP Addresses and DNS names listed above"  
		printf "Would you like to continue regenerating these certificates? [yes or no] "		
		read continue
		tmpVar=`echo $continue | tr "[:upper:]" "[:lower:]"`
		#echo "tmpVar: $tmpVar"

		if [ $tmpVar == "no" ] || [ $tmpVar == "n" ]; then
			exit 0	
		fi 
		echo ""
		
	fi
#recreateLumCert
#exit 0
}

checkCerts ()
{
	echo ""
	echo "#=========== $1 =====================================#"

		testCerts $1 
}

BackupFile ()
{
        time=$(date +"%y%m%d_%H%M_%S")
        
        if [ "$serverType" == "s932" ] || [ "$serverType" == "s10" ]; then
                printf "\n"
                echo '#===========Backing Up Files============================================#'
                echo "Backing up /etc/ssl/servercerts/servercert.pem................."
                #Backing up server key and certificate
                cp /etc/ssl/servercerts/servercert.pem /etc/ssl/servercerts/servercert.pem-$time
                echo "Backing up /etc/ssl/servercerts/serverkey.pem................."
                cp /etc/ssl/servercerts/serverkey.pem /etc/ssl/servercerts/serverkey.pem-$time
                
                derFile="$(find /var/lib/novell-lum/ -type f | grep [0-9]*.[0-9]*.[0-9]*.[0-9]*.der$)"
                lumFileName=${derFile##*/}
                echo "Backing up /var/lib/novell-lum/$lumFileName............."
                cp /var/lib/novell-lum/$lumFileName /var/lib/novell-lum/$lumFileName-$time
        fi
        if [ "$serverType" == "s932" ]; then
                #backing up trusted root certificate
                echo "Backing up /etc/opt/novell/SSCert.pem......................"
                cp /etc/opt/novell/SSCert.pem /etc/opt/novell/SSCert.pem-$time
                echo "Backing up /etc/opt/novell/SSCert.der......................"
                cp /etc/opt/novell/SSCert.der /etc/opt/novell/SSCert.pem-$time
                
        elif [ "$serverType" == 's10' ]; then
                #backing up trusted root certificate
                echo "Backing up /etc/opt/novell/certs/SSCert.pem......................"
                cp /etc/opt/novell/certs/SSCert.pem /etc/opt/novell/certs/SSCert.pem-$time
                echo "Backing up /etc/opt/novell/certs/SSCert.der......................"
                cp /etc/opt/novell/certs/SSCert.der /etc/opt/novell/certs/SSCert.der-$time
	
	else
                echo "This server in not SUSE Linux Enterpriser Server 9 or 10"                
        fi

}

FileExtractionAndInstall ()
{
        
        if [ "$serverType" == "s932" ] || [ "$serverType" == "s10" ]; then
                #Extract the Server and Key and Certificate
                printf "\n"
                echo '#===========Extracting and Installing Certificates======================#'
                echo "Extracting the Server and Key and Certificate................"
                openssl pkcs12 -in "$filePath" -passin pass:$exportPass -nodes -clcerts -out servcert.pem
                returnCode="$?"
		if [ $returnCode != "0" ] ; then
			certCode=1		
		fi
                
                #Install the Private key
                echo "Installing the Private Key..................................."
                openssl rsa -in servcert.pem -out /etc/ssl/servercerts/serverkey.pem
                returnCode="$?"
		if [ $returnCode != "0" ] ; then
			certCode=1		
		fi
                
                #Install the Public Key Certificate
                echo "Installing the Public Certificate............................."
                openssl x509 -in servcert.pem -out /etc/ssl/servercerts/servercert.pem
                returnCode="$?"
		if [ $returnCode != "0" ] ; then
			certCode=1		
		fi  		              
                rm -r servcert.pem
                
        fi
        
        if [ "$serverType" == "s932" ]; then
                #Extract and Install the Trusted Root Certificate
                echo "Extracting and Installing the Trusted Root Certificate........."
                openssl pkcs12 -in "$filePath" -passin pass:$exportPass -nokeys -nodes -cacerts -out /etc/opt/novell/SSCert.pem
                returnCode="$?"
		if [ $returnCode != "0" ] ; then
			certCode=1		
		fi                                
                
                
                #Install the Trusted Rood Certificate (binary Version)
                echo 'Installing the Trusted Rood Certificate (binary Version)........'
                openssl x509 -outform der -in /etc/opt/novell/SSCert.pem -out /etc/opt/novell/SSCert.der
                returnCode="$?"
		if [ $returnCode != "0" ] ; then
			certCode=1		
		fi                                
                
        fi
        if [ "$serverType" == "s10" ]; then
                               
                #Extract and Install the Trusted Root Certificate
                echo "Extracting and Installing the Trusted Root Certificate........."
                openssl pkcs12 -in "$filePath" -passin pass:$exportPass -nokeys -nodes -cacerts -out /etc/opt/novell/certs/SSCert.pem
                returnCode="$?"
		if [ $returnCode != "0" ] ; then
			certCode=1		
		fi                                
                
                #Install the Trusted Rood Certificate (binary Version)
                echo 'Installing the Trusted Rood Certificate (binary Version)........'
                openssl x509 -outform der -in /etc/opt/novell/certs/SSCert.pem -out /etc/opt/novell/certs/SSCert.der
                returnCode="$?"
		if [ $returnCode != "0" ] ; then
			certCode=1		
		fi                    
        fi      
        
}

findServerVersion ()
{
	#Finds the what version of OS the server is
	if grep -i "enterprise[[:space:]]*server[[:space:]]*1" /etc/SuSE-release | grep -i [3,5,6]86 &>/dev/null; then
                serverType=s10
        elif grep -i "enterprise[[:space:]]*server[[:space:]]*1" /etc/SuSE-release 2>/dev/null | grep -i x86_64 &>/dev/null; then
                serverType=s10
        elif grep -i "enterprise[[:space:]]*server[[:space:]]*9" /etc/SuSE-release 2>/dev/null | grep i[3,5,6]86 &>/dev/null; then
                serverType=s932
        else
                serverType=unknown
        fi          
}

recreateLumCert ()
{

	lowerFQN=`echo $ldapFQN | tr "[:upper:]" "[:lower:]"`

	#temporarily exports the password so that we are not prompted for it.
	if [ $lowerFQN == "`grep -i admin-fdn /etc/nam.conf | cut -d= -f2- | tr "[:upper:]" "[:lower:]"`" ] ; then	 
		export LUM_PWD=$pass
	
	fi
	
        echo 'Restarting nldap....................................#'
                nldap -u
                nldap -l	
        printf "\n"
        echo '#===========Recreating Lum Certificate===================================#'
        if [ "$serverType" == "s932" ] || [ "$serverType" == "s10" ]; then
                /usr/bin/namconfig -k           
        fi
        
        #unsets the exported password
	if [ $lowerFQN == "`grep -i admin-fdn /etc/nam.conf | cut -d= -f2- | tr "[:upper:]" "[:lower:]"`" ] ; then	
		unset LUM_PWD	
	fi   
        
        
}

checkOESVersion ()
{
	oesVersion=$(cat /etc/novell-release | grep VERSION | cut -d= -f2 |sed -e 's/^[ \t]*//')
}

# return 0 if program version is equal or greater than check version
# http://fitnr.com/bash-comparing-version-strings.html - Louis Marascio
check_version()
{
    local version=$1 check=$2
    local winner=$(echo -e "$version\n$check" | sed '/^$/d' | sort -nr | head -1)
    [[ "$winner" = "$version" ]] && return 0
    return 1
}

reloadServices ()
{
	printf "\n"
	echo '#===========Reloading Services==========================================#'
	if check_version "$oesVersion" "11"; then
		echo "OES version is 11 or higher"
	else
		echo 'OES 10 Restarting owcimomd..........................#'
		rcowcimomd restart
	fi
	echo 'Restarting namcd....................................#'
			rcnamcd restart
	echo 'Restarting apache2..................................#'
			rcapache2 restart

	printf "\n"
}
checkUser ()
{
	user=`whoami`
	if [ $user = "root" ]; then
		userError=0
		#printf "You are now inside the if statement.\n"
	
	else
		printf "\nYou are currently not logged in as a root user.  Please \"su\" to root before continuing.\n\n "
		exit 3
	fi
}

finalStatus ()
{

	echo '#=========== Results Summary ====================================#'
	
	if [ $contextFlag = "1" ]; then
	
		if [ $continueCode == "1" ]  ; then
			echo -e "One or more LDAP searches during the Precheck phase \033[31mFAILED\033[0m"
		else
			echo -e "All LDAP searches during the Precheck \033[32mSUCCEEDED\033[0m"
		
		fi
		
		if [ $postCode == "1" ] ; then
			echo -e "One or more ldap searches during the Postchek phase \033[31mFAILED\033[0m"
		else
			echo -e "All LDAP searches during the Postcheck \033[32mSUCCEEDED\033[0m"
		fi	
	fi
	if [ $certCode == "1" ] ; then
		echo -e "One or more creations of the certificates \033[31mFAILED\033[0m"
	else
		echo -e "All creations of the certificates \033[32mSUCCEEDED\033[0m"
	fi		
	printf "\n\n"

}

execCalls ()
{
	if [ $fileFlag = "1" ] ; then			
		#if [ $contextFlag = "1" ] ; then		        
			getEdirUserName
			setVariables
			checkOESVersion			
			if [ $contextFlag = "1" ] ; then
				checkCerts 'Precheck'
			fi
			BackupFile
			FileExtractionAndInstall
			if [ $contextFlag = "1" ] ; then
				checkCerts 'Postcheck'
			fi
			echo ""	
			
			if [ $lumFlag = "1" ] ; then
				recreateLumCert			
			fi
			
			if [ $reloadFlag = "1" ] ; then
				reloadServices			
			fi
			finalStatus		
		#else
			
			#echo "No context was specified."
			
			#echo "Please Try Again."
		#fi
	fi


}

checkUser

while getopts f:c:hrl parmlist
do

case "$parmlist" in
        # this case is used to create certificates and to specify the source file
        f)
                findServerVersion
                filePath="$OPTARG"
                #echo "$FilePath"
                if [ -f "$filePath" ]; then      
			
                        ParseString

                        if [ "$extension" == "$fileType" ]; then
                        	fileFlag="1"
                        else
                                echo 'A valid certificate file was not specified.'
                                echo 'Please Try Again.'
                                
                        fi
                else
                        echo "ERROR: File not found - $filePath" 
                        exit 3
                fi
        ;;
        # Displays the help menu
        h)     
        	printf "\n"
        	printf "\n" 
                echo '#=======================================================#'
                echo '#             Certificate Creation Tool                 #'      
                echo '#             Version 3.1 March  5, 2012                #'
                echo '#=======================================================#'
                printf "\n\n"
                echo 'USAGE: ./certificate-creation.sh -f /directory/fileName.pfx -l -r'
                printf "\n"
                echo 'MANDATORY ARGUMENTS:'
                printf "\n"
                echo '  -f      Used to denote a file name and path'
                echo '  -l      Creates LUM certificate'
                echo '  -r      Restarts namcd, owcimomd, nlap, and apache2'
                
                printf "\n"        
                echo 'OPTIONAL ARGUMENTS:'
                echo '  -c      Specifies the context in the Organization'
                echo ' 		Pre and Post checks to validate certs occur'
                echo '  -h      Help Menu' 
                printf "\n"
                echo 'ABOUT:'
                echo 'This tool is used to create both the Server Certificate and Trusted Root Certificate'
                echo 'You must first create the exported certificate from iManager'
                printf "\n"
                echo 'The directions to export the .pfx file through iManager can be found here:'
                echo 'http://wiki.novell.com/index.php/Recreating_Server_Certificates_on_OES_Linux'
                printf "\n"
                exit 0
        
        ;;
        #Used for creation of the novell-lum certificate
        l)               
                lumFlag="1"        
        ;;
        # Used to restart the required services
        r)   
                reloadFlag="1"        
        ;;
	c)		
		contextOrg="$OPTARG"		
		if [ -n "$contextOrg" ]; then
		contextFlag="1"		
		fi  		
	;;      
        # This catches all other invalid parameters
        *)
                echo 'No parameters were specified.  Please run the command again with a -h for more help'
                
        ;;
esac
done
execCalls
shift $(($OPTIND - 1))
