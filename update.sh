#!/bin/bash

echo "Executando script de atualização"
echo "Aguardando senha para usuário root..."
stty -echo # comando para desativar saida
read password
stty echo # comando para ativar saida
#Verificar senha
echo "$password" | sudo -Sk printf "" 2>/dev/null
echo "Verificar senha..."

if [ $? != 0 ]; then
    echo "Senha incorreta, script encerrado"
    exit
fi

echo "Senha Correta..."
echo "$password" | sudo -S apt update > /dev/null 2>&1
upgradable_packages=$(echo "$password" | sudo -S apt list --upgradable 2>/dev/null | grep -v "Listing...")

if [ -z "$upgradable_packages" ]; then
    echo "Não há atualizações disponíveis."
else
    echo "As seguintes atualizações estão disponíveis"
    echo "$upgradable_packages"
    
    #Pergunta se deseja atualizar
    read -p "Você deseja atualizar o sistema sim(S) ou não(N): " response
    if [ "$response" == "S" || "$response" == "s" ]; then
        echo "$password" | sudo -S apt upgrade  
        echo "Atualizando o sistema..."
    else
        echo "Atualização não desejada."
    fi
fi
