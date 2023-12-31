#!/bin/bash

echo "Executando script de atualização"
echo "Aguardando senha para usuário root..."
stty -echo # comando para desativar saída
read password
stty echo # comando para ativar saída
# Verificar senha
echo "Verificar senha..."
echo "$password" | sudo -Sk printf "" 2>/dev/null

if [ $? != 0 ]; then
    echo "Senha incorreta, script encerrado"
    exit
fi

echo "$password" | sudo -S apt update > /dev/null 2>&1
upgradable_packages=$(echo "$password" | sudo -S apt list --upgradable 2>/dev/null | grep -v "Listing...")

if [ -z "$upgradable_packages" ]; then
    echo "Não há atualizações disponíveis."
else
    echo "As seguintes atualizações estão disponíveis"
    echo "$upgradable_packages"
    
    # Pergunta se deseja atualizar
    read -p "Você deseja atualizar o sistema sim(S) ou não(N): " response
    case "$response" in
        [Ss]*)
            echo "$password" | sudo -S apt upgrade
            echo "Atualizando o sistema..."
            ;;
        *)
            echo "Atualização não desejada."
            ;;
    esac
fi

