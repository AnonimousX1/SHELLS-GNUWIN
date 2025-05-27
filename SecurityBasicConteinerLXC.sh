#!/bin/bash

# --- VARIAVEIS ---
USERNAME="usuario_novo"
SSH_PORT="22" # Mude se quiser uma porta diferente

# Defina as regras de porta/protocolo aqui.
# Formato: "porta/protocolo". Exemplos: "80/tcp", "443/tcp", "5000/tcp", "53/udp"
# Se uma porta precisa de TCP e UDP, adicione duas entradas: "53/tcp", "53/udp"
PORT_RULES=(
    "80/tcp"
    "443/tcp"
    "5000/tcp"
    # Adicione mais regras conforme necessário, por exemplo:
    # "53/udp"
    # "53/tcp"
    # "8080/tcp"
)

echo "Iniciando configuração de segurança básica do container..."

# 1. Atualizar o sistema
echo "Atualizando pacotes do sistema..."
apt update && apt upgrade -y
apt autoremove -y

# 2. Instalar ferramentas de segurança (UFW, Fail2ban)
echo "Instalando UFW e Fail2ban..."
apt install -y ufw fail2ban

# 3. Configurar UFW (Firewall no container)
echo "Configurando UFW..."
ufw enable
ufw default deny incoming
ufw default allow outgoing

# Permitir SSH (na porta configurada)
echo "Permitindo porta SSH $SSH_PORT/tcp..."
ufw allow "$SSH_PORT/tcp"

# Aplicar regras de portas personalizadas
if [ ${#PORT_RULES[@]} -gt 0 ]; then
    echo "Aplicando regras de portas personalizadas..."
    for rule in "${PORT_RULES[@]}"; do
        echo "Permitindo regra: $rule"
        ufw allow "$rule"
    done
else
    echo "Nenhuma regra de porta personalizada definida."
fi

#Mostrar status de configuração de ufw
ufw status verbose

# 4. Configurar Fail2ban
echo "Configurando Fail2ban..."
# Copia o arquivo de configuração padrão para edição
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Habilita o jail para SSH (já vem habilitado por padrão em jail.local, mas bom verificar)
# Você pode editar jail.local para ajustar bantime, findtime, maxretry
sed -i 's/^enabled = false$/enabled = true/' /etc/fail2ban/jail.d/sshd.conf # Certifica que o jail SSH está habilitado
systemctl enable fail2ban
systemctl start fail2ban

# 5. Segurança do SSH
echo "Configurando segurança do SSH..."
# Desabilitar login de root
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Desabilitar autenticação por senha (se for usar apenas chaves SSH)
# IMPORTANTE: Garanta que você configurou chaves SSH para o seu 'USERNAME' antes de fazer isso!
# sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
# sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Mudar a porta SSH (se configurado)
if [ "$SSH_PORT" != "22" ]; then
    echo "Alterando porta SSH para $SSH_PORT..."
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
fi

systemctl restart sshd

# 6. Criar novo usuário e forçar troca de senha no primeiro login
echo "Criando usuário '$USERNAME' e forçando troca de senha no primeiro login..."
useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:senha_temp_inicial" | chpasswd # Define uma senha temporária
chage -d 0 "$USERNAME"                         # Força a troca de senha no próximo login

echo "Adicione o usuário '$USERNAME' ao grupo sudo para privilégios administrativos."
usermod -aG sudo "$USERNAME"

echo "Configurações básicas de segurança finalizadas. Lembre-se de:"
echo " - Adicionar suas chaves SSH para '$USERNAME'."
echo " - Testar o login do novo usuário."
echo " - Verificar as regras do firewall do Proxmox host também!"
echo " - Remover ou desabilitar a senha temporária do '$USERNAME' após o primeiro login."
echo " - Trocar a senha do usuário root (se não tiver feito)."
echo " - Validar todas as configurações de acordo com sua política de segurança."
