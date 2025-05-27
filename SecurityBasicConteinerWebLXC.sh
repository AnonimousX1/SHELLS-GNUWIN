#!/bin/bash

# --- VARIAVEIS ---
USERNAME="usuario_novo"
SSH_PORT="22" # Mude se quiser uma porta diferente

# Defina as regras de porta/protocolo para tráfego ENTRANDO no container.
# Formato: "porta/protocolo". Exemplos: "80/tcp", "443/tcp", "5000/tcp", "53/udp"
PORT_RULES_IN=(
    "80/tcp"
    "443/tcp"
    "5000/tcp"
    # Adicione mais regras conforme necessário, por exemplo:
    # "53/udp"
    # "53/tcp"
    # "8080/tcp"
)

# Configurações para tráfego de SAÍDA permitido
ALLOW_OUT_DNS="yes"           # Permitir DNS (porta 53 tcp/udp)
ALLOW_OUT_NTP="yes"           # Permitir NTP (porta 123 udp) - para sincronia de tempo
ALLOW_OUT_HTTP_HTTPS="yes"    # Permitir HTTP/HTTPS (porta 80/443 tcp) - para apt, APIs, etc.
# Adicione aqui outras IPs/Portas específicas que o container PRECISA acessar na internet
# Exemplo: ALLOW_OUT_SPECIFIC_IPS_PORTS=("198.51.100.5/tcp" "203.0.113.10:8080/tcp")
ALLOW_OUT_SPECIFIC_IPS_PORTS=()


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
# Política padrão para tráfego ENTRANDO: bloquear tudo
ufw default deny incoming
# Política padrão para tráfego SAINDO: bloquear tudo (abordagem holística/permissiva)
ufw default deny outgoing
# Permitir tráfego relacionado e estabelecido (importante para conexões de retorno)
ufw allow in on lo # Permitir todo tráfego na interface de loopback
ufw allow out on lo
ufw allow related,established

# Permitir SSH ENTRANDO (na porta configurada)
echo "Permitindo tráfego SSH ENTRANDO na porta $SSH_PORT/tcp..."
ufw allow in "$SSH_PORT/tcp" # Especificar 'in' para clareza

# Aplicar regras de portas personalizadas para tráfego ENTRANDO
if [ ${#PORT_RULES_IN[@]} -gt 0 ]; then
    echo "Aplicando regras de portas personalizadas para tráfego ENTRANDO..."
    for rule_in in "${PORT_RULES_IN[@]}"; do
        echo "Permitindo regra ENTRANDO: $rule_in"
        ufw allow in "$rule_in" # Especificar 'in' para clareza
    done
else
    echo "Nenhuma regra de porta personalizada para tráfego ENTRANDO definida."
fi

# Permitir tráfego de SAÍDA essencial
echo "Configurando permissões de SAÍDA essenciais..."
if [ "$ALLOW_OUT_DNS" = "yes" ]; then
    echo "Permitindo tráfego DNS SAINDO (porta 53/tcp e 53/udp)..."
    ufw allow out to any port 53 proto tcp
    ufw allow out to any port 53 proto udp
fi

if [ "$ALLOW_OUT_NTP" = "yes" ]; then
    echo "Permitindo tráfego NTP SAINDO (porta 123/udp)..."
    ufw allow out to any port 123 proto udp
fi

if [ "$ALLOW_OUT_HTTP_HTTPS" = "yes" ]; then
    echo "Permitindo tráfego HTTP SAINDO (porta 80/tcp)..."
    ufw allow out to any port 80 proto tcp
    echo "Permitindo tráfego HTTPS SAINDO (porta 443/tcp)..."
    ufw allow out to any port 443 proto tcp
fi

# Aplicar regras de SAÍDA personalizadas para IPs/Portas específicos
if [ ${#ALLOW_OUT_SPECIFIC_IPS_PORTS[@]} -gt 0 ]; then
    echo "Aplicando regras de SAÍDA personalizadas para IPs/Portas específicos..."
    for rule_out_specific in "${ALLOW_OUT_SPECIFIC_IPS_PORTS[@]}"; do
        # A regra pode ser "ip_destino" ou "ip_destino:porta" ou "ip_destino/protocolo" ou "ip_destino:porta/protocolo"
        # UFW é flexível. Ex: "1.2.3.4", "1.2.3.4 port 1234", "1.2.3.4 proto tcp port 1234"
        # Para simplificar, vamos assumir que a regra já está no formato que UFW entende para 'to'
        # Ex: "1.2.3.4 port 8080 proto tcp"
        target_part=$(echo "$rule_out_specific" | awk -F'port|proto' '{print $1}' | xargs) # Extrai o IP
        port_part=$(echo "$rule_out_specific" | grep -oP 'port \K[0-9]+')
        proto_part=$(echo "$rule_out_specific" | grep -oP 'proto \K[a-z]+')

        full_rule_out="to $target_part"
        if [ -n "$port_part" ]; then
            full_rule_out="$full_rule_out port $port_part"
        fi
        if [ -n "$proto_part" ]; then
            full_rule_out="$full_rule_out proto $proto_part"
        fi
        
        echo "Permitindo regra SAINDO: ufw allow out $full_rule_out"
        ufw allow out $full_rule_out
    done
fi

#Mostrar status de configuração de ufw
ufw status verbose

# 4. Configurar Fail2ban
# ... (resto do script permanece o mesmo) ...
echo "Configurando Fail2ban..."
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/^enabled = false$/enabled = true/' /etc/fail2ban/jail.d/sshd.conf
systemctl enable fail2ban
systemctl start fail2ban

# 5. Segurança do SSH
# ... (resto do script permanece o mesmo) ...
echo "Configurando segurança do SSH..."
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
if [ "$SSH_PORT" != "22" ]; then
    echo "Alterando porta SSH para $SSH_PORT..."
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
fi
systemctl restart sshd

# 6. Criar novo usuário e forçar troca de senha no primeiro login
# ... (resto do script permanece o mesmo) ...
echo "Criando usuário '$USERNAME' e forçando troca de senha no primeiro login..."
useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:senha_temp_inicial" | chpasswd
chage -d 0 "$USERNAME"
echo "Adicione o usuário '$USERNAME' ao grupo sudo para privilégios administrativos."
usermod -aG sudo "$USERNAME"

echo "Configurações básicas de segurança finalizadas. Lembre-se de:"
# ... (resto do script permanece o mesmo) ...
echo " - Adicionar suas chaves SSH para '$USERNAME'."
echo " - Testar o login do novo usuário."
echo " - Verificar as regras do firewall do Proxmox host também!"
echo " - Remover ou desabilitar a senha temporária do '$USERNAME' após o primeiro login."
echo " - Trocar a senha do usuário root (se não tiver feito)."
echo " - Validar todas as configurações de acordo com sua política de segurança."
