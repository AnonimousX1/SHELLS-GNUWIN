#!/bin/bash

# --- VARIAVEIS ---
USERNAME="usuario_novo"
SSH_PORT="22" # Mude se quiser uma porta diferente

# Defina as regras de porta/protocolo para tráfego ENTRANDO no container.
# Formato: "porta/protocolo". Exemplos: "80/tcp", "443/tcp", "5000/tcp", "53/udp"
# CERTIFIQUE-SE DE QUE A INDENTAÇÃO AQUI E EM TODO O SCRIPT USE ESPAÇOS NORMAIS (ASCII 32)
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

# Adicione aqui outras regras de SAÍDA específicas que o container PRECISA acessar.
# Formatos aceitos:
# "IP_DESTINO/PROTOCOLO" (ex: "198.51.100.5/tcp")
# "IP_DESTINO:PORTA/PROTOCOLO" (ex: "203.0.113.10:8080/udp")
# "IP_DESTINO" (ex: "8.8.8.8")
ALLOW_OUT_SPECIFIC_IPS_PORTS=(
    "198.51.100.5/tcp"      # Exemplo: permitir tcp para um IP específico
    "203.0.113.10:53/udp"   # Exemplo: permitir udp para um IP e porta específicos
    "8.8.8.8"               # Exemplo: permitir todo tráfego para este IP
    ""                        # Exemplo de regra vazia, será ignorada
)


echo "Iniciando configuração de segurança básica do container..."

# 1. Atualizar o sistema
echo "Atualizando pacotes do sistema..."
apt update && apt upgrade -y
apt autoremove -y

# 2. Instalar ferramentas de segurança (UFW, Fail2ban)
echo "Instalando UFW e Fail2ban..."
if apt install -y ufw fail2ban; then
    echo "UFW e Fail2ban instalados com sucesso."
else
    echo "ERRO: Falha ao instalar UFW ou Fail2ban. Abortando."
    exit 1
fi

echo ""
echo "Consolidação de instalação UFW e Fail2ban..."
sleep 3 # Aguarda um pouco para consolidar as regras

# 3. Configurar UFW (Firewall no container)
echo "Configurando UFW..."
echo "y" | ufw enable # Responde 'y' automaticamente para a confirmação
# Política padrão para tráfego ENTRANDO: bloquear tudo
ufw default deny incoming
# Política padrão para tráfego SAINDO: bloquear tudo
ufw default deny outgoing
# Permitir tráfego relacionado e estabelecido (importante para conexões de retorno)
ufw allow in on lo # Permitir todo tráfego na interface de loopback
ufw allow out on lo
ufw allow related,established

# Permitir SSH ENTRANDO (na porta configurada)
echo "Permitindo tráfego SSH ENTRANDO na porta $SSH_PORT/tcp..."
ufw allow in "$SSH_PORT/tcp"

# Aplicar regras de portas personalizadas para tráfego ENTRANDO
if [ ${#PORT_RULES_IN[@]} -gt 0 ]; then
    echo "Aplicando regras de portas personalizadas para tráfego ENTRANDO..."
    for rule_in in "${PORT_RULES_IN[@]}"; do
        if [ -n "$rule_in" ]; then # Ignora regras vazias
            echo "Permitindo regra ENTRANDO: $rule_in"
            ufw allow in "$rule_in" # Especificar 'in' para clareza
        fi
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
        if [ -z "$rule_out_specific" ]; then # Pula regras vazias
            echo "Aviso: Regra de SAÍDA específica vazia encontrada, pulando."
            continue
        fi

        echo "Processando regra SAÍDA original: $rule_out_specific"
        
        target_ip=""
        target_port=""
        target_proto=""

        # Tenta extrair PROTOCOLO (parte depois do último /)
        if [[ "$rule_out_specific" == *"/"* ]]; then
            target_proto=$(echo "$rule_out_specific" | sed 's#.*/##')
            base_part=$(echo "$rule_out_specific" | sed 's#/[^/]*$##') # Parte antes do último /
        else
            base_part="$rule_out_specific" # Sem / , então tudo é base_part
        fi

        # Da base_part, tenta extrair IP e PORTA (se IP:PORTA)
        if [[ "$base_part" == *":"* ]]; then
            target_ip=$(echo "$base_part" | cut -d':' -f1)
            target_port=$(echo "$base_part" | cut -d':' -f2-) # -f2- para pegar o resto se houver mais ':' na porta (ipv6)
        else
            target_ip="$base_part" # Sem : na base_part, então é só IP
        fi
        
        # Validações básicas (opcional, mas bom ter)
        if [ -z "$target_ip" ]; then
            echo "Aviso: Não foi possível extrair IP da regra '$rule_out_specific', pulando."
            continue
        fi

        full_rule_out_cmd="to $target_ip"

        if [ -n "$target_port" ]; then
            full_rule_out_cmd="$full_rule_out_cmd port $target_port"
        fi

        if [ -n "$target_proto" ]; then
            full_rule_out_cmd="$full_rule_out_cmd proto $target_proto"
        fi
        
        echo "Permitindo regra SAINDO: ufw allow out $full_rule_out_cmd"
        ufw allow out $full_rule_out_cmd
    done
fi

#Mostrar status de configuração de ufw
ufw status verbose

echo ""
echo "Consolidação de configurações de UFW..."
sleep 3 # Aguarda um pouco para consolidar as regras

# 4. Configurar Fail2ban
echo "Configurando Fail2ban..."
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Habilita o jail para SSH e configura a porta correta
echo "Criando/Garantindo configuração do jail SSH em /etc/fail2ban/jail.d/sshd.conf..."
mkdir -p /etc/fail2ban/jail.d # Garante que o diretório exista
cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled = true
port = $SSH_PORT
# Se precisar especificar backend ou logpath (geralmente os padrões funcionam):
# backend = %(sshd_backend)s
# logpath = %(sshd_log)s
EOF

systemctl enable fail2ban
systemctl start fail2ban

echo ""
echo "Fail2ban configurado e iniciado."
sleep 1

# 5. Segurança do SSH
echo "Configurando segurança do SSH..."
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
if [ "$SSH_PORT" != "22" ]; then
    echo "Alterando porta SSH para $SSH_PORT..."
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/^Port 22$/Port $SSH_PORT/" /etc/ssh/sshd_config
fi
systemctl restart sshd

# 6. Criar novo usuário e forçar troca de senha no primeiro login
echo "Criando usuário '$USERNAME' e forçando troca de senha no primeiro login..."
useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:senha_temp_inicial" | chpasswd
chage -d 0 "$USERNAME"
echo "Adicionando usuário '$USERNAME' ao grupo sudo para privilégios administrativos..."
usermod -aG sudo "$USERNAME"

echo ""
echo "Configurações básicas de segurança finalizadas. Lembre-se de:"
echo " - Adicionar suas chaves SSH para '$USERNAME'."
echo " - Remover ou desabilitar a senha temporária do '$USERNAME' após o primeiro login seguro com chave SSH ou nova senha."
echo " - Trocar a senha do usuário root (se não tiver feito e se o login root por senha estiver habilitado)."
echo " - Validar todas as configurações de acordo com sua política de segurança."
