#!/bin/bash

#AVISO 1: Antes de executar na máquina user limpe espaços com "dos2unix SecurityBasicConteinerWebLXC.sh"
#AVISO 2: Dê permissão para o arquivo com "chmod +x SecurityBasicConteinerLXCNetworks.sh"
#AVISO 3: Execute o arquivo com "sudo ./SecurityBasicConteinerLXCNetworks.sh"

# --- VARIAVEIS ---
USERNAME="usuario_novo"
SENHA_TEMP_INICIAL="Defina uma senha aqui"
SSH_PORT="22" # Mude se quiser uma porta diferente

# Atribua seu servidor NTP se tiver
#Formato: 185.255.13.2 ou URL"
SERVER_NTP="" 
# ajuste seu timezone
#Formato: "America/Sao_Paulo"
TIME_ZONE="" 

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

# Regras de SAÍDA baseadas apenas em PORTAS
    #"53/tcp"    # Ex: DNS alternativo
    #"53/udp"
    # "8080/tcp"

# Adicione aqui outras regras de SAÍDA específicas que o container PRECISA acessar.
# Formatos aceitos (IP_OU_FAIXA_CIDR pode ser um IP como "8.8.8.8" ou uma faixa como "192.168.1.0/24"):
# "IP_OU_FAIXA_CIDR"
# "IP_OU_FAIXA_CIDR/PROTOCOLO"
# "IP_OU_FAIXA_CIDR:PORTA"
# "IP_OU_FAIXA_CIDR:PORTA/PROTOCOLO"
#    "198.51.100.5/tcp"          # Ex: permitir tcp para um IP específico
#    "203.0.113.10:53/udp"       # Ex: permitir udp para um IP e porta específicos
#    "8.8.8.8"                   # Ex: permitir todo tráfego para este IP
#    "172.16.0.0/12"             # Ex: permitir todo tráfego para a faixa 172.16.0.0/12
#    "10.0.0.0/8/tcp"            # Ex: permitir TCP para a faixa 10.0.0.0/8
#    "192.168.0.0/16:8080/tcp"   # Ex: permitir TCP na porta 8080 para a faixa 192.168.0.0/16
#    ""                          # Ex: regra vazia, será ignorada
	
ALLOW_OUT_SPECIFIC_PORTS=(

)

ALLOW_OUT_SPECIFIC_IPS_PORTS=(

)


echo "Iniciando configuração de segurança básica do container..."

# 0. Atualizar o sistema
echo "Atualizando pacotes do sistema..."
apt update && apt upgrade -y
apt autoremove -y


# 1.Definindo servidor NTP
#echo "Definindo servidor NTP..."
#if [ -z "$SERVER_NTP" ]; then
	#sed -i "NTP=" /etc/systemd/timesyncd.conf
#fi
#timedatectl set-timezone "$TIME_ZONE"

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

# Aplicar regras de SAÍDA personalizadas para Portas/Protocolos específicos
if [ ${#ALLOW_OUT_SPECIFIC_PORTS[@]} -gt 0 ]; then
    echo "Aplicando regras de SAÍDA para portas específicas..."

    # Itera sobre cada regra definida no array
    for rule_port in "${ALLOW_OUT_SPECIFIC_PORTS[@]}"; do
        # Pula a iteração se a entrada for uma string vazia
        if [ -z "$rule_port" ]; then
            continue
        fi

        # Valida se a regra está no formato 'porta/protocolo' (ex: 80/tcp ou 53/udp)
        # Usando uma expressão regular para checar o padrão
        if [[ "$rule_port" =~ ^([1-9][0-9]*)/(tcp|udp)$ ]]; then
            # Se a regra for válida, aplica-a
            echo "  -> Permitindo regra válida: $rule_port"
            ufw allow out "$rule_port"
        else
            # Se a regra for inválida, avisa o usuário e não a aplica
            echo "  -> AVISO: A regra '$rule_port' não está no formato 'porta/protocolo' válido. Pulando."
        fi
    done
else
    # Informa ao usuário que nenhuma regra foi definida e, portanto, nenhuma ação foi tomada
    echo "Nenhuma regra de SAÍDA para portas específicas foi definida. Pulando esta etapa."
fi

# Aplicar regras de SAÍDA personalizadas para IPs/Portas específicos
if [ ${#ALLOW_OUT_SPECIFIC_IPS_PORTS[@]} -gt 0 ]; then
    echo "Aplicando regras de SAÍDA personalizadas para IPs/Portas específicos..."
    for rule_out_specific in "${ALLOW_OUT_SPECIFIC_IPS_PORTS[@]}"; do
        if [ -z "$rule_out_specific" ]; then
            echo "Aviso: Regra de SAÍDA específica vazia encontrada, pulando."
            continue
        fi

        echo "Processando regra SAÍDA original: $rule_out_specific"
        
        target_ip_or_cidr=""
        target_port=""
        target_proto=""
        base_part_for_ip_port=""

        # Tenta extrair PROTOCOLO (parte alfabética depois do último /)
        if [[ "$rule_out_specific" =~ /([a-zA-Z]+)$ ]]; then # Termina com /letras
            target_proto="${BASH_REMATCH[1]}"
            # A parte antes deste protocolo encontrado (usando expansão de parâmetro do Bash)
            base_part_for_ip_port="${rule_out_specific%/${target_proto}}"
        else
            # Sem /letras no final, então não há protocolo especificado desta forma.
            # A string inteira é a base para IP/CIDR e Porta.
            target_proto=""
            base_part_for_ip_port="$rule_out_specific"
        fi

        # Da base_part_for_ip_port, tenta extrair IP_OU_FAIXA_CIDR e PORTA (se IP:PORTA)
        if [[ "$base_part_for_ip_port" == *":"* ]]; then
            # Formato IP_OU_FAIXA_CIDR:PORTA
            target_ip_or_cidr=$(echo "$base_part_for_ip_port" | cut -d':' -f1)
            target_port=$(echo "$base_part_for_ip_port" | cut -d':' -f2-)
        else
            # Formato IP_OU_FAIXA_CIDR apenas
            target_ip_or_cidr="$base_part_for_ip_port"
            target_port=""
        fi
        
        if [ -z "$target_ip_or_cidr" ]; then
            echo "Aviso: Não foi possível extrair IP/Faixa da regra '$rule_out_specific', pulando."
            continue
        fi

        full_rule_out_cmd="to $target_ip_or_cidr"

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
echo "Verificando status do Fail2ban..."
if systemctl is-active --quiet fail2ban; then
    echo "Fail2ban está ativo."
else
    echo "AVISO: Fail2ban pode não ter iniciado corretamente."
fi

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
echo "$USERNAME:$SENHA_TEMP_INICIAL" | chpasswd
chage -d 0 "$USERNAME"
echo "Adicionando usuário '$USERNAME' ao grupo sudo para privilégios administrativos..."
usermod -aG sudo "$USERNAME"

echo ""
echo "Configurações básicas de segurança finalizadas. Lembre-se de:"
echo " - Adicionar suas chaves SSH para '$USERNAME'."
echo " - Remover ou desabilitar a senha temporária do '$USERNAME' após o primeiro login seguro com chave SSH ou nova senha."
echo " - Trocar a senha do usuário root (se não tiver feito e se o login root por senha estiver habilitado)."
echo " - Validar todas as configurações de acordo com sua política de segurança."
