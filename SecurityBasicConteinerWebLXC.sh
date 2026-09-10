#!/bin/bash
set -euo pipefail # Aborta o script em caso de erro, variável não declarada ou falha em pipes

#AVISO 0: ESTE SCRIPT FOI TESTADO SOMENTE EM DISTRIBUIÇÕES UBUNTU E DEBIAN.
#AVISO 1: O Script anterior foi feito por mim, porém este foi feito com auxilio de IA (Gemini)
#AVISO 2: Antes de executar na máquina limpe espaços em brancos com o comando "dos2unix SecurityBasicConteinerWebLXC.sh"
#AVISO 3: Dê permissão para o arquivo com "chmod +x SecurityBasicConteinerLXCNetworks.sh"
#AVISO 4: Execute o arquivo com "sudo ./SecurityBasicConteinerLXCNetworks.sh"

# --- VARIAVEIS ---
if [[ $EUID -ne 0 ]]; then
   echo "ERRO: Este script precisa ser executado como root (use sudo)."
   exit 1
fi

# --- VARIAVEIS ---
USERNAME="usuario_novo"
SENHA_TEMP_INICIAL="Defina uma senha aqui"
SSH_PORT="22" # Mude se quiser uma porta diferente

# Atribua seu servidor NTP se tiver
#Formato: 185.255.13.2 ou URL"
SERVER_NTP=""
# ajuste seu timezone
#Formato: "America/Sao_Paulo"
TIME_ZONE="America/Sao_Paulo"

# Configurações para tráfego de SAÍDA permitido
ALLOW_OUT_DNS="yes"           # Permitir DNS (porta 53 tcp/udp)
ALLOW_OUT_NTP="yes"           # Permitir NTP (porta 123 udp) - para sincronia de tempo
ALLOW_OUT_HTTP_HTTPS="yes"    # Permitir HTTP/HTTPS (porta 80/443 tcp) - para apt, APIs, etc.


# Defina as regras de porta/protocolo para tráfego ENTRANDO no container.
# Formato: "porta/protocolo". Exemplos: "80/tcp", "443/tcp", "5000/tcp", "53/udp"
# CERTIFIQUE-SE DE QUE A INDENTAÇÃO AQUI E EM TODO O SCRIPT USE ESPAÇOS NORMAIS (ASCII 32)
PORT_RULES_IN=(
    "8330/tcp"
    # Adicione mais regras conforme necessário, por exemplo:
    # "8443/udp"
    # "8443/tcp"
)

# Defina as regras de porta/protocolo para tráfego SAINDO do container.
# Formato: "porta/protocolo". Exemplos: "80/tcp", "443/tcp", "5000/tcp", "53/udp"
# CERTIFIQUE-SE DE QUE A INDENTAÇÃO AQUI E EM TODO O SCRIPT USE ESPAÇOS NORMAIS (ASCII 32)
PORT_RULES_OUT=(
    "8330/tcp"
    #"53/tcp"    # Ex: DNS alternativo
    #"53/udp"
    # "8080/tcp"
)

# Regras de SAÍDA baseadas em IPs, Redes, Portas e Protocolos
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

# Regras de SAÍDA baseadas apenas em IP's
ALLOW_OUT_ADVANCED_RULES=(
)

echo -e "\nIniciando configuração de segurança básica do container LXC...\n"

# 0. Atualizar o sistema
echo "Atualizando pacotes do sistema..."
apt update && apt upgrade -y
apt autoremove -y


# 1. Definindo Servidor NTP e Fuso Horário
echo -e "\nConfigurando Fuso Horário e Servidor NTP..."

# Aplica o Timezone se a variável foi preenchida
if [[ -n "$TIME_ZONE" ]]; then
    echo " -> Definindo Timezone para '$TIME_ZONE'..."
    timedatectl set-timezone "$TIME_ZONE" || echo "AVISO: O container LXC restringiu a mudança de Timezone. Ignorando."
fi

# Aplica o servidor NTP customizado se a variável foi preenchida
if [[ -n "$SERVER_NTP" ]]; then
    if [[ -f /etc/systemd/timesyncd.conf ]]; then
        echo " -> Definindo servidor NTP para '$SERVER_NTP'..."
        
        # A expressão regular (regex) inteligente encontra a linha NTP= (comentada com #, com espaços ou sem) e a substitui
        sed -i "s/^#*[[:space:]]*NTP=.*/NTP=$SERVER_NTP/" /etc/systemd/timesyncd.conf
        
        # Ativa e reinicia o serviço silenciosamente. Se o LXC bloquear o processo de tempo, ele avisa mas não quebra o script
        systemctl enable systemd-timesyncd &>/dev/null || true
        systemctl restart systemd-timesyncd || echo "    AVISO: Falha ao iniciar systemd-timesyncd (Restrição comum em LXC não-privilegiados)."
    else
        echo " -> AVISO: Arquivo /etc/systemd/timesyncd.conf não encontrado. Configuração de NTP pulada."
    fi
else
    echo " -> Nenhum servidor NTP ou Timezone customizado definido. Mantendo padrão."
fi

# 2. Instalar ferramentas de segurança (UFW, Fail2ban)
echo "Instalando UFW e Fail2ban..."
if apt install -y sudo ufw fail2ban; then
    echo "UFW e Fail2ban instalados com sucesso."
else
    echo "ERRO: Falha ao instalar UFW ou Fail2ban."
fi

echo -e "\nConsolidação de instalação UFW e Fail2ban..."
sleep 3 # Aguarda um pouco para consolidar as regras

# 3. Configurar UFW (Firewall no container)
echo -e "\nConfigurando UFW...\n"
ufw --force reset
# Política padrão para tráfego ENTRANDO: bloquear tudo
ufw default deny incoming
# Política padrão para tráfego SAINDO: bloquear tudo
ufw default deny outgoing

# Permitir tráfego na interface de loopback
ufw allow in on lo
ufw allow out on lo

# Permitir SSH ENTRANDO (na porta configurada)
echo "Permitindo tráfego SSH ENTRANDO na porta $SSH_PORT/tcp..."
ufw allow in "$SSH_PORT/tcp"

# Aplicar regras de Portas/Protocolos específicos para tráfego ENTRANDO
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

# Aplicar regras de Portas/Protocolos específicos para tráfego SAINDO
if [ ${#PORT_RULES_OUT[@]} -gt 0 ]; then
    echo "Aplicando regras de SAÍDA para portas específicas..."

    # Itera sobre cada regra definida no array
    for rule_port in "${PORT_RULES_OUT[@]}"; do
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


# Permitir tráfego de SAÍDA em portas essencial
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

# Aplicar regras de SAÍDA personalizadas para IPs/Portas/protocolos específicos
if [ ${#ALLOW_OUT_ADVANCED_RULES[@]} -gt 0 ]; then
    echo "Aplicando regras de SAÍDA personalizadas para IPs/Portas/protocolos específicos..."
    for rule_out_specific in "${ALLOW_OUT_ADVANCED_RULES[@]}"; do
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

# Mostrar status de configuração de ufw
ufw --force enable
ufw status verbose

echo -e "\nConsolidação de configurações de UFW...\n"
sleep 3 # Aguarda um pouco para consolidar as regras



# 4. Configurar Fail2ban
echo "Configurando Fail2ban..."
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local || true
mkdir -p /etc/fail2ban/jail.d # Garante que o diretório exista

# 5. Habilita o jail para SSH e configura a porta correta
echo "Criando/Garantindo configuração do jail SSH em /etc/fail2ban/jail.d/sshd.conf..."
cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled = true
port = $SSH_PORT
# Se precisar especificar backend ou logpath (geralmente os padrões funcionam):
# backend = %(sshd_backend)s
# logpath = %(sshd_log)s
backend = systemd # Padrão em LXC modernos Debian/Ubuntu
EOF

systemctl enable fail2ban
systemctl restart fail2ban


echo -e "\nFail2ban configurado"
echo "Verificando status do Fail2ban..."
if systemctl is-active --quiet fail2ban; then
    echo "Fail2ban está ativo."
else
    echo "AVISO: Fail2ban pode não ter iniciado corretamente."
fi

# 6. Criar novo usuário e forçar troca de senha no primeiro login
echo "Criando usuário '$USERNAME' e forçando troca de senha no primeiro login..."
if id "$USERNAME" &>/dev/null; then
    echo "O usuário '$USERNAME' já existe. Pulando criação."
else
    useradd -m -s /bin/bash "$USERNAME"
    echo "$USERNAME:$SENHA_TEMP_INICIAL" | chpasswd
    chage -d 0 "$USERNAME"
    echo "Adicionando usuário '$USERNAME' ao grupo sudo para privilégios administrativos..."
    usermod -aG sudo "$USERNAME"
fi

# 7. Segurança do SSH
echo "Configurando segurança do SSH..."
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
if [ "$SSH_PORT" != "22" ]; then
    echo "Alterando porta SSH para $SSH_PORT..."
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/^Port 22$/Port $SSH_PORT/" /etc/ssh/sshd_config
fi


systemctl restart sshd

echo -e "\nConfigurações básicas de segurança finalizadas. Lembre-se de:"
echo " - Adicionar suas chaves SSH para '$USERNAME'."
echo " - Remover ou desabilitar a senha temporária do '$USERNAME' após o primeiro login seguro com chave SSH ou nova senha."
echo " - Trocar a senha do usuário root (se não tiver feito e se o login root por senha estiver habilitado)."
echo " - Validar todas as configurações de acordo com sua política de segurança."
