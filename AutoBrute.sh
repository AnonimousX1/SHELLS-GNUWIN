#!/bin/bash


wordlist_dir="/caminho/para/seu/diretorio/de/wordlists"  # Substitua pelo caminho correto


hash_file="hash.txt" # Substitua pelo nome do arquivo com a hash


hash_format="crypt"  # Ou outro formato como raw-md5, bcrypt, etc.

# Verifica se o diretório de wordlists existe
if [ ! -d "$wordlist_dir" ]; then
  echo "Erro: Diretório de wordlists não encontrado: $wordlist_dir"
  exit 1
fi

# Loop através de cada arquivo no diretório de wordlists
for wordlist_file in "$wordlist_dir"/*; do
  # Verifica se é um arquivo regular (não um diretório)
  if [ -f "$wordlist_file" ]; then
    echo "Testando com wordlist: $wordlist_file"
    john --format="$hash_format" --wordlist="$wordlist_file" "$hash_file"

     if john --show "$hash_file" | grep -q ":"; then
       echo "Senha encontrada!"
       exit 0
     fi
  fi
done

echo "Todos os dicionários foram testados."

exit 0
