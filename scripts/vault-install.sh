#!/bin/sh
# Configures the Vault server for a database secrets demo

echo "Preparing to install Vault..."
sudo apt-get -y update > /dev/null 2>&1
sudo apt-get -y upgrade > /dev/null 2>&1
sudo apt-get install -y unzip jq > /dev/null 2>&1
sudo apt-get install -y python3 python3-pip
pip3 install awscli Flask hvac

mkdir /etc/vault.d
mkdir /etc/vault.d/plugins
mkdir -p /opt/vault

echo "Installing Vault..."
export CLIENT_IP=`ifconfig ens4 | grep "inet " | awk -F' ' '{print $2}'`
wget https://releases.hashicorp.com/vault/1.1.2/vault_1.1.2_linux_amd64.zip
sudo unzip vault_1.1.2_linux_amd64.zip -d /usr/local/bin/

wget https://github.com/sethvargo/vault-secrets-gen/releases/download/v0.0.2/vault-secrets-gen_0.0.2_linux_amd64.zip
sudo unzip vault-secrets-gen_0.0.2_linux_amd64.zip -d /etc/vault.d/plugins/

# Server configuration
sudo bash -c "cat >/etc/vault.d/vault.hcl" << 'EOF'
storage "file" {
  path = "/opt/vault"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

plugin_directory = "/etc/vault.d/plugins"
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
ui = true
EOF

# Set Vault up as a systemd service
echo "Installing systemd service for Vault..."
sudo bash -c "cat >/etc/systemd/system/vault.service" << 'EOF'
[Unit]
Description=Hashicorp Vault
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/vault.hcl
Restart=on-failure # or always, on-abort, etc

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl start vault
sudo systemctl enable vault
export VAULT_ADDR=http://localhost:8200
vault operator init -key-shares=1 -key-threshold=1 > /root/init.txt 2>&1
export VAULT_TOKEN=`cat /root/init.txt | sed -n -e '/^Initial Root Token/ s/.*\: *//p'`

# Setup demos
export UNSEAL_KEY_1=`cat /root/init.txt | sed -n -e '/^Unseal Key 1/ s/.*\: *//p'`
mkdir /root/p1_setup
mkdir /root/p2_database
mkdir /root/p3_ftp
mkdir /root/p4_rotation
mkdir /root/p5_pki
mkdir /root/p6_apps

# mkdir /root/eaas
# mkdir /root/unseal
mkdir /root/working

# Enable Audit log
sudo bash -c "cat >/root/p1_setup/s1_audit.sh" <<EOF
vault audit enable file file_path=/var/log/vault_audit.log
EOF
chmod a+x /root/p1_setup/s1_audit.sh

# # Auto unseal
# sudo bash -c "cat >/root/unseal/s1_reconfig.sh" <<EOF
# cat >>/etc/vault.d/vault.hcl <<VAULTCFG

# seal "awskms" {
#     region = "us-west-2"
#     kms_key_id = "$xx{AWS_KMS_KEY_ID}"
# }
# VAULTCFG
# EOF
# chmod a+x /root/unseal/s1_reconfig.sh

# sudo bash -c "cat >/root/unseal/s2_unseal_migrate.sh" <<EOF
# #!/bin/bash

# vault operator unseal -migrate $UNSEAL_KEY_1
# vault operator unseal -migrate $UNSEAL_KEY_2
# vault operator unseal -migrate $UNSEAL_KEY_3
# EOF
# chmod a+x /root/unseal/s2_unseal_migrate.sh

# sudo bash -c "cat >/root/unseal/s3_unseal_migrate.sh" <<EOF
# #!/bin/bash

# vault operator rekey -init -target=recovery -key-shares=1 -key-threshold=1
# EOF
# chmod a+x /root/unseal/s3_unseal_migrate.sh

# sudo bash -c "cat >/root/unseal/s4_unseal_rekey.sh" <<EOF
# #!/bin/bash
# if [ -z "\$1" ]; then
#   exit 1
# fi
# vault operator rekey -target=recovery -key-shares=1 -key-threshold=1 -nonce=\$1 $UNSEAL_KEY_1
# vault operator rekey -target=recovery -key-shares=1 -key-threshold=1 -nonce=\$1 $UNSEAL_KEY_2
# vault operator rekey -target=recovery -key-shares=1 -key-threshold=1 -nonce=\$1 $UNSEAL_KEY_3
# EOF
# chmod a+x /root/unseal/s4_unseal_rekey.sh

# Dynamic creds
sudo bash -c "cat >/root/p2_database/s1_setup_db.sh" << 'EOF'
vault secrets enable database

vault write database/config/sedemovaultdb \
    plugin_name="mssql-database-plugin" \
    connection_url="sqlserver://{{username}}:{{password}}@${MSSQL_HOST}:1433" \
    allowed_roles="app-role" \
    username="${MSSQL_USER}" \
    password="${MSSQL_PASS}"

vault write database/roles/app-role \
    db_name=sedemovaultdb \
    creation_statements="CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';\
        CREATE USER [{{name}}] FOR LOGIN [{{name}}];\
        GRANT SELECT ON SCHEMA::dbo TO [{{name}}];" \
    default_ttl="60s" \
    max_ttl="24h"
EOF
chmod a+x /root/p2_database/s1_setup_db.sh

sudo bash -c "cat >/root/p2_database/operators.hcl" <<EOF
path "database/roles/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "database/creds/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "secret/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}
EOF

sudo bash -c "cat >/root/p2_database/appdevs.hcl" <<EOF
path "secret/*" {
    capabilities = ["read", "list"]
}
EOF

sudo bash -c "cat >/root/p2_database/s2_policies.sh" <<EOF
vault policy write operators /root/p2_database/operators.hcl
vault policy write appdevs /root/p2_database/appdevs.hcl
EOF
chmod a+x /root/p2_database/s2_policies.sh

sudo bash -c "cat >/root/p2_database/s3_users.sh" <<EOF
vault auth enable userpass
vault write auth/userpass/users/james \
    password="superpass" \
    policies="operators"

vault write auth/userpass/users/sally \
    password="superpass" \
    policies="appdevs"
EOF
chmod a+x /root/p2_database/s3_users.sh

# FTP Users and passwords

sudo bash -c "cat >/root/p3_ftp/s1_setup_serets.sh" <<EOF
vault secrets enable -path=ftpsites/group1 -version=2 kv
vault secrets enable -path=ftpsites/group2 -version=2 kv

vault kv put ftpsites/group1/firstsite site="Great Site 1" url="ftp://greatsite.example.com" username="johndoe" password="pass1234"
vault kv put ftpsites/group1/firstsite site="Another Site 1" url="ftp://anothersite.example.com" username="johndoe" password="pass1234"
vault kv put ftpsites/group2/firstsite site="Super FTP 2" url="ftp://suerpftp.example.com" username="johndoe" password="pass1234"
vault kv put ftpsites/group2/firstsite site="File Store 2" url="ftp://filestore.example.com" username="johndoe" password="pass1234"
EOF
chmod a+x /root/p3_ftp/s1_setup_serets.sh

sudo bash -c "cat >/root/p3_ftp/operators.hcl" <<EOF
path "database/roles/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "database/creds/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "secret/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "ftpsites/group1/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}
EOF

sudo bash -c "cat >/root/p3_ftp/appdevs.hcl" <<EOF
path "secret/*" {
    capabilities = ["read", "list"]
}

path "ftpsites/group2/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}
EOF

sudo bash -c "cat >/root/p3_ftp/s2_policies.sh" <<EOF
vault policy write operators /root/p3_ftp/operators.hcl
vault policy write appdevs /root/p3_ftp/appdevs.hcl
EOF
chmod a+x /root/p3_ftp/s2_policies.sh

sudo bash -c "cat >/root/p3_ftp/s3_api_login.sh" <<EOF
TOKEN=\`curl \\
    --request POST \\
    --data '{ "password": "superpass" }' \\
    http://127.0.0.1:8200/v1/auth/userpass/login/james | jq -r .auth.client_token\`

curl \
    --header "X-Vault-Token: \$TOKEN" \
    http://127.0.0.1:8200/v1/ftpsites/group1/data/firstsite
EOF
chmod a+x /root/p3_ftp/s3_api_login.sh



# Windows password rotation

sudo bash -c "cat >/root/p4_rotation/s1_enable_plugin.sh" <<EOF
setcap cap_ipc_lock=+ep /etc/vault.d/plugins/vault-secrets-gen

export SHA256=\`shasum -a 256 "/etc/vault.d/plugins/vault-secrets-gen" | cut -d' ' -f1\`

vault write sys/plugins/catalog/secrets-gen sha_256="\$SHA256" command="vault-secrets-gen"

vault secrets enable -path="gen" -plugin-name="secrets-gen" plugin

vault secrets enable -path=systemcreds -version=2 kv
EOF
chmod a+x /root/p4_rotation/s1_enable_plugin.sh

sudo bash -c "cat >/root/p4_rotation/rotate-windows.hcl" <<EOF
path "systemcreds/data/windows/*" {
  capabilities = ["create", "update"]
}

# Allow hosts to generate new passphrases
path "gen/passphrase" {
  capabilities = ["update"]
}

# Allow hosts to generate new passwords
path "gen/password" {
  capabilities = ["update"]
}
EOF

sudo bash -c "cat >/root/p4_rotation/operators.hcl" <<EOF
path "database/roles/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "database/creds/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "secret/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "ftpsites/group1/*" {
    capabilities = ["read", "list", "create", "delete", "update"]
}

path "systemcreds/*" {
    capabilities = ["list"]
}

path "systemcreds/data/windows/*" {
    capabilities = ["list", "read"]
}
EOF

sudo bash -c "cat >/root/p4_rotation/s2_create_policy.sh" <<EOF
# Create our policies
vault policy write rotate-windows /root/p4_rotation/rotate-windows.hcl
vault policy write operators /root/p4_rotation/operators.hcl
EOF
chmod a+x /root/p4_rotation/s2_create_policy.sh

sudo bash -c "cat >/root/p4_rotation/token_payload.json" <<EOF
{
  "policies": [
    "rotate-windows"
  ],
  "metadata": {
    "user": "root"
  },
  "ttl": "24h",
  "renewable": true
}
EOF

sudo bash -c "cat >/root/p4_rotation/s3_gen_token.sh" <<EOF
# Create a token for use with our Windows machine
# This is normally done programatically on the machine
# vault token create -period 24h -policy rotate-windows

curl -s \\
    --header "X-Vault-Token: \$VAULT_TOKEN" \\
    --request POST \\
    --data @/root/p4_rotation/token_payload.json \\
    http://127.0.0.1:8200/v1/auth/token/create > token.txt

echo ""
echo "\\\$Env:VAULT_TOKEN = \"\`cat token.txt | jq -r .auth.client_token\`\""
echo "\\\$Env:VAULT_ADDR = \"http://$CLIENT_IP:8200\""
echo ""
EOF
chmod a+x /root/p4_rotation/s3_gen_token.sh

# Certificates

sudo bash -c "cat >/root/p5_pki/cert.pem" <<EOF
-----BEGIN CERTIFICATE-----
MIIFsDCCA5igAwIBAgIJAJBPACxRaOM7MA0GCSqGSIb3DQEBCwUAMG0xCzAJBgNV
BAYTAlVTMRAwDgYDVQQIDAdHZW9yZ2lhMRAwDgYDVQQHDAdBdGxhbnRhMRIwEAYD
VQQKDAlIYXNoaUNvcnAxDjAMBgNVBAsMBVNhbGVzMRYwFAYDVQQDDA1oYXNoaWNv
cnAuY29tMB4XDTE5MDUyODEzMTQ1OFoXDTIwMDUyNzEzMTQ1OFowbTELMAkGA1UE
BhMCVVMxEDAOBgNVBAgMB0dlb3JnaWExEDAOBgNVBAcMB0F0bGFudGExEjAQBgNV
BAoMCUhhc2hpQ29ycDEOMAwGA1UECwwFU2FsZXMxFjAUBgNVBAMMDWhhc2hpY29y
cC5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCy8r5TLlxcZ4pW
MYB109mxRT6DLflqH79PUw6xUwNrnAKz2M+HZZ9lw1ol+zvc69B+NoIHDezwOaAA
9BeVD0pV1KGSo87Q5RcUIYftToG2c53rmtIEvx3TW46tEguaB8rdj55FDOIOdGNA
ToQpcl0UU6jqc69YGXbutEv8y1noLu2MJuWKWqudXtUjNfa+1yW93YSGKdqtyUal
ucV/2T0T/yP5g5vP5urGofMwB3xmDggoDtLojTFlXwlDVeiCh5pZRHYmXN6gl9AA
9sScbssecDowDSjETB2rkh5YKTJUFvHFF3pPs6R8KiiG8XS2njyzKvmJ1GKf8oz1
WmlWxI7VW1l9feYZJ82yZp51AFWzPy6n2RWbEIOqC1V3MeElh4EEDWCvt/2fO/Ho
PFOawWZajgLVO5LrRCbnZncET1CoABdRDjFQjIfJpePuWkJh0HG22i8f2gL0YCUk
7CSPbkLKwIz0OkyYKXydW6DZl1yjaMk+CBdeOTvc4/rZTPYKxB/55TMkZKCpaO/u
r/bcQ2qRukogIIbMFGWhQLs3MRa5zEeB+O8IRl0eHfHs4dB2TbejpaEt4puckHIN
5k3w4J7wEQW1wOcqFZwCU8THa7JD8+3SvA0LqHefd5zkPTboTZ6jb8GrFyEXU3IJ
kL3mq2dRziuot3wlxHouQAq8507tlwIDAQABo1MwUTAdBgNVHQ4EFgQUOtm+if8e
b2xvcvTGn8T6psOFOV8wHwYDVR0jBBgwFoAUOtm+if8eb2xvcvTGn8T6psOFOV8w
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAl44PMB5HAyFEATfx
uX1kv+N0xUr2SZa+P1/6b5mOb4e/RrxX69P/g683v1HuuCDa9nSGC2/6R3ERLFGS
xWDWDpHCtFTcZvHDGeyfmSnedQXtqxW5kPc15wvILtB+xoD//Cy8vssD/HwcVH9k
tBucUjC14jr+Ty3aaU/ocs3jfEdma6xc+eRdqa7wiCk8tF1FERA7o+hpGwq7yEzv
aMeALLO2X+6SsKsQqafvU76kF+a7V0HtZ0r6Pgep+O2yqX9f8F3izJqyLpoi/KHU
ovO0fJ0drdrBKW7eHthsV1iDgAOSBxEo9n3xIxSvvuXGJYMtn2f3tclzw6HnuuyK
FSi95Ef6iIkZZM3Skfwf4IY0xFsI7WYwae4/df4xUT1Yi3XRCdRl8gXx0QJp+nwL
CbEexbbk1gUvI0EX+Kg97Mm1zLNI4K18Re2opw+vrB+rR5iRgMYdbQ2cUL1WJ70+
a6769h69TmaIHa9LJeTjKPF0KoMZTlTCPO8o6nm9lPv2PH+63TA2LJfNZEirhFJG
HB7MI6ccrNgEg0TWu+/FfAPREvSSaIDCVD7/N8QvFD3l0nFlVbiXl3DCVIzh1Xrf
Bq9lEysq7+/ciPcr7dhCgiyjW5GGN57WD8EBmaG230J1FavBJXBFtKSFHrWbtj6o
9guLF/448z0ZAEm7wmNyxmerOY0=
-----END CERTIFICATE-----
EOF

sudo bash -c "cat >/root/p5_pki/s1_enable_pki.sh" <<EOF
# Enable PKI
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki

# Store generic certs
vault secrets enable -path=certs -version=2 kv
vault kv put certs/mycert cert-for="My organization" another-key="Just another K/V" cert=@/root/p5_pki/cert.pem

# openssl x509 -in cert.pem -noout -subject
EOF
chmod a+x /root/p5_pki/s1_enable_pki.sh


sudo bash -c "cat >/root/p5_pki/s2_configure_pki.sh" <<EOF
# Generate root certificate
vault write -field=certificate pki/root/generate/internal \\
    common_name="example.com" \\
    ttl=87600h > CA_cert.crt

# Configure CA and CRL urls
vault write pki/config/urls \\
    issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \\
    crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"
EOF
chmod a+x /root/p5_pki/s2_configure_pki.sh

sudo bash -c "cat >/root/p5_pki/s3_gen_intermediate.sh" <<EOF
# Generate the intermediate CA
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int

# Save the CSR
vault write -format=json pki_int/intermediate/generate/internal \\
    common_name="example.com Intermediate Authority" ttl="43800h" \\
    | jq -r '.data.csr' > pki_intermediate.csr

vault write -format=json pki/root/sign-intermediate csr=@pki_intermediate.csr \\
    format=pem_bundle ttl="43800h" \\
    | jq -r '.data.certificate' > intermediate.cert.pem

# Write the intermediate cert back to Vault
vault write pki_int/intermediate/set-signed certificate=@intermediate.cert.pem

# Create a role
vault write pki_int/roles/example-dot-com \\
    allowed_domains="example.com" \\
    allow_subdomains=true \\
    max_ttl="720h"
EOF
chmod a+x /root/p5_pki/s3_gen_intermediate.sh

sudo bash -c "cat >/root/p5_pki/s4_gen_cert.sh" <<EOF
curl --header "X-Vault-Token: \$VAULT_TOKEN" \\
       --request POST \\
       --data '{"common_name": "test.example.com", "ttl": "24h"}' \\
       http://127.0.0.1:8200/v1/pki_int/issue/example-dot-com | jq
EOF
chmod a+x /root/p5_pki/s4_gen_cert.sh

# Application Support

sudo bash -c "cat >/root/p6_apps/tf_policy.hcl" <<EOF
# Login with AppRole
path "auth/approle/login" {
  capabilities = [ "create", "read" ]
}

# Write test data
path "ftpsites/group1/*" {
  capabilities = [ "list", "read" ]
}
EOF

sudo bash -c "cat >/root/p6_apps/s1_create_role.sh" <<EOF
# Enable approle auth method
vault auth enable approle

# Create policy
vault policy write terraform tf_policy.hcl

# Create a new role
vault write auth/approle/role/tf-role policies="terraform"
EOF
chmod a+x /root/p6_apps/s1_create_role.sh

sudo bash -c "cat >/root/p6_apps/s2_login.sh" <<EOF
# Get Role ID
ROLE_ID=\`curl -s --header "X-Vault-Token: \$VAULT_TOKEN" \\
       --request GET \\
       \$VAULT_ADDR/v1/auth/approle/role/tf-role/role-id | jq -r .data.role_id \`

SECRET_ID=\`curl -s --header "X-Vault-Token: \$VAULT_TOKEN" \\
       --request POST \\
       \$VAULT_ADDR/v1/auth/approle/role/tf-role/secret-id | jq -r .data.secret_id \`

sudo bash -c "cat >/root/p6_apps/login.json" <<PAYLOAD
{ "role_id": "\$ROLE_ID", "secret_id": "\$SECRET_ID" }
PAYLOAD

curl -s --request POST --data @/root/p6_apps/login.json \$VAULT_ADDR/v1/auth/approle/login | jq -r .auth.client_token
EOF
chmod a+x /root/p6_apps/s2_login.sh

sudo bash -c "cat >/root/p6_apps/s3_login.sh" <<EOF
# Login
vault write auth/approle/login role_id="675a50e7-cfe0-be76-e35f-49ec009731ea" \\
  secret_id="ed0a642f-2acf-c2da-232f-1b21300d5f29"
EOF
chmod a+x /root/p6_apps/s3_login.sh






# # ec2 auth

# sudo bash -c "cat >/root/ec2auth/s1_setup_auth.sh" << 'EOT'
# vault auth enable aws

# vault write auth/aws/config/client \
#     secret_key=$xx{AWS_SECRET_KEY} \
#     access_key=$xx{AWS_ACCESS_KEY}

# vault policy write "db-policy" -<<EOF
# path "database/creds/app-role" {
#     capabilities = ["list", "read"]
# }
# EOF

# vault write \
#     auth/aws/role/app-db-role \
#     auth_type=ec2 \
#     policies=db-policy \
#     max_ttl=1h \
#     disallow_reauthentication=false \
#     bound_ami_id=$xx{AMI_ID}
# EOT
# chmod a+x /root/ec2auth/s1_setup_auth.sh

# # encryption as a service
# cd /root/eaas
# git clone https://github.com/norhe/transit-app-example.git

# sudo bash -c "cat >/root/eaas/s1_enable_transit.sh" <<EOT
# # Enable Logging
# vault audit enable file file_path=/var/log/vault_audit.log

# # Enable the secret engine
# vault secrets enable -path=lob_a/workshop/transit transit

# # Create our customer key
# vault write -f lob_a/workshop/transit/keys/customer-key

# # Create our archive key to demonstrate multiple keys
# vault write -f lob_a/workshop/transit/keys/archive-key
# EOT
# chmod a+x /root/eaas/s1_enable_transit.sh

# sudo bash -c "cat >/root/eaas/transit-app-example/backend/config.ini" <<EOT
# [DEFAULT]
# LogLevel = WARN

# [DATABASE]
# Address=$DB_HOST
# Port=3306
# User=$xx{MYSQL_USER}
# Password=$xx{MYSQL_PASS}
# Database=my_app

# [VAULT]
# Enabled=False
# DynamicDBCreds=False
# ProtectRecords=False
# Address=http://localhost:8200
# Token=$VAULT_TOKEN
# KeyPath=lob_a/workshop/transit
# KeyName=customer-key
# EOT

# mkdir /root/eaas/app
# mv /root/eaas/transit-app-example/backend/* /root/eaas/app
# rm -r /root/eaas/transit-app-example

# sudo bash -c "cat >/root/eaas/app/run" <<EOT
# #!/bin/bash

# python3 app.py
# EOT
# chmod a+x /root/eaas/app/run

# echo "Setting up environment variables..."
echo "export VAULT_ADDR=http://localhost:8200" >> /home/ubuntu/.profile
echo "export VAULT_TOKEN=$VAULT_TOKEN" >> /home/ubuntu/.profile
echo "export VAULT_ADDR=http://localhost:8200" >> /root/.profile
echo "export VAULT_TOKEN=$VAULT_TOKEN" >> /root/.profile

vault operator unseal $UNSEAL_KEY_1
vault login $VAULT_TOKEN

sudo bash -c "cat >/root/working/gcp-creds.json" <<EOF
${INIT_CREDS}
EOF

sudo bash -c "cat >/root/working/gcp-creds-fmt.json" <<EOF
{
    "type": "gcp",
    "credentials": "${INIT_CREDS_FMT}"
}
EOF

# Enable KV v2 static secrets
curl \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data '{ "type": "kv", "options": { "version": "2" } }' \
    http://127.0.0.1:8200/v1/sys/mounts/secret

curl \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @/root/working/gcp-creds.json \
    http://127.0.0.1:8200/v1/secret/data/creds

# Enable GCP auth
curl \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @/root/working/gcp-creds-fmt.json \
    http://127.0.0.1:8200/v1/sys/auth/gcp

# Create policy
curl \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --request PUT \
    --data '{ "policy": "path \"secret/*\" {\n    capabilities = [\"read\", \"list\", \"create\", \"delete\", \"update\"]\n}" }' \
    http://127.0.0.1:8200/v1/sys/policy/manage-vm

# Create a role eligible to login
sudo bash -c "cat >/root/working/gcp-gce-role.json" <<EOF
{
    "type": "gce",
    "project_id": "kevin-cochran",
    "policies": ["manage-vm"],
    "bound_zones": ["us-central1-a"],
    "ttl": "1h",
    "max_ttl": "2h",
    "bound_labels": [
        "instance_type:my-test-machine"
    ]
}
EOF

curl \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @/root/working/gcp-gce-role.json \
    http://127.0.0.1:8200/v1/auth/gcp/role/gcp-test-role


echo "Vault installation complete."
