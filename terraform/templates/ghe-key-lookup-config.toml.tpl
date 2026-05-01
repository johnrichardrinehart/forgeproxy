listen = "${listen}"
identity_keyring_key = "${identity_keyring_key}"
%{ if identity_env_var != "" ~}
identity_env_var = "${identity_env_var}"
%{ endif ~}
%{ if identity_file != "" ~}
identity_file = "${identity_file}"
%{ endif ~}
ssh_user = "${ssh_user}"
ssh_target_endpoint = "${ssh_target_endpoint}"
ssh_port = ${ssh_port}
%{ if ghe_url != "" ~}
ghe_url = "${ghe_url}"
%{ endif ~}
