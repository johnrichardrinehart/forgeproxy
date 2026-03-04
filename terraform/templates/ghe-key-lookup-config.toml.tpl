listen = "${listen}"
identity_file = "${identity_file}"
ssh_user = "${ssh_user}"
ssh_target_endpoint = "${ssh_target_endpoint}"
ssh_port = ${ssh_port}
cache_ttl_pos = ${cache_ttl_pos}
cache_ttl_neg = ${cache_ttl_neg}
%{ if ghe_url != "" ~}
ghe_url = "${ghe_url}"
%{ endif ~}
