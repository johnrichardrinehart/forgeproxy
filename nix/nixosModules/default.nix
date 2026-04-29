{
  forgeproxy = ./forgeproxy/default.nix;
  otel-collector = ./forgeproxy/otel-collector.nix;
  valkey = ./valkey/default.nix;
  valkey-tls = ./valkey/tls.nix;
  nginx = ./nginx/default.nix;
  nginx-runtime = ./nginx/runtime.nix;
  hardening = ./profiles/hardening.nix;
  performance = ./profiles/performance.nix;
  secrets = ./forgeproxy/secrets.nix;
  ami = ./profiles/ami.nix;
  backend = ./forgeproxy/backend.nix;
  security-controls = ./compliance/default.nix;
  proxy-host = ./hosts/proxy-host.nix;
  valkey-host = ./hosts/valkey-host.nix;
  dev = ./profiles/dev.nix;
  dev-tools = ./profiles/dev-tools.nix;
  ghe-key-lookup = ./ghe-key-lookup/default.nix;
  ghe-key-lookup-host = ./hosts/ghe-key-lookup-host.nix;
}
