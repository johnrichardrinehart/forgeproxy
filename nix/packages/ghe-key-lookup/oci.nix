{
  dockerTools,
  openssh,
  ghe-key-lookup,
}:
dockerTools.buildLayeredImage {
  name = "ghe-key-lookup";
  tag = "latest";
  contents = [
    ghe-key-lookup
    openssh
  ];
  config = {
    Entrypoint = [ "${ghe-key-lookup}/bin/ghe-key-lookup" ];
    Env = [ "RUST_LOG=info" ];
    ExposedPorts = {
      "3000/tcp" = { };
    };
  };
}
