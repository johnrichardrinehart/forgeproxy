{
  pkgs,
  lib,
}:

let
  minioRootUser = "minioadmin";
  minioRootPassword = "minioadmin";
  minioRegion = "us-east-1";
  s3Port = 9000;
  valkeyPort = 6379;
in
{
  mkValkeyNode =
    {
      extraSystemPackages ? [ ],
      memorySize ? null,
    }:
    {
      config,
      pkgs,
      lib,
      ...
    }:
    {
      services.redis.servers.default = {
        enable = true;
        port = valkeyPort;
        bind = "0.0.0.0";
        settings = {
          protected-mode = "no";
        };
      };

      environment.systemPackages = [ pkgs.redis ] ++ extraSystemPackages;

      networking.firewall.allowedTCPPorts = [ valkeyPort ];
    }
    // lib.optionalAttrs (memorySize != null) {
      virtualisation.memorySize = memorySize;
    };

  mkS3Node =
    {
      extraSystemPackages ? [ ],
      memorySize ? 512,
    }:
    {
      config,
      pkgs,
      lib,
      ...
    }:
    {
      systemd.services.minio = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        environment = {
          MINIO_ROOT_USER = minioRootUser;
          MINIO_ROOT_PASSWORD = minioRootPassword;
          MINIO_REGION = minioRegion;
        };
        serviceConfig = {
          User = "minio";
          Group = "minio";
          StateDirectory = "minio";
          WorkingDirectory = "/var/lib/minio";
          ExecStart = pkgs.writeShellScript "minio-server" ''
            #!/usr/bin/env bash
            export PATH=${
              lib.makeBinPath [
                pkgs.coreutils
                pkgs.shadow
              ]
            }
            exec ${pkgs.minio}/bin/minio server /var/lib/minio --address 0.0.0.0:${toString s3Port}
          '';
          Restart = "always";
        };
      };

      users.users.minio = {
        isSystemUser = true;
        group = "minio";
        home = "/var/lib/minio";
      };
      users.groups.minio = { };

      environment.systemPackages = [
        pkgs.minio
        pkgs.minio-client
        pkgs.curl
      ]
      ++ extraSystemPackages;

      networking.firewall.allowedTCPPorts = [ s3Port ];
      virtualisation.memorySize = memorySize;
    };

  valkeyStartScript = ''
    with subtest("Valkey starts"):
        valkey.wait_for_unit("redis-default.service")
        valkey.wait_for_open_port(${toString valkeyPort})
  '';

  s3StartScript = ''
    with subtest("S3 starts"):
        s3.wait_for_unit("minio.service")
        s3.wait_for_open_port(${toString s3Port})
        s3.succeed(
            "mc alias set local http://localhost:${toString s3Port} ${minioRootUser} ${minioRootPassword} && "
            "mc mb --ignore-existing local/test-bucket"
        )
  '';
}
