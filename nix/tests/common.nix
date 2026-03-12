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
  giteaAdminUser = "octocat";
  giteaAdminPassword = "secret123";
  giteaAdminToken = "0123456789abcdef0123456789abcdef01234567";
  giteaAdminTokenSalt = "forgeproxy";
  giteaAdminTokenLastEight = "01234567";
  giteaAdminTokenHash = "6aba73fa830d0e6a8b1706262d2eb52f9690616dc9f83390ca8d39353b2371fc1a30136add3bc07404ca1b8a299fc281e777";
  giteaDbPath = "/var/lib/gitea/data/gitea.db";
in
{
  inherit
    giteaAdminPassword
    giteaAdminToken
    giteaAdminUser
    ;

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

  giteaSeedAdminTokenScript = ''
    ghe.succeed(
        "${pkgs.sqlite}/bin/sqlite3 ${giteaDbPath} "
        "\"DELETE FROM access_token WHERE name = 'forgeproxy-test-admin';"
        "INSERT INTO access_token (uid, name, token_hash, token_salt, token_last_eight, scope, created_unix, updated_unix) "
        "VALUES ("
        "(SELECT id FROM \"user\" WHERE name = '${giteaAdminUser}'), "
        "'forgeproxy-test-admin', "
        "'${giteaAdminTokenHash}', "
        "'${giteaAdminTokenSalt}', "
        "'${giteaAdminTokenLastEight}', "
        "'all', "
        "CAST(strftime('%s','now') AS INTEGER), "
        "CAST(strftime('%s','now') AS INTEGER)"
        ");\""
    )
  '';
}
