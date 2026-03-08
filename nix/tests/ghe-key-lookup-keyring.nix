{
  self,
  pkgs,
  lib,
}:

let
  testIdentityKey =
    pkgs.runCommand "ghe-key-lookup-test-identity" { nativeBuildInputs = [ pkgs.openssh ]; }
      ''
        mkdir -p "$out"
        ssh-keygen -t ed25519 -N "" -C "ghe-key-lookup-test" -f "$out/id_ed25519" >/dev/null
      '';

  fakeSsh = pkgs.writeShellScriptBin "ssh" ''
    has_identity_file_flag=0
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "-i" ]; then
        has_identity_file_flag=1
      fi
      shift
    done

    if [ "$has_identity_file_flag" -ne 0 ]; then
      echo "unexpected -i identity file flag" >&2
      exit 64
    fi

    if [ -z "''${SSH_AUTH_SOCK-}" ]; then
      echo "missing SSH_AUTH_SOCK" >&2
      exit 65
    fi

    if [ ! -S "$SSH_AUTH_SOCK" ]; then
      echo "SSH_AUTH_SOCK is not a socket: $SSH_AUTH_SOCK" >&2
      exit 66
    fi

    printf '%s\n' $'id\tkey\ttitle\tcreated_at\tverified\tread_only\taccessed_at\tuser_id\trepository_id\tlogin'
    printf '%s\n' $'1\tssh-ed25519 AAAATEST\ttest-key\t2026-03-06 00:00:00\t1\t0\t\t1\t\toctocat'
  '';
in
pkgs.testers.runNixOSTest {
  name = "ghe-key-lookup-keyring";
  globalTimeout = 180;

  nodes.vm =
    {
      config,
      pkgs,
      lib,
      ...
    }:
    {
      imports = [
        self.nixosModules.ghe-key-lookup
      ];

      services.ghe-key-lookup = {
        enable = true;
        package = pkgs.ghe-key-lookup;
        listen = "0.0.0.0:3000";
        sshTargetEndpoint = "ghe.example.com";
        sshControlPath = "";
        identityKeyringKey = "GHE_KEY_LOOKUP_IDENTITY";
        identityEnvVar = null;
        identityFile = null;
        openFirewall = false;
        logLevel = "debug";
      };

      # Start manually after injecting the key into the service keyring via
      # ExecStartPre in the service's own keyring/session context.
      systemd.services.ghe-key-lookup.wantedBy = lib.mkForce [ ];

      # Ensure our fake ssh is found before OpenSSH in PATH.
      systemd.services.ghe-key-lookup.path = lib.mkBefore [
        fakeSsh
        pkgs.keyutils
      ];

      environment.systemPackages = with pkgs; [
        curl
        jq
        keyutils
      ];
    };

  testScript = ''
    import json

    start_all()

    with subtest("Inject keyring identity and start service"):
        vm.succeed(
            "mkdir -p /run/systemd/system/ghe-key-lookup.service.d && "
            "cat > /run/systemd/system/ghe-key-lookup.service.d/keyring.conf <<'UNIT'\n"
            "[Service]\n"
            "ExecStartPre=/bin/sh -c 'keyctl search @u user GHE_KEY_LOOKUP_IDENTITY >/dev/null 2>&1 && keyctl unlink $(keyctl search @u user GHE_KEY_LOOKUP_IDENTITY) @u || true'\n"
            "ExecStartPre=/bin/sh -c 'cat ${testIdentityKey}/id_ed25519 | keyctl padd user GHE_KEY_LOOKUP_IDENTITY @u >/dev/null'\n"
            "UNIT"
        )
        vm.succeed("systemctl daemon-reload")
        vm.succeed("systemctl start ghe-key-lookup.service")

    with subtest("Service starts and listens"):
        vm.wait_for_unit("ghe-key-lookup.service")
        vm.wait_for_open_port(3000)

    with subtest("Lookup succeeds using in-memory identity flow"):
        out = vm.succeed(
            "curl -sf 'http://localhost:3000/api/v3/users/keys/lookup?fingerprint=SHA256:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE='"
        )
        rows = json.loads(out)
        assert len(rows) == 1, f"expected one row, got: {rows}"
        assert rows[0]["login"] == "octocat", f"unexpected lookup result: {rows[0]}"

    with subtest("No on-disk identity fallback file is required"):
        vm.succeed("test ! -e /run/ghe-key-lookup/admin-key")

    with subtest("Journal shows no identity file/stdin key errors"):
        vm.succeed(
            "journalctl -u ghe-key-lookup.service --no-pager | "
            "grep -q 'unexpected -i identity file flag' && exit 1 || true"
        )
        vm.succeed(
            "journalctl -u ghe-key-lookup.service --no-pager | "
            "grep -q 'missing SSH_AUTH_SOCK' && exit 1 || true"
        )
        vm.succeed(
            "journalctl -u ghe-key-lookup.service --no-pager | "
            "grep -q 'SSH_AUTH_SOCK is not a socket' && exit 1 || true"
        )
        vm.succeed(
            "journalctl -u ghe-key-lookup.service --no-pager | "
            "grep -q 'Identity file /proc/self/fd' && exit 1 || true"
        )
        vm.succeed(
            "journalctl -u ghe-key-lookup.service --no-pager | "
            "grep -q 'Load key \"/dev/stdin\"' && exit 1 || true"
        )
  '';
}
