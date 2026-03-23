{
  config,
  lib,
  pkgs,
  ...
}:

let
  forgeproxyCfg = config.services.forgeproxy;
  cfg = config.services.forgeproxy-otel-collector;
  yq = pkgs."yq-go";
  otelcol = pkgs."opentelemetry-collector-contrib";
  renderConfigScript = pkgs.writeShellApplication {
    name = "forgeproxy-otlp-collector-config";
    runtimeInputs = [
      pkgs.coreutils
      yq
    ];
    text = ''
      #!/usr/bin/env bash
      set -euo pipefail

      mode=''${1:-}
      source_config=${lib.escapeShellArg cfg.sourceConfigFile}
      runtime_config=${lib.escapeShellArg cfg.generatedConfigFile}

      if [[ ! -f "$source_config" ]]; then
        echo "forgeproxy-otlp-collector: missing source config $source_config" >&2
        exit 1
      fi

      prometheus_enabled=$(${yq}/bin/yq -r '.observability.metrics.prometheus.enabled // .metrics.prometheus.enabled // true' "$source_config")
      enabled=$(${yq}/bin/yq -r '.observability.exporters.otlp.enabled // .metrics.otlp.enabled // false' "$source_config")
      endpoint=$(${yq}/bin/yq -r '.observability.exporters.otlp.endpoint // .metrics.otlp.endpoint // ""' "$source_config")

      case "$mode" in
        check-enabled)
          [[ "$prometheus_enabled" == "true" && "$enabled" == "true" && -n "$endpoint" && "$endpoint" != "null" ]]
          exit 0
          ;;
        render)
          ;;
        *)
          echo "usage: forgeproxy-otlp-collector-config {check-enabled|render}" >&2
          exit 64
          ;;
      esac

      protocol=$(${yq}/bin/yq -r '.observability.exporters.otlp.protocol // .metrics.otlp.protocol // "grpc"' "$source_config")
      export_interval_secs=$(${yq}/bin/yq -r '.observability.exporters.otlp.export_interval_secs // .metrics.otlp.export_interval_secs // 60' "$source_config")
      scrape_target=$(${yq}/bin/yq -r '.proxy.http_listen // ""' "$source_config")

      if [[ -z "$scrape_target" || "$scrape_target" == "null" ]]; then
        echo "forgeproxy-otlp-collector: proxy.http_listen must be set in $source_config" >&2
        exit 1
      fi

      if ! [[ "$export_interval_secs" =~ ^[0-9]+$ ]] || (( export_interval_secs <= 0 )); then
        echo "forgeproxy-otlp-collector: observability.exporters.otlp.export_interval_secs must be a positive integer" >&2
        exit 1
      fi

      exporter_name=
      normalized_endpoint=$endpoint
      insecure=

      case "$protocol" in
        grpc)
          exporter_name=otlp
          insecure=false
          case "$normalized_endpoint" in
            http://*)
              normalized_endpoint=''${normalized_endpoint#http://}
              insecure=true
              ;;
            https://*)
              normalized_endpoint=''${normalized_endpoint#https://}
              ;;
          esac
          if [[ "$normalized_endpoint" == */* ]]; then
            echo "forgeproxy-otlp-collector: gRPC OTLP endpoints must be host:port or scheme://host:port" >&2
            exit 1
          fi
          ;;
        http|http/protobuf|http_protobuf)
          exporter_name=otlphttp
          ;;
        *)
          echo "forgeproxy-otlp-collector: unsupported observability.exporters.otlp.protocol '$protocol'" >&2
          exit 1
          ;;
      esac

      mkdir -p "$(dirname "$runtime_config")"

      printf '%s\n' \
        "receivers:" \
        "  prometheus:" \
        "    config:" \
        "      global:" \
        "        scrape_interval: ''${export_interval_secs}s" \
        "        scrape_timeout: 10s" \
        "      scrape_configs:" \
        "        - job_name: forgeproxy" \
        "          metrics_path: /metrics" \
        "          static_configs:" \
        "            - targets: [\"''${scrape_target}\"]" \
        "" \
        "processors:" \
        "  batch:" \
        "    timeout: ''${export_interval_secs}s" \
        "" \
        "exporters:" \
        "  ''${exporter_name}:" \
        "    endpoint: \"''${normalized_endpoint}\"" \
        > "$runtime_config"

      if [[ "$exporter_name" == "otlp" && "$insecure" == "true" ]]; then
        printf '%s\n' \
          "    tls:" \
          "      insecure: true" \
          >> "$runtime_config"
      fi

      printf '\n' >> "$runtime_config"
      printf '%s\n' \
        "service:" \
        "  pipelines:" \
        "    metrics:" \
        "      receivers: [prometheus]" \
        "      processors: [batch]" \
        "      exporters: [''${exporter_name}]" \
        >> "$runtime_config"
    '';
  };
in
{
  options.services.forgeproxy-otel-collector = {
    enable = lib.mkEnableOption "host-local OTLP collector for forgeproxy metrics" // {
      default = true;
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = otelcol;
      defaultText = lib.literalExpression ''pkgs."otelcol-contrib"'';
      description = "OpenTelemetry Collector package used to export forgeproxy metrics.";
    };

    sourceConfigFile = lib.mkOption {
      type = lib.types.path;
      default = forgeproxyCfg.configFile;
      defaultText = lib.literalExpression "config.services.forgeproxy.configFile";
      description = ''
        Shared forgeproxy configuration file. The collector derives its runtime
        config from this file so operators only manage one config surface.
      '';
    };

    generatedConfigFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/forgeproxy-otelcol/config.yaml";
      description = "Runtime-generated collector config derived from sourceConfigFile.";
    };
  };

  config = lib.mkIf (forgeproxyCfg.enable && cfg.enable) {
    systemd.services.forgeproxy-otlp-collector = {
      description = "OpenTelemetry Collector for forgeproxy metrics";
      after = [
        "network-online.target"
        "forgeproxy.service"
      ];
      wants = [ "network-online.target" ];
      requires = [ "forgeproxy.service" ];
      partOf = [ "forgeproxy.service" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        RuntimeDirectory = "forgeproxy-otelcol";
        ExecCondition = "${renderConfigScript}/bin/forgeproxy-otlp-collector-config check-enabled";
        ExecStartPre = "${renderConfigScript}/bin/forgeproxy-otlp-collector-config render";
        ExecStart = "${lib.getExe' cfg.package "otelcol-contrib"} --config=${cfg.generatedConfigFile}";
        Restart = "on-failure";
        RestartSec = 5;
        LockPersonality = true;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictNamespaces = true;
        RestrictRealtime = true;
      };
    };
  };
}
