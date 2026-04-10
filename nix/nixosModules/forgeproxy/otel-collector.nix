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
  cursorStorageDir = "/var/lib/forgeproxy-otelcol/storage";
  localTraceReceiverEndpoint = "127.0.0.1:4317";
  renderConfigScript = pkgs.writeShellApplication {
    name = "forgeproxy-otlp-collector-config";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.gnused
      yq
    ];
    text = ''
      #!/usr/bin/env bash
      set -euo pipefail

      mode=''${1:-}
      forgeproxy_config=${lib.escapeShellArg cfg.forgeproxyConfigFile}
      collector_config=${lib.escapeShellArg cfg.sourceConfigFile}
      runtime_config=${lib.escapeShellArg cfg.generatedConfigFile}
      runtime_resource_file=${lib.escapeShellArg cfg.resourceAttributesFile}

      if [[ ! -f "$forgeproxy_config" ]]; then
        echo "forgeproxy-otlp-collector: missing forgeproxy config $forgeproxy_config" >&2
        exit 1
      fi

      yaml_escape() {
        printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
      }

      yaml_inline_list() {
        local first=true
        printf '['
        for item in "$@"; do
          if [[ "$first" == "true" ]]; then
            first=false
          else
            printf ', '
          fi
          printf '"%s"' "$(yaml_escape "$item")"
        done
        printf ']'
      }

      read_config() {
        local path=$1
        ${yq}/bin/yq -r "$path" "$forgeproxy_config"
      }

      read_signal_field() {
        local signal=$1
        local suffix=$2
        read_collector_config ".exporters.otlp.''${signal}.''${suffix}"
      }

      read_collector_config() {
        local path=$1
        if [[ ! -f "$collector_config" ]]; then
          printf '\n'
          return 0
        fi
        ${yq}/bin/yq -r "$path" "$collector_config"
      }

      read_runtime_attr() {
        local path=$1
        if [[ ! -f "$runtime_resource_file" ]]; then
          printf '\n'
          return 0
        fi
        ${yq}/bin/yq -r "$path" "$runtime_resource_file"
      }

      validate_positive_integer() {
        local path=$1
        local value=$2
        if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value <= 0 )); then
          echo "forgeproxy-otlp-collector: ''${path} must be a positive integer" >&2
          exit 1
        fi
      }

      validate_basic_auth_pair() {
        local path=$1
        local username=$2
        local password=$3

        if [[ -n "$username" && -z "$password" ]] || [[ -z "$username" && -n "$password" ]]; then
          echo "forgeproxy-otlp-collector: ''${path}.username and ''${path}.password must either both be set or both be empty" >&2
          exit 1
        fi
      }

      validate_protocol() {
        local path=$1
        local protocol=$2

        case "$protocol" in
          grpc|http|http/protobuf|http_protobuf)
            ;;
          *)
            echo "forgeproxy-otlp-collector: unsupported ''${path} '$protocol'" >&2
            exit 1
            ;;
        esac
      }

      normalize_grpc_endpoint() {
        local endpoint=$1
        local normalized_endpoint=$endpoint
        local insecure=false

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

        printf '%s\n%s\n' "$normalized_endpoint" "$insecure"
      }

      exporter_name_for() {
        local signal=$1
        local protocol=$2

        case "$protocol" in
          grpc)
            printf 'otlp/%s' "$signal"
            ;;
          http|http/protobuf|http_protobuf)
            printf 'otlphttp/%s' "$signal"
            ;;
        esac
      }

      prometheus_enabled=$(read_config '.observability.metrics.prometheus.enabled // true')
      journald_enabled=$(read_config '.observability.logs.journald.enabled // true')
      traces_enabled=$(read_config '.observability.traces.enabled // false')
      scrape_target=$(read_config '.proxy.http_listen // ""')
      host_metrics_enabled=$(read_collector_config '.metrics.host.enabled // false')

      metrics_enabled=$(read_signal_field metrics 'enabled // false')
      # shellcheck disable=SC2034
      metrics_endpoint=$(read_signal_field metrics 'endpoint // ""')
      metrics_protocol=$(read_signal_field metrics 'protocol // "grpc"')
      metrics_interval=$(read_signal_field metrics 'export_interval_secs // 60')
      metrics_auth_username=$(read_signal_field metrics 'auth.basic.username // ""')
      metrics_auth_password=$(read_signal_field metrics 'auth.basic.password // ""')

      logs_enabled=$(read_signal_field logs 'enabled // false')
      # shellcheck disable=SC2034
      logs_endpoint=$(read_signal_field logs 'endpoint // ""')
      logs_protocol=$(read_signal_field logs 'protocol // "grpc"')
      logs_interval=$(read_signal_field logs 'export_interval_secs // 60')
      logs_auth_username=$(read_signal_field logs 'auth.basic.username // ""')
      logs_auth_password=$(read_signal_field logs 'auth.basic.password // ""')

      traces_export_enabled=$(read_signal_field traces 'enabled // false')
      # shellcheck disable=SC2034
      traces_endpoint=$(read_signal_field traces 'endpoint // ""')
      traces_protocol=$(read_signal_field traces 'protocol // "grpc"')
      traces_interval=$(read_signal_field traces 'export_interval_secs // 60')
      traces_auth_username=$(read_signal_field traces 'auth.basic.username // ""')
      traces_auth_password=$(read_signal_field traces 'auth.basic.password // ""')

      host_metrics_enabled=''${host_metrics_enabled:-false}
      metrics_enabled=''${metrics_enabled:-false}
      metrics_endpoint=''${metrics_endpoint:-}
      metrics_protocol=''${metrics_protocol:-grpc}
      metrics_interval=''${metrics_interval:-60}
      metrics_auth_username=''${metrics_auth_username:-}
      metrics_auth_password=''${metrics_auth_password:-}

      logs_enabled=''${logs_enabled:-false}
      logs_endpoint=''${logs_endpoint:-}
      logs_protocol=''${logs_protocol:-grpc}
      logs_interval=''${logs_interval:-60}
      logs_auth_username=''${logs_auth_username:-}
      logs_auth_password=''${logs_auth_password:-}

      traces_export_enabled=''${traces_export_enabled:-false}
      traces_endpoint=''${traces_endpoint:-}
      traces_protocol=''${traces_protocol:-grpc}
      traces_interval=''${traces_interval:-60}
      traces_auth_username=''${traces_auth_username:-}
      traces_auth_password=''${traces_auth_password:-}

      any_enabled=false
      if [[ "$metrics_enabled" == "true" || "$logs_enabled" == "true" || "$traces_export_enabled" == "true" ]]; then
        any_enabled=true
      fi

      case "$mode" in
        check-enabled)
          [[ "$any_enabled" == "true" ]]
          exit 0
          ;;
        render)
          ;;
        validate)
          ;;
        *)
          echo "usage: forgeproxy-otlp-collector-config {check-enabled|render|validate}" >&2
          exit 64
          ;;
      esac

      if [[ "$metrics_enabled" == "true" ]]; then
        if [[ "$prometheus_enabled" != "true" && "$host_metrics_enabled" != "true" ]]; then
          echo "forgeproxy-otlp-collector: exporters.otlp.metrics.enabled requires observability.metrics.prometheus.enabled and/or metrics.host.enabled" >&2
          exit 1
        fi
        if [[ "$prometheus_enabled" == "true" && ( -z "$scrape_target" || "$scrape_target" == "null" ) ]]; then
          echo "forgeproxy-otlp-collector: proxy.http_listen must be set when Prometheus metrics export is enabled" >&2
          exit 1
        fi
      fi

      if [[ "$host_metrics_enabled" == "true" && "$metrics_enabled" != "true" ]]; then
        echo "forgeproxy-otlp-collector: metrics.host.enabled requires exporters.otlp.metrics.enabled" >&2
        exit 1
      fi

      if [[ "$logs_enabled" == "true" && "$journald_enabled" != "true" ]]; then
        echo "forgeproxy-otlp-collector: exporters.otlp.logs.enabled requires observability.logs.journald.enabled" >&2
        exit 1
      fi

      if [[ "$traces_enabled" == "true" && "$traces_export_enabled" != "true" ]]; then
        echo "forgeproxy-otlp-collector: observability.traces.enabled requires exporters.otlp.traces.enabled" >&2
        exit 1
      fi

      validate_protocol "exporters.otlp.metrics.protocol" "$metrics_protocol"
      validate_protocol "exporters.otlp.logs.protocol" "$logs_protocol"
      validate_protocol "exporters.otlp.traces.protocol" "$traces_protocol"

      validate_positive_integer "exporters.otlp.metrics.export_interval_secs" "$metrics_interval"
      validate_positive_integer "exporters.otlp.logs.export_interval_secs" "$logs_interval"
      validate_positive_integer "exporters.otlp.traces.export_interval_secs" "$traces_interval"

      validate_basic_auth_pair "exporters.otlp.metrics.auth.basic" "$metrics_auth_username" "$metrics_auth_password"
      validate_basic_auth_pair "exporters.otlp.logs.auth.basic" "$logs_auth_username" "$logs_auth_password"
      validate_basic_auth_pair "exporters.otlp.traces.auth.basic" "$traces_auth_username" "$traces_auth_password"

      if [[ "$mode" == "validate" ]]; then
        exit 0
      fi

      mkdir -p "$(dirname "$runtime_config")"
      umask 077

      resource_service_name=$(read_runtime_attr '.service_name // ""')
      resource_service_namespace=$(read_runtime_attr '.service_namespace // ""')
      resource_service_version=$(read_runtime_attr '.service_version // ""')
      resource_service_instance_id=$(read_runtime_attr '.service_instance_id // ""')
      resource_host_id=$(read_runtime_attr '.host_id // ""')
      resource_host_name=$(read_runtime_attr '.host_name // ""')
      resource_service_machine_id=$(read_runtime_attr '.service_machine_id // ""')
      resource_service_ip_address=$(read_runtime_attr '.service_ip_address // ""')
      resource_cloud_provider=$(read_runtime_attr '.cloud_provider // ""')
      resource_cloud_platform=$(read_runtime_attr '.cloud_platform // ""')
      resource_cloud_region=$(read_runtime_attr '.cloud_region // ""')
      resource_deployment_environment=$(read_runtime_attr '.deployment_environment // ""')
      resource_forge_backend=$(read_config '.backend_type // "github-enterprise"')
      resource_upstream_hostname=$(read_config '.upstream.hostname // ""')

      if [[ -z "$resource_service_name" || "$resource_service_name" == "null" ]]; then
        resource_service_name="forgeproxy"
      fi
      if [[ -z "$resource_service_namespace" || "$resource_service_namespace" == "null" ]]; then
        resource_service_namespace="forgeproxy"
      fi

      {
        extensions=()

        if [[ "$logs_enabled" == "true" ]]; then
          extensions+=("file_storage/journald")
        fi

          for signal in metrics logs traces; do
            eval "signal_enabled=\$''${signal}_enabled"
            if [[ "$signal" == "traces" ]]; then
              signal_enabled=$traces_export_enabled
            fi
            eval "auth_username=\$''${signal}_auth_username"
          eval "auth_password=\$''${signal}_auth_password"

          if [[ "$signal_enabled" == "true" && -n "$auth_username" ]]; then
            auth_name="basicauth/client-''${signal}"
            extensions+=("$auth_name")
          fi
        done

        if (( ''${#extensions[@]} == 0 )); then
          printf '%s\n' "extensions: {}"
        else
          printf '%s\n' "extensions:"
          if [[ "$logs_enabled" == "true" ]]; then
            printf '%s\n' \
              "  file_storage/journald:" \
              "    directory: \"${cursorStorageDir}\"" \
              "    create_directory: true"
          fi

          for signal in metrics logs traces; do
            eval "signal_enabled=\$''${signal}_enabled"
            if [[ "$signal" == "traces" ]]; then
              signal_enabled=$traces_export_enabled
            fi
            eval "auth_username=\$''${signal}_auth_username"
            eval "auth_password=\$''${signal}_auth_password"

            if [[ "$signal_enabled" == "true" && -n "$auth_username" ]]; then
              auth_name="basicauth/client-''${signal}"
              # shellcheck disable=SC2154
              printf '%s\n' \
                "  ''${auth_name}:" \
                "    client_auth:" \
                "      username: \"$(yaml_escape "$auth_username")\"" \
                "      password: \"$(yaml_escape "$auth_password")\""
            fi
          done
        fi

        printf '\n%s\n' "receivers:"

        if [[ "$logs_enabled" == "true" ]]; then
          printf '%s\n' \
            "  journald:" \
            "    start_at: end" \
            "    priority: debug" \
            "    units: [\"forgeproxy.service\"]" \
            "    storage: file_storage/journald"
        fi

        if [[ "$metrics_enabled" == "true" ]]; then
          if [[ "$prometheus_enabled" == "true" ]]; then
            printf '%s\n' \
              "  prometheus:" \
              "    config:" \
              "      global:" \
              "        scrape_interval: ''${metrics_interval}s" \
              "        scrape_timeout: 10s" \
              "      scrape_configs:" \
              "        - job_name: forgeproxy" \
              "          metrics_path: /metrics" \
              "          static_configs:" \
              "            - targets: [\"''${scrape_target}\"]"
          fi

          if [[ "$host_metrics_enabled" == "true" ]]; then
            printf '%s\n' \
              "  hostmetrics:" \
              "    collection_interval: ''${metrics_interval}s" \
              "    scrapers:" \
              "      cpu: {}" \
              "      disk: {}" \
              "      filesystem: {}" \
              "      load: {}" \
              "      memory: {}" \
              "      network: {}" \
              "      paging: {}"
          fi
        fi

        if [[ "$traces_export_enabled" == "true" ]]; then
          printf '%s\n' \
            "  otlp/internal:" \
            "    protocols:" \
            "      grpc:" \
            "        endpoint: \"${localTraceReceiverEndpoint}\""
        fi

        printf '\n%s\n' "processors:"

        printf '%s\n' \
          "  resource/common:" \
          "    attributes:" \
          "      - key: service.name" \
          "        value: \"$(yaml_escape "$resource_service_name")\"" \
          "        action: upsert" \
          "      - key: service.namespace" \
          "        value: \"$(yaml_escape "$resource_service_namespace")\"" \
          "        action: upsert"

        if [[ -n "$resource_service_version" && "$resource_service_version" != "null" ]]; then
          printf '%s\n' \
            "      - key: service.version" \
            "        value: \"$(yaml_escape "$resource_service_version")\"" \
            "        action: upsert"
        fi

        for attr in \
          "service.instance.id:$resource_service_instance_id" \
          "host.id:$resource_host_id" \
          "host.name:$resource_host_name" \
          "service.machine_id:$resource_service_machine_id" \
          "service.ip_address:$resource_service_ip_address" \
          "cloud.provider:$resource_cloud_provider" \
          "cloud.platform:$resource_cloud_platform" \
          "cloud.region:$resource_cloud_region" \
          "deployment.environment.name:$resource_deployment_environment" \
          "deployment.environment:$resource_deployment_environment" \
          "forge.backend:$resource_forge_backend" \
          "server.address:$resource_upstream_hostname"
        do
          key=''${attr%%:*}
          value=''${attr#*:}
          if [[ -n "$value" && "$value" != "null" ]]; then
            printf '%s\n' \
              "      - key: ''${key}" \
              "        value: \"$(yaml_escape "$value")\"" \
              "        action: upsert"
          fi
        done

        if [[ "$metrics_enabled" == "true" ]]; then
          printf '%s\n' \
            "  batch/metrics:" \
            "    timeout: ''${metrics_interval}s"
        fi

        if [[ "$logs_enabled" == "true" ]]; then
          printf '%s\n' \
            "  batch/logs:" \
            "    timeout: ''${logs_interval}s"
        fi

        if [[ "$traces_export_enabled" == "true" ]]; then
          printf '%s\n' \
            "  batch/traces:" \
            "    timeout: ''${traces_interval}s"
        fi

        printf '\n%s\n' "exporters:"

        for signal in metrics logs traces; do
          eval "signal_enabled=\$''${signal}_enabled"
          if [[ "$signal" == "traces" ]]; then
            signal_enabled=$traces_export_enabled
          fi
          if [[ "$signal_enabled" != "true" ]]; then
            continue
          fi

          eval "endpoint=\$''${signal}_endpoint"
          eval "protocol=\$''${signal}_protocol"
          eval "auth_username=\$''${signal}_auth_username"

          auth_lines=()
          if [[ -n "$auth_username" ]]; then
            auth_lines+=("    auth:")
            auth_lines+=("      authenticator: basicauth/client-''${signal}")
          fi

          case "$protocol" in
            grpc)
              mapfile -t normalized_grpc < <(normalize_grpc_endpoint "$endpoint")
              normalized_endpoint=''${normalized_grpc[0]}
              insecure=''${normalized_grpc[1]}
              printf '%s\n' \
                "  otlp/''${signal}:" \
                "    endpoint: \"$(yaml_escape "$normalized_endpoint")\""
              if [[ "$insecure" == "true" ]]; then
                printf '%s\n' \
                  "    tls:" \
                  "      insecure: true"
              fi
              ;;
            http|http/protobuf|http_protobuf)
              http_endpoint_key="''${signal}_endpoint"
              printf '%s\n' \
                "  otlphttp/''${signal}:" \
                "    ''${http_endpoint_key}: \"$(yaml_escape "$endpoint")\""
              ;;
          esac

          if (( ''${#auth_lines[@]} > 0 )); then
            printf '%s\n' "''${auth_lines[@]}"
          fi
        done

        printf '\n%s\n' \
          "service:" \
          "  telemetry:" \
          "    metrics:" \
          "      level: none"

        if (( ''${#extensions[@]} > 0 )); then
          printf '  extensions: '
          yaml_inline_list "''${extensions[@]}"
          printf '\n'
        fi

        printf '%s\n' "  pipelines:"

        if [[ "$metrics_enabled" == "true" ]]; then
          metrics_exporter=$(exporter_name_for metrics "$metrics_protocol")
          metrics_receivers=()
          if [[ "$prometheus_enabled" == "true" ]]; then
            metrics_receivers+=("prometheus")
          fi
          if [[ "$host_metrics_enabled" == "true" ]]; then
            metrics_receivers+=("hostmetrics")
          fi
          printf '%s\n' \
            "    metrics:" \
            "      receivers: $(yaml_inline_list "''${metrics_receivers[@]}")" \
            "      processors: [resource/common, batch/metrics]" \
            "      exporters: [\"''${metrics_exporter}\"]"
        fi

        if [[ "$logs_enabled" == "true" ]]; then
          logs_exporter=$(exporter_name_for logs "$logs_protocol")
          printf '%s\n' \
            "    logs:" \
            "      receivers: [journald]" \
            "      processors: [resource/common, batch/logs]" \
            "      exporters: [\"''${logs_exporter}\"]"
        fi

        if [[ "$traces_export_enabled" == "true" ]]; then
          traces_exporter=$(exporter_name_for traces "$traces_protocol")
          printf '%s\n' \
            "    traces:" \
            "      receivers: [otlp/internal]" \
            "      processors: [resource/common, batch/traces]" \
            "      exporters: [\"''${traces_exporter}\"]"
        fi
      } > "$runtime_config"
    '';
  };
in
{
  options.services.forgeproxy-otel-collector = {
    enable =
      lib.mkEnableOption "host-local OTLP collector for forgeproxy metrics, logs, and traces"
      // {
        default = true;
      };

    package = lib.mkOption {
      type = lib.types.package;
      default = otelcol;
      defaultText = lib.literalExpression ''pkgs."otelcol-contrib"'';
      description = "OpenTelemetry Collector package used to export forgeproxy metrics, logs, and traces.";
    };

    forgeproxyConfigFile = lib.mkOption {
      type = lib.types.path;
      default = forgeproxyCfg.configFile;
      defaultText = lib.literalExpression "config.services.forgeproxy.configFile";
      description = ''
        Forgeproxy configuration file. The collector reads only the app-local
        observability toggles from this file.
      '';
    };

    sourceConfigFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/forgeproxy/otel-collector-config.yaml";
      description = ''
        Collector-specific source configuration file containing host metrics
        and OTLP exporter egress settings.
      '';
    };

    resourceAttributesFile = lib.mkOption {
      type = lib.types.path;
      default = forgeproxyCfg.runtimeResourceFile;
      defaultText = lib.literalExpression "config.services.forgeproxy.runtimeResourceFile";
      description = ''
        Runtime-discovered resource attributes produced by forgeproxy at
        service startup. The collector reuses this file so metrics, logs, and
        traces share the same stable instance identity and cloud metadata.
      '';
    };

    generatedConfigFile = lib.mkOption {
      type = lib.types.path;
      default = "/run/forgeproxy-otelcol/config.yaml";
      description = "Runtime-generated collector config derived from sourceConfigFile.";
    };
  };

  config = lib.mkIf (forgeproxyCfg.enable && cfg.enable) {
    systemd.services.forgeproxy.serviceConfig.ExecStartPre = lib.mkAfter [
      "${renderConfigScript}/bin/forgeproxy-otlp-collector-config validate"
    ];

    systemd.services.forgeproxy-otlp-collector = {
      description = "OpenTelemetry Collector for forgeproxy metrics, logs, and traces";
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
        RuntimeDirectoryMode = "0700";
        StateDirectory = "forgeproxy-otelcol";
        StateDirectoryMode = "0700";
        UMask = "0077";
        ExecCondition = "${renderConfigScript}/bin/forgeproxy-otlp-collector-config check-enabled";
        ExecStartPre = "${renderConfigScript}/bin/forgeproxy-otlp-collector-config render";
        ExecStart = "${lib.getExe' cfg.package "otelcol-contrib"} --config=${cfg.generatedConfigFile}";
        Restart = "on-failure";
        RestartSec = 5;
        SupplementaryGroups = [ "systemd-journal" ];
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
