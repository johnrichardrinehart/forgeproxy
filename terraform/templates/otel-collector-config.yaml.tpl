metrics:
  host:
    enabled: ${host_metrics_enabled}
exporters:
  otlp:
    metrics:
      enabled: ${otlp_metrics_enabled}
      endpoint: "${otlp_metrics_endpoint}"
      protocol: "${otlp_metrics_protocol}"
      export_interval_secs: ${otlp_metrics_interval}
      auth:
        basic:
          username: "${otlp_metrics_username}"
          password: "${otlp_metrics_password}"
    logs:
      enabled: ${otlp_logs_enabled}
      endpoint: "${otlp_logs_endpoint}"
      protocol: "${otlp_logs_protocol}"
      export_interval_secs: ${otlp_logs_interval}
      auth:
        basic:
          username: "${otlp_logs_username}"
          password: "${otlp_logs_password}"
    traces:
      enabled: ${otlp_traces_enabled}
      endpoint: "${otlp_traces_endpoint}"
      protocol: "${otlp_traces_protocol}"
      export_interval_secs: ${otlp_traces_interval}
      auth:
        basic:
          username: "${otlp_traces_username}"
          password: "${otlp_traces_password}"
