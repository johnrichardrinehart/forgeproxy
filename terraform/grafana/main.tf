provider "grafana" {
  url  = var.grafana_url
  auth = var.grafana_auth
}

locals {
  dashboard_tags_json = jsonencode(var.dashboard_tags)
}

resource "grafana_folder" "forgeproxy" {
  title = var.folder_title
}

resource "grafana_dashboard" "forgeproxy" {
  folder    = grafana_folder.forgeproxy.uid
  overwrite = var.dashboard_overwrite

  config_json = templatefile("${path.module}/dashboards/forgeproxy.json.tftpl", {
    dashboard_uid           = var.dashboard_uid
    dashboard_title         = var.dashboard_title
    dashboard_description   = var.dashboard_description
    dashboard_tags_json     = local.dashboard_tags_json
    dashboard_refresh       = var.dashboard_refresh
    dashboard_time_from     = var.dashboard_time_from
    dashboard_time_to       = var.dashboard_time_to
    metrics_datasource_name = var.metrics_datasource_name
    metrics_datasource_uid  = var.metrics_datasource_uid
    logs_datasource_name    = var.logs_datasource_name
    logs_datasource_uid     = var.logs_datasource_uid
    traces_datasource_name  = var.traces_datasource_name
    traces_datasource_uid   = var.traces_datasource_uid
  })
}

output "dashboard_url" {
  description = "URL of the managed Grafana dashboard."
  value       = grafana_dashboard.forgeproxy.url
}

output "folder_uid" {
  description = "UID of the Grafana folder containing the dashboard."
  value       = grafana_folder.forgeproxy.uid
}
