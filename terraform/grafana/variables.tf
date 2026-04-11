variable "grafana_url" {
  type        = string
  description = "Grafana instance URL."
}

variable "grafana_auth" {
  type        = string
  sensitive   = true
  description = "Grafana service account token. Set via TF_VAR_grafana_auth or terraform.tfvars."
}

variable "folder_title" {
  type        = string
  default     = "Forgeproxy"
  description = "Grafana folder title for the dashboard."
}

variable "dashboard_overwrite" {
  type        = bool
  default     = true
  description = "Whether Terraform should overwrite an existing dashboard with the same UID."
}

variable "dashboard_uid" {
  type        = string
  default     = "forgeproxy-overview"
  description = "Stable Grafana dashboard UID."
}

variable "dashboard_title" {
  type        = string
  default     = "Forgeproxy"
  description = "Dashboard title shown in Grafana."
}

variable "dashboard_description" {
  type        = string
  default     = "Git caching proxy - clones, bundles, cache, coordination, host metrics, logs, and traces"
  description = "Dashboard description shown in Grafana."
}

variable "dashboard_tags" {
  type        = list(string)
  default     = ["forgeproxy", "git-proxy", "devinfra"]
  description = "Tags attached to the Grafana dashboard."
}

variable "dashboard_refresh" {
  type        = string
  default     = "30s"
  description = "Dashboard auto-refresh interval."
}

variable "dashboard_time_from" {
  type        = string
  default     = "now-6h"
  description = "Default dashboard relative start time."
}

variable "dashboard_time_to" {
  type        = string
  default     = "now"
  description = "Default dashboard relative end time."
}

variable "metrics_datasource_name" {
  type        = string
  description = "Grafana Prometheus datasource name shown as the default dashboard selection."
}

variable "metrics_datasource_uid" {
  type        = string
  description = "Grafana Prometheus datasource UID backing the dashboard queries."
}

variable "logs_datasource_name" {
  type        = string
  description = "Grafana Loki datasource name shown as the default dashboard selection."
}

variable "logs_datasource_uid" {
  type        = string
  description = "Grafana Loki datasource UID backing the dashboard log queries."
}

variable "traces_datasource_name" {
  type        = string
  description = "Grafana Tempo datasource name shown as the default dashboard selection."
}

variable "traces_datasource_uid" {
  type        = string
  description = "Grafana Tempo datasource UID backing the dashboard trace queries."
}
