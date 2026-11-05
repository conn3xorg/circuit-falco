variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file or jump_hosts."
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "falco_version" {
  type        = string
  default     = "0.45.2"
  description = "Falco release to install from Falco's package repository."

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.falco_version))
    error_message = "falco_version is a release number such as \"0.45.2\"."
  }
}

variable "priority" {
  type        = string
  default     = "debug"
  description = "Lowest priority of alert Falco logs, from emergency, alert, critical, error, warning, notice, informational and debug. Falco's default, debug, logs every rule that fires."

  validation {
    condition     = contains(["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"], var.priority)
    error_message = "priority is one of emergency, alert, critical, error, warning, notice, informational and debug."
  }
}

variable "json_output" {
  type        = bool
  default     = false
  description = "Log each alert as a JSON object rather than a line of text, for log shippers."
}

variable "rules" {
  type        = string
  default     = ""
  description = "Falco rules of your own, as YAML, written to /etc/falco/rules.d/conn3x.yaml. They can use the macros and lists in Falco's default rules. Empty removes the file."
}

variable "rules_updates" {
  type        = bool
  default     = false
  description = "Let falcoctl fetch new versions of Falco's default rules every week. When false, the rules stay those that came with falco_version."
}
