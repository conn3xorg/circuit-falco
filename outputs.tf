output "service" {
  description = "The systemd unit Falco runs as on each host. falco.service is an alias of it."
  value       = "falco-modern-bpf.service"
}

output "rules_file" {
  description = "File on each host that holds the rules from the rules input, or null when there are none."
  value       = var.rules == "" ? null : "/etc/falco/rules.d/conn3x.yaml"
}
