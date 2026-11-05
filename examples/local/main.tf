variable "port" {
  type    = number
  default = 2222
}

module "falco" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  priority = "notice"

  # A rule of your own, built on the open_read macro from Falco's rules.
  rules = <<-EOT
    - rule: Conn3x example canary read
      desc: Something opened the canary file the example plants.
      condition: open_read and fd.name = /etc/conn3x-falco-canary
      output: Canary file read | file=%fd.name process=%proc.name command=%proc.cmdline user=%user.name
      priority: WARNING
      tags: [conn3x]
  EOT
}

output "service" {
  value = module.falco.service
}
