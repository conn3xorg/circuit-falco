# Facts give each host's distribution, which picks Falco's apt or rpm
# repository, and its architecture, since Falco builds for two.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = (self.os_id == "ubuntu" && self.os_version == "24.04") || (self.os_id == "debian" && self.os_version == "13") || (self.os_id == "rocky" && startswith(self.os_version, "10.")) || (self.os_id == "fedora" && self.os_version == "45")
      error_message = "Host ${each.key} runs ${self.os_id} ${self.os_version}. This circuit supports Ubuntu 24.04, Debian 13, Rocky Linux 10 and Fedora 45."
    }
    postcondition {
      condition     = contains(["x86_64", "aarch64"], self.arch)
      error_message = "Host ${each.key} is ${self.arch}. Falco publishes packages for x86_64 and aarch64 only."
    }
  }
}

locals {
  deb      = { for name, f in data.conn3x_host.facts : name => contains(["debian", "ubuntu"], f.os_id) }
  repo_key = file("${path.module}/files/falcosecurity-packages.asc")

  # The unit the package enables for the modern eBPF probe. falco.service is
  # an alias of it.
  unit     = "falco-modern-bpf"
  follower = "falcoctl-artifact-follow.service"
  masked   = "[ \"$(readlink /etc/systemd/system/${local.follower})\" = /dev/null ]"

  # The falco versions dnf's versionlock holds, from dnf 4's
  # "falco-0:0.45.2-1.*" or dnf 5's "Package name: falco" then "evr = 0.45.2-1".
  locked = "dnf -q versionlock list 2>/dev/null | sed -n -e 's/^falco-[0-9]*:\\([^-]*\\)-.*/\\1/p' -e '/^Package name: falco$/{n;s/^evr = \\([^-]*\\)-.*/\\1/p;}'"

  # Rocky's dnf 4 needs the versionlock plugin. Fedora's dnf 5 has it built in.
  lock = join("; ", [
    "set -e",
    "command -v dnf5 >/dev/null || rpm -q python3-dnf-plugin-versionlock >/dev/null || dnf -y -q install python3-dnf-plugin-versionlock",
    "dnf -q versionlock delete falco >/dev/null",
    "dnf -q versionlock add falco-${var.falco_version} >/dev/null",
  ])

  config_file = "/etc/falco/config.d/zz-conn3x.yaml"
  rules_file  = "/etc/falco/rules.d/conn3x.yaml"

  # Falco reads every file in config.d, so the new file is tested beside
  # copies of the others, as it will be read.
  config_test = join("; ", [
    "d=$(mktemp -d)",
    "trap 'rm -rf \"$d\"' EXIT",
    "for f in /etc/falco/config.d/*.yaml; do [ -e \"$f\" ] && [ \"$f\" != ${local.config_file} ] && cp \"$f\" \"$d\"/; done",
    "cp %s \"$d\"/zz-conn3x.yaml",
    "falco -c /etc/falco/falco.yaml -o config_files=\"$d\" --dry-run >/dev/null",
  ])

  # Rules of your own can use the macros and lists in Falco's default rules,
  # so they're tested together.
  rules_test = "falco -c /etc/falco/falco.yaml -V /etc/falco/falco_rules.yaml -V %s >/dev/null"
}

circuit "falco" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # The modern eBPF probe is built into Falco and loads against the types
  # the kernel describes in BTF. Without them it can't load, and Falco would
  # sit failing to start.
  step "kernel" {
    command {
      command = "echo \"The kernel, $(uname -r), doesn't expose BTF at /sys/kernel/btf/vmlinux, which Falco's modern eBPF probe needs.\" >&2; exit 1"
      unless  = "test -r /sys/kernel/btf/vmlinux"
    }
  }

  # Masked before the package goes in, so the first start doesn't fetch
  # rules either. The package's scripts only unmask a mask they made.
  step "rules_updates" {
    command {
      command = var.rules_updates ? "systemctl unmask ${local.follower}" : "systemctl mask --now ${local.follower}"
      unless  = var.rules_updates ? "! ${local.masked}" : local.masked
    }
  }

  # The key Falco has signed its packages with since the January 2026
  # rotation, fingerprint 478B 2FBB C75F 4237 B731 DA43 6510 6822 B35B 1B1F.
  # It expires on 10 December 2028.
  step "repo" {
    repository {
      name       = "falcosecurity"
      url        = local.deb[each.key] ? "https://download.falco.org/packages/deb" : "https://download.falco.org/packages/rpm"
      key        = local.repo_key
      suites     = local.deb[each.key] ? ["stable"] : null
      components = ["main"]
    }
  }

  # Holds falco at falco_version, so apt upgrade or dnf upgrade can't move it.
  # A new falco_version moves the hold before the package step installs it.
  # On Debian and Ubuntu, a pin rather than apt-mark hold: apt-get refuses to
  # change a held package, even to the version asked for.
  step "apt_pin" {
    file {
      path    = "/etc/apt/preferences.d/falco"
      state   = var.hold_package && local.deb[each.key] ? "present" : "absent"
      content = var.hold_package && local.deb[each.key] ? "Package: falco\nPin: version ${var.falco_version}\nPin-Priority: 1001\n" : null
    }
  }

  step "dnf_lock" {
    command {
      command = local.deb[each.key] ? "true" : var.hold_package ? local.lock : "dnf -q versionlock delete falco >/dev/null"
      unless  = local.deb[each.key] ? "true" : var.hold_package ? "[ \"$(${local.locked})\" = ${var.falco_version} ]" : "[ -z \"$(${local.locked})\" ]"
    }
  }

  # The package picks the modern eBPF probe on a kernel that has it, then
  # enables and starts falco-modern-bpf.service.
  step "package" {
    package {
      name    = "falco"
      version = var.falco_version
    }
  }

  step "config" {
    file {
      path     = local.config_file
      validate = local.config_test
      content  = <<-EOT
        # Written by Conn3x. Changes here are overwritten on the next apply.
        # Falco reads the files in config.d in name order, so this one is read
        # last and wins.
        engine:
          kind: modern_ebpf
        priority: ${var.priority}
        json_output: ${var.json_output}
        # Falco's health endpoint, which falcoctl asks for Falco's version.
        # Nothing off the host needs it. A map here replaces Falco's whole
        # webserver map, so it's given in full.
        webserver:
          enabled: true
          threadiness: 0
          listen_port: 8765
          listen_address: 127.0.0.1
          k8s_healthz_endpoint: /healthz
          prometheus_metrics_enabled: false
          ssl_enabled: false
      EOT
    }
    notify = [handler.restart]
  }

  step "rules" {
    file {
      path     = local.rules_file
      state    = var.rules == "" ? "absent" : "present"
      validate = var.rules == "" ? null : local.rules_test
      content  = var.rules == "" ? null : "# Written by Conn3x. Changes here are overwritten on the next apply.\n${var.rules}"
    }
    notify = [handler.reload]
  }

  step "service" {
    service {
      name    = local.unit
      state   = "started"
      enabled = true
    }
  }

  # The health webserver only takes a new address on a full restart.
  handler "restart" {
    service {
      name   = local.unit
      action = "restart"
    }
  }

  # Falco rereads its rules on SIGHUP, so the service keeps running.
  handler "reload" {
    service {
      name   = local.unit
      action = "reload"
    }
  }
}
