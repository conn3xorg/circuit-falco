# Local example

Applies circuit-falco to a throwaway Rocky Linux 10 container with systemd, logging alerts of `notice` and above, with one rule of its own that fires when something reads `/etc/conn3x-falco-canary`. You need Conn3x and rootful Podman.

```sh
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` To see an alert, read a file Falco's default rules watch:

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 'cat /etc/shadow >/dev/null; sleep 2; journalctl -u falco-modern-bpf --since "-1min" | grep Sensitive'
```

`check.sh` does that and reads the canary too, then checks Falco logged an alert for each, and that its health webserver listens on loopback only:

```sh
podman exec -i circuit-falco sh < check.sh
```

The container is privileged, because Falco loads its eBPF probe into the kernel, and a container has no kernel of its own. That has two consequences worth knowing before you run it:

- It needs a kernel with BTF under the container. Podman's machine on a Mac has one. On Linux, `ls /sys/kernel/btf/vmlinux` on the host tells you.
- Falco sees every process on the machine the container runs on, not just the container's, so expect alerts about things you did outside it.

`up.sh` listens on `127.0.0.1:2222`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINER_NAME` to name the container something else. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses. On a Mac: `export CONTAINER_CONNECTION=podman-machine-default-root`. On Linux: `export PODMAN="sudo podman"`.

`./down.sh` removes the container, its volumes, the key and the state.
