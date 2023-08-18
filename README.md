# ansible-role-gophish

[![Ansible Role Name](https://img.shields.io/ansible/role/51375?label=Role%20Name&logo=ansible&style=flat-square)](https://galaxy.ansible.com/justin_p/gophish)
[![Ansible Quality Score](https://img.shields.io/ansible/quality/51375?label=Ansible%20Quality%20Score&logo=ansible&style=flat-square)](https://galaxy.ansible.com/justin_p/gophish)
[![Ansible Role Downloads](https://img.shields.io/ansible/role/d/51375?label=Ansible%20Role%20Downloads&logo=ansible&style=flat-square)](https://galaxy.ansible.com/justin_p/gophish)
[![Github Actions](https://img.shields.io/github/workflow/status/justin-p/ansible-role-gophish/CI?label=Github%20Actions&logo=github&style=flat-square)](https://github.com/justin-p/ansible-role-gophish/actions)

A Ansible role that deploys the [gophish](https://github.com/gophish/gophish) application as a systemd service. This role does not install any mail services for relaying or web services for proxing gophish. You are expected to handle this in your own playbooks, see [Deployment playbook](#Deployment-playbook) for an example.

## Requirements

None.

## Variables

`defaults/main.yml`

| Variable                             | Description                                                                                    | Default value                                                                     |
| ------------------------------------ | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| gophish_version                      | The version of gophish that should be installed.                                               | 0.12.1                                                                            |
| gophish_platform                     | The platform type.                                                                             | linux                                                                             |
| gophish_arch                         | The architecture.                                                                              | 64bit                                                                             |
| gophish_sha256                       | The sha256 sum of the downloaded file that matches the version, platform and arch combination. | sha256:44f598c1eeb72c3b08fa73d57049022d96cea2872283b87a73d21af78a2c6d47           |
| gophish_user                         | The user that gophish will run as.                                                             | {{ ansible_user }}                                                                |
| gophish_download_destination         | The download destination of the gophish release zip file.                                      | /tmp/gophish-v{{ gophish_version }}-{{ gophish_platform }}-{{ gophish_arch }}.zip |
| gophish_install_destination          | The install destination of gophish.                                                            | /home/{{ gophish_user }}/gophish                                                  |
| gophish_config_template_source       | The gophish config jinja template to deploy. Will default to included template.                | config.json.j2                                                                    |
| gophish_config_template_destination  | The destination of the gophish config file.                                                    | {{ gophish_install_destination }}/config.json                                     |
| gophish_service                      | The name of the gophish service.                                                               | gophish.service                                                                   |
| gophish_service_template_source      | The gophish service template to deploy. Will default to included template.                     | gophish.service.j2                                                                |
| gophish_service_template_destination | The destination where the service should be placed.                                            | /etc/systemd/system/{{ gophish_service }}                                         |
| gophish_service_log_directory        | The location of the gophish log directory. Used by the service.                                | /var/log/gophish                                                                  |
| gophish_tls_private_key_path         | The location of the gophish private key file.                                                  | gophish.key                                                                       |
| gophish_tls_public_key_path          | The location of the gophish public key.                                                        | gophish.crt                                                                       |

`vars/main.yml`

| Variable                    | Value                                                                                                                                                    |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| gophish_url                 | `https://github.com/gophish/gophish/releases/download/v{{ gophish_version }}/gophish-v{{ gophish_version }}-{{ gophish_platform }}-{{ gophish_arch }}.zip` |
| gophish_binary              | {{ gophish_install_destination }}/gophish                                                                                                                |
| gophish_binary_capability   | cap_net_bind_service+eip                                                                                                                                 |
| gophish_dependency_packages | ['libcap2-bin', 'coreutils', 'grep']                                                                                                                                 |

## Dependencies

[geerlingguy.pip](https://github.com/geerlingguy/ansible-role-pip)
[robertdebock.update_package_cache](https://github.com/robertdebock/ansible-role-update_package_cache)
[robertdebock.core_dependencies](https://github.com/robertdebock/ansible-role-core_dependencies)

## Example Playbooks

### Default role installation

```yaml
---
- hosts: gophish_hosts
  become: yes
  roles:
    - role: justin_p.gophish
```

### Deployment playbook

This playbook is tested as part of the role CI.

```yaml
---
- hosts: gophish_hosts
  become: yes
  tasks:
    - include_role:
        name: robertdebock.update_package_cache
      tags: molecule-idempotence-notest
    - include_role:
        name: robertdebock.bootstrap
    - include_role:
        name: robertdebock.epel
    - include_role:
        name: robertdebock.update
      vars:
        update_reboot: no
    - include_role:
        name: robertdebock.firewall
      vars:
        firewall_services:
          - name: ssh
          - name: http
          - name: https
    - include_role:
        name: robertdebock.users
      vars:
        users_group_list:
          - name: gophish
        users_user_list:
          - name: gophish
            group: gophish
            cron_allow: no
    - include_role:
        name: robertdebock.hostname
      vars:
        hostname: gophish.local
        hostname_reboot: yes
    - meta: flush_handlers
    - name: Set Python interpreter to python3 for use by subsequent tasks.
      set_fact:
        ansible_python_interpreter: /usr/bin/python3
    - include_role:
        name: geerlingguy.postfix
    - include_role:
        name: geerlingguy.pip
      vars:
        pip_package: python3-pip
    - include_role:
        name: robertdebock.openssl
      vars:
        openssl_items:
          - name: phishlet.gophish.local
            common_name: phishlet.gophish.local
    - include_role:
        name: nginxinc.nginx
      vars:
        nginx_selinux: true
        nginx_selinux_tcp_ports:
          - 80
          - 443
        nginx_logrotate_conf_enable: true
    - include_role:
        name: nginxinc.nginx_config
      vars:
        nginx_config_http_template_enable: true
        nginx_config_http_template:
          default:
            servers:
              gophish_http_server:
                listen:
                  listen_80:
                    port: 80
                server_name: phishlet.gophish.local
                https_redirect: phishlet.gophish.local
              gophish_https_server:
                listen:
                  listen_443:
                    port: 443
                    ssl: true
                server_name: phishlet.gophish.local
                ssl:
                  cert: /etc/ssl/certs/phishlet.gophish.local.crt
                  key: /etc/ssl/private/phishlet.gophish.local.key
                reverse_proxy:
                  locations:
                    backend:
                      location: /
                      proxy_connect_timeout: null
                      proxy_pass: http://gophish
                      proxy_set_header:
                        header_host:
                          name: Host
                          value: $host
                        header_x_real_ip:
                          name: X-Real-IP
                          value: $remote_addr
                        header_x_forwarded_for:
                          name: X-Forwarded-For
                          value: $proxy_add_x_forwarded_for
                        header_x_forwarded_host:
                          name: X-Forwarded-Host
                          value: $server_name
                      proxy_ignore_headers:
                        - Vary
                        - Cache-Control
            upstreams:
              upstream1:
                name: gophish
                servers:
                  server1:
                    address: localhost
                    port: 8080
                    weight: 1
    - include_role:
        name: robertdebock.cron
    - include_role:
        name: robertdebock.logrotate
      vars:
        - name: gophish
          path: "/var/log/gophish/*.log"
    - include_role:
        name: justin_p.gophish
      vars:
        gophish_user: gophish
        gophish_config_template_source: "{{ playbook_dir }}/templates/config.json.j2"
```

#### Contents of `{{ playbook_dir }}/templates/config.json.j2`

```json
{
	"admin_server": {
		"listen_url": "127.0.0.1:3333",
		"use_tls": true,
		"cert_path": "gophish_admin.crt",
		"key_path": "gophish_admin.key"
	},
	"phish_server": {
		"listen_url": "127.0.0.1:8080",
		"use_tls": false,
		"cert_path": "example.crt",
		"key_path": "example.key"
	},
	"db_name": "sqlite3",
	"db_path": "gophish.db",
	"migrations_prefix": "db/db_",
	"contact_address": "",
	"logging": {
		"filename": "",
		"level": ""
	}
}
```

## Local Development

This role includes molecule that will spin up a local docker environment to deploy, configure and test this role.

Development requirements:

- Docker
- Molecule
- Molecule-docker
- yamllint
- ansible-lint

or simply use a VM with [this](https://github.com/justin-p/ansible-terraform-workstation) configuration.

## License

MIT

## Authors

Justin Perdok ([@justin-p](https://github.com/justin-p/)), Orange Cyberdefense

## Contributing

Feel free to open issues, contribute and submit your Pull Requests. You can also ping me on Twitter ([@JustinPerdok](https://twitter.com/JustinPerdok))
