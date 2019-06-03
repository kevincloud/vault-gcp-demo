output "vault_ip" {
  value = "${google_compute_instance.vault-server.network_interface.0.access_config.0.nat_ip}"
}

output "vault_ssh" {
    value = "ssh -i ~/keys/kevin-gcp kcochran@${google_compute_instance.vault-server.network_interface.0.access_config.0.nat_ip}"
}

output "sql_ip" {
  value = "${google_compute_instance.sql-server.network_interface.0.access_config.0.nat_ip}"
}

