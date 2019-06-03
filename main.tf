provider "google" {
    credentials = "${var.gcp_creds}"
    project = "${var.gcp_project}"
    region = "${var.gcp_region}"
}

resource "random_pet" "name-id" {
    length = 2
}

resource "google_compute_network" "primary-vpc" {
    name = "kevin-primary-vpc"
    auto_create_subnetworks = false
    routing_mode = "GLOBAL"
}

resource "google_compute_subnetwork" "demo-subnet" {
    name          = "kevin-demo-subnet"
    ip_cidr_range = "10.2.0.0/16"
    region        = "us-central1"
    network       = "${google_compute_network.primary-vpc.self_link}"
}

resource "google_compute_firewall" "allow-internal" {
    name = "fw-allow-internal"
    network = "${google_compute_network.primary-vpc.name}"

    allow {
        protocol = "icmp"
    }

    allow {
        protocol = "tcp"
        ports = ["0-65535"]
    }

    allow {
        protocol = "udp"
        ports = ["0-65535"]
    }

    source_ranges = ["${var.public-subnet}"]
}

resource "google_compute_firewall" "allow-http" {
    name = "fw-allow-http"
    network = "${google_compute_network.primary-vpc.name}"

    allow {
        protocol = "tcp"
        ports = ["80", "22", "8200"]
    }

    source_ranges = ["0.0.0.0/0"]
    target_tags = ["vault"]
}

resource "google_compute_firewall" "allow-rdp" {
    name = "fw-allow-rdp"
    network = "${google_compute_network.primary-vpc.name}"

    allow {
        protocol = "tcp"
        ports = ["3389"]
    }

    allow {
        protocol = "udp"
        ports = ["3389"]
    }

    target_tags = ["sqlserver"]
}

data "template_file" "vault-install-script" {
    template = "${file("${path.module}/scripts/vault-install.sh")}"

    vars = {
        INIT_CREDS = "${var.gcp_init_creds}"
        INIT_CREDS_FMT = "${var.gcp_init_creds_fmt}"
        MSSQL_USER = "${var.mssql-user}"
        MSSQL_PASS = "${var.mssql-pass}"
        MSSQL_HOST = "${google_compute_instance.sql-server.network_interface.0.network_ip}"
    }
}

resource "google_compute_instance" "vault-server" {
    name = "kevin-vault-server"
    machine_type = "n1-standard-1" # same as 'custom-1-3840'
    zone = "${var.gcp_region}-a"

    tags = ["vault"]

    boot_disk {
        auto_delete = true
        initialize_params {
            image = "ubuntu-os-cloud/ubuntu-1804-lts"
        }
    }

    network_interface {
        subnetwork = "${google_compute_subnetwork.demo-subnet.self_link}"
        network = "${google_compute_network.primary-vpc.self_link}"
        access_config = { }
    }

    metadata_startup_script = "${data.template_file.vault-install-script.rendered}"

    labels = {
        instance_type = "my-test-machine"
    }

    service_account {
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    }
}

data "template_file" "sql-install-script" {
    template = "${file("${path.module}/scripts/windows-sql.ps1")}"

    vars = {
        INIT_CREDS = "${var.gcp_init_creds}"
    }
}

resource "google_compute_instance" "sql-server" {
    name = "kevin-sql-server"
    machine_type = "n1-standard-2"
    zone = "${var.gcp_region}-a"

    tags = ["sqlserver"]

    boot_disk {
        auto_delete = true
        initialize_params {
            image = "windows-sql-cloud/sql-web-2016-win-2016"
        }
    }

    metadata {
        gce-initial-windows-user = "Alligator"
        gce-initial-windows-password = "tesT!5844"
    }

    network_interface {
        subnetwork = "${google_compute_subnetwork.demo-subnet.self_link}"
        network = "${google_compute_network.primary-vpc.self_link}"
        access_config = { }
    }

    labels = {
        instance_type = "my-test-machine"
    }

    metadata {
        windows-startup-script-ps1 = "${data.template_file.sql-install-script.rendered}"
    }
    // metadata_startup_script = "${data.template_file.sql-install-script.rendered}"

    service_account {
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    }
}
