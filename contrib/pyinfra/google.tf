variable "init_script" {
  type = string
  default = <<EOF
apt-get update -qq && apt-get dist-upgrade -y
apt-get install -y fail2ban ssh-import-id unattended-upgrades
sudo su - ubuntu -c 'ssh-import-id cmars'
EOF
}
variable "hkp_count" {
  type = number
  default = 1
}
variable "hkp_machine_type" {
  type = string
  default = "e2-small"
}

provider "google" {
  credentials = file("secrets/serviceaccount.json")
  project = "hockeypuck"
  region = "us-central1"
  zone = "us-central1-a"
}

resource "google_compute_network" "vpc_network" {
  name = "hkp-network"
  auto_create_subnetworks = "true"
}

resource "google_compute_firewall" "hkp" {
  name = "hkp-firewall"
  network = google_compute_network.vpc_network.self_link
  target_tags = ["hkp"]

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports = ["22", "80", "443", "11370", "11371"]
  }
}

resource "google_compute_instance" "hkp" {
  count = var.hkp_count
  name = "hkp${count.index}"
  machine_type = var.hkp_machine_type
  tags = ["hkp"]

  boot_disk {
    initialize_params {
      image = "ubuntu-1804-bionic-v20201116"
      size = 100
    }
  }

  network_interface {
    network = google_compute_network.vpc_network.self_link
    access_config {}
  }

  metadata_startup_script = var.init_script
}

output "hkp_public_ips" { value = google_compute_instance.hkp.*.network_interface.0.access_config.0.nat_ip }
output "hkp_private_ips" { value = google_compute_instance.hkp.*.network_interface.0.network_ip }
