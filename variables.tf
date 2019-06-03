variable "gcp_creds" { }
variable "gcp_init_creds" { }
variable "gcp_init_creds_fmt" { }
variable "gcp_region" { }
variable "gcp_project" { }
variable "mssql-user" { }
variable "mssql-pass" { }

variable "private-subnet" {
    default = "10.2.0.0/16"
}

variable "public-subnet" {
    default = "10.2.0.0/16"
}

