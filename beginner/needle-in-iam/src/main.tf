# ~~=== Variables ===~~~
variable "project" {}
variable "region" {}
variable "zone" {}
variable "flag" {}


# ~~~=== Setup Terraform ===~~~
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.76.0"
    }
  }
}

provider "google" {

  project = var.project
  region  = var.region
  zone    = var.zone
}

# ~~~=== Decoy IAM Roles ===~~~

locals {
  roles_data = csvdecode(file("${path.module}/roles.csv"))
}

resource "google_project_service" "iam_service" {
  project = var.project
  service = "iam.googleapis.com"
}

resource "google_project_iam_custom_role" "custom_role" {
  for_each    = { for role in local.roles_data : role.role_id => role }
  role_id     = each.value.role_id
  title       = each.value.title
  description = each.value.description
  permissions = [
    "compute.instances.list",
    "compute.instances.get",
  ]
}

resource "google_project_iam_member" "custom_role_member" {
  for_each = google_project_iam_custom_role.custom_role
  project  = var.project
  role     = each.value.id
  member   = "user:example@example.com"
}

# ~~~=== Flag IAM Roles ===~~~

resource "google_project_iam_custom_role" "flag_role" {
  role_id     = "ComputeOperator"
  title       = "Compute Operator"
  description = var.flag
  permissions = [
    "compute.instances.list",
    "compute.instances.get",
  ]
}

resource "google_project_iam_member" "flag_role_member" {
  project = var.project
  role    = google_project_iam_custom_role.flag_role.id
  member  = "user:example@example.com"
}

# ~~~=== Service Account ===~~~

resource "google_service_account" "cicd_service_account" {
  account_id   = "buildkite-agent"
  display_name = "A service account for the CI/CD pipeline."
}

resource "google_service_account_key" "private_service_account_key" {
  service_account_id = google_service_account.cicd_service_account.name
}

resource "local_file" "private_key" {
  content  = base64decode(google_service_account_key.private_service_account_key.private_key)
  filename = "${path.module}/../publish/credentials.json"
}

resource "google_project_iam_custom_role" "cicd_role" {
  role_id     = "ECSDeveloper"
  title       = "ECS Developer"
  description = "A role to allow our Devlopers to interact with the ECS environment"
  permissions = [
    "iam.roles.list",
  ]
}

resource "google_project_iam_member" "list_roles_member" {
  project = var.project
  role    = google_project_iam_custom_role.cicd_role.id
  member  = "serviceAccount:${google_service_account.cicd_service_account.email}"
}
