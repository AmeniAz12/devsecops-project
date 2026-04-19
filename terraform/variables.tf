variable "image_name" {
  default = "devsecops-image:latest"
}

variable "staging_replicas" {
  default = 1
}

variable "prod_replicas" {
  default = 2
}
