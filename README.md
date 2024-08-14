# Azure Key Vault Let's Encrypt

This repository contains a function app that uses Let's Encrypt to sign Azure Key Vault certificates.

## Features

Let's Encrypt HTTP-01 Challenge

- Free certificate signing
- No need to grant access to your DNS provider, a simple http redirect is all that is needed.

Key Vault

- Private key never leaves Key Vault.

## Usage

## Acknowledgment

The ACME (RFC8555) module in this project was adapted from the acme-rs library found at https://github.com/kariustobias/acme-rs.
