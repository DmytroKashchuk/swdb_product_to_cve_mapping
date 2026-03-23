# Mapping Products from the Spiceworks Database

This repository documents how we mapped products from the Spiceworks database to the products identified in the Spiceworks dataset.

## Mapping Methods

We performed the mapping using several different approaches:

- **Matching via CNA**  
  In this method, the **CNA** is used as the vendor and product reference in text form.  
  Overall, this includes approximately **400 CNAs** compared against around **10,000 technologies**.

- **Matching via CPE**

- **Normalized Matching via CPE**

## How CPE Works

A CPE follows this structure:

```text
cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}
