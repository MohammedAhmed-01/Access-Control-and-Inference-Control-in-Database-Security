📌 Access Control & Inference Control in Database Security

A practical implementation project demonstrating how to secure database systems using Access Control mechanisms and Inference Control techniques. This repository includes SQL scripts, examples, and documentation to explain how different security models work and how to protect sensitive information from direct and indirect disclosure.

🚀 Project Overview

This project explores two core components of database security:

1. Access Control

Ensuring that users can only view or modify data they are authorized to access.
Includes implementations of:

Role-Based Access Control (RBAC)

Discretionary Access Control (DAC)

Mandatory Access Control (MAC) (conceptual explanation)

SQL privilege management (GRANT, REVOKE)

2. Inference Control

Protecting sensitive data from being inferred through aggregate queries or statistical techniques.
Includes:

Aggregation attack examples

Tracker & differencing attacks

Query restriction rules

Secure view creation

Noise addition & anonymization concepts

🧠 What This Repository Contains

✔️ SQL scripts for creating users, roles, and privileges

✔️ Access control examples (RBAC, DAC)

✔️ Example of inference attacks and how to prevent them

✔️ Secure view creation to block sensitive queries

✔️ A complete practical assignment report

✔️ Documentation explaining each security mechanism

📁 Repository Structure

.
├── access_control/

│   ├── create_roles.sql

│   ├── grant_permissions.sql

│   ├── revoke_permissions.sql

│   └── dac_rbac_examples.sql


│
├── inference_control/

│   ├── aggregation_attack.sql

│   ├── differencing_attack.sql

│   ├── secure_views.sql

│   └── query_restrictions.sql
│

├── docs/

│   ├── Practical_Assignment_Report.pdf

│   └── Explanation.md

│

└── README.md
🛠️ Technologies Used

Sql Server / SSMS

SQL (Roles, Privileges, Views)

Database Security Concepts

🎯 Learning Outcomes

By using this project, students will understand how to:

Enforce fine-grained access control in databases

Prevent sensitive data leakage through inference attacks

Apply secure query design principles

Implement practical database security solutions

📝 License

This project is open-source and intended for academic and learning purposes.
