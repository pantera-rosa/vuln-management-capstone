# VulnGuard
Automated Detection, Assessment, and Remediation of Unfixed Software Vulnerabilities Using Machine Learning
## File Structure
```
.
├── README.md
├── eda
│   └── EDA.ipynb
└── src
    ├── backend
    │   ├── Dockerfile
    │   ├── app                           # web app logic
    │   │   ├── api
    │   │   │   ├── __init__.py
    │   │   │   └── route.py              
    │   │   └── main.py                   
    │   ├── aws                           # AWS logic 
    │   │   ├── ecr
    │   │   ├── lambdas
    │   │   ├── sagemaker
    │   │   ├── step_functions
    │   │   └── storage
    │   ├── schemas                       # schema models for requests/responses
    │   ├── tests
    │   ├── utils                         # common util functions
    │   └── workflow                      # workflow components logic
    │       ├── vuln_assess
    │       │   ├── __init__.py
    │       │   ├── vuln_rank.py
    │       │   └── vuln_severity.py
    │       ├── vuln_detect
    │       │   ├── __init__.py
    │       │   ├── vuln_filter.py
    │       │   ├── vuln_query.py
    │       │   └── vuln_scan.py
    │       └── vuln_remediate
    │           ├── __init__.py
    │           ├── vuln_analyze_code.py
    │           └── vuln_generate_fix.py
    └── frontend
        ├── Dockerfile
        └── src
```