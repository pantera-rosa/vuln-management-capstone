# VulnGuard
Automated Detection, Assessment, and Remediation of Unfixed Software Vulnerabilities Using Machine Learning
## Folder Structure
```
.
├── eda
└── src
   ├── backend
   │   ├── app                          # web app logic
   │   │   └── api
   │   ├── aws                          # AWS logic
   │   │   ├── ecr
   │   │   ├── lambdas
   │   │   ├── sagemaker
   │   │   ├── step_functions
   │   │   └── storage
   │   ├── schemas                      # schema models for requests/responses 
   │   ├── utils                        # common util functions
   │   └── workflow                     # workflow components logic
   │       ├── vuln_assess
   │       ├── vuln_detect
   │       └── vuln_remediate
   └── frontend
       └── src
    
```