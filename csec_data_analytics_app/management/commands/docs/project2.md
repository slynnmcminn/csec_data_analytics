# Project 2: Django API Endpoint Development

## Introduction

This project will guide you through creating an API endpoint in Django to manage vulnerability objects. The emphasis 
will be on understanding schema validation in Django and the serialization process prior to data storage.

## Instructions
> Open GitHub Desktop and pull changes for the project. Although it's unlikely, you may need to reconcile changes with your
local repository.

1. **Understanding the API View**: 
   - Navigate to `csec_data_analytics_app/views/views_vulnerability.py`.
   - Familiarize yourself with the sample API endpoint that provides a framework for the CRUD operations (Create, 
Read, Update, Delete) using the Django REST Framework.

2. **URL Mapping Exploration**: 
   - Open `csec_data_analytics/urls.py`.
   - Identify the connection between the Django URL path and the API View.

3. **Serializer Development**: 
   - Proceed to `csec_data_analytics_app/models.py`.
   - Craft a model serializer by referring to the JSON Schema definition available at [CVE API JSON Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema).
   - Use at least 10 attributes, including a nested document structure, from the JSON Schema.

4. **API Function Completion**: 
   - Return to `csec_data_analytics_app/views/views_vulnerability.py`.
   - Develop the API functions using your model serializer from the previous step, ensuring the API can create, retrieve, 
update, and delete vulnerability records.

5. **API Function Validation**: 
   - Leverage the Django REST Framework Browsable API to validate the functionality of each API method. This can be 
accessed by running the Django Server locally, and navigating to http://localhost:8000/vulnerability in your browser. 

## Submission Requirements

Compile a detailed report comprising:

- **Cover Page**: 
  - Your name
  - Submission date
  - Course designation

- **Code Documentation**: 
  - Include your refined code from `views_vulnerability.py`.
  - Present the model you've designed in `csec_data_analytics_app/models.py`.

- **Testing Overview**: 
  - Provide a concise walkthrough highlighting the successful execution of each API method. Use screenshots for clarity.

- **Reflection and Understanding**: 
  - Answer the following questions:
    - What is the primary purpose of an API Endpoint?
    - How does the Django REST Framework streamline the API development process?
    - Can you describe a real-world application for the vulnerability objects you've developed?
    - Identify two significant security risks when exposing this API to the public. How would you address these concerns?
