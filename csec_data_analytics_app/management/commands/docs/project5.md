# Project 5: Enhancing Data Extraction with Large Language Models

## Overview

This project builds upon your previous work with the NVD vulnerability descriptions. Your task is to leverage a Large Language Model to glean new, structured insights from these descriptions.

## Steps to Follow

### Set Up Your Working Environment
- Start by opening GitHub Desktop. Fetch the latest updates for the project and integrate these changes into your ongoing work.

### Prepare for API Interaction
1. **Acquire an OpenAI API Key**:
   - Sign up at OpenAI and navigate to [OpenAI API Keys](https://platform.openai.com/api-keys).
   - Generate a new secret key and ensure its security. A complimentary $5 credit should suffice for this assignment.

2. **Establish API Connectivity**:
   - Use your secret key to establish a connection with the OpenAI API and verify its functionality.

### Process Vulnerability Descriptions
3. **Feature Extraction via GPT-4**:
   - Choose `gpt-4-1106-preview` for processing. Iterate through 25 NVD vulnerability descriptions (from Project 3).
   - Design and execute prompts to extract a specific data feature, already identified in the NVD, that seems inferable from the descriptions.

4. **Data Integration and Validation**:
   - Integrate the newly extracted feature into your MongoDB document.
   - Implement a boolean flag to denote the validation status of each new feature, facilitating human review for accuracy.

5. **Model Comparison and Evaluation**:
   - Assess the precision of extracted features against the original NVD data.
   - Repeat the extraction using `gpt-3.5-turbo` and analyze the differences in output accuracy.

### BONUS (Optional)
- Innovate by identifying and extracting a novel feature from the descriptions. Incorporate this into your machine learning model from Project 4 and evaluate any performance enhancements.

## Submission Guidelines

Your submission should include the following components:

### **Cover Page**:
  - Your full name
  - Date of submission
  - Course title and number

### **Detailed Report**

#### 1. Code Documentation (40% of total score)
Present the complete code developed for the Chat Completion Manager class. Ensure the submission is in text format, not screenshots.

#### 2. Analytical Reflection (60% of total score)
Delve into your prompt construction strategy. Break down each element of your prompts, explaining their purpose and considering alternative approaches.

Evaluate the reliability of the vulnerability description in context to your selected feature extraction. Reflect on both the successes and failures in the language model's performance.

#### BONUS (Extra 10%)
For those attempting the bonus challenge, include your updated machine learning code with the new feature integration. Provide a comparative analysis of the model's performance pre- and post-integration of the new feature.
