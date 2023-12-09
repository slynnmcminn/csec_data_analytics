# Project 4: Machine Learning Over Vulnerability Data

## Introduction

In this project you will develop a machine learning model for vulnerability data to be used for decision support 
by cybersecurity analysts. Your model will predict whether a vulnerability is likely to have an exploit based on 
historical data from the National Vulnerability Database.

## Instructions
> Open GitHub Desktop and pull changes for the project. Use these updates to copy into your existing ongoing project.

Use your vulnerability documents collected from the NVD in project 3 and train a machine learning model 

1. **Import data from MongoDB**: 
   - Extract the vulnerability records, previously gathered from the NVD in Project 3, and place them into a pandas dataframe.

2. **Train the Machine Learning Model**: 
   - Using SciKitLearn (sklearn), proceed to train your model using the `RandomForestClassifier` to predict whether a vulnerability will have a known exploit.

3. **Test your Model**: 
   - Partition your dataset into training and testing segments and then evaluate your model's performance on the test set.

4. **Evaluate Testing Metrics**:
   - Carry out a cross-validation analysis. Specifically, extract and analyze metrics like the average F1 score, false positive rate, and false negative rate.

5. **Evaluate Feature Importance**:
   - Examine the significance of each feature utilized by your model in making predictions.


**Bonus 1**:
   - Use a different classifier to perform the same analysis

**Bonus 2**:
   - Export the data to csv, and supply training labels for risk in order to train a new model that predicts the risk 
level for vulnerabilities. Note that you only need to label a minimum of 100 rows of data and delete the remaining data.

## Submission Requirements

Compile a report comprising:

### **Cover Page**: 
  - Your name
  - Submission date
  - Course designation

### **Assignment Documentation**

---

#### 1. Code Documentation (30 points)

Integrate within your report the MLManager class and any auxiliary code formulated during this project.

---

#### 2. Machine Learning Model Analysis (30 points)

   - Report the testing results from your machine learning model. (20 points)
   - Report the feature importance from your machine learning model. (10 points)

---

#### 3. Reflection and Understanding (40 points)

a. Delve into the metrics from your model and articulate the derived results. (10 points)

b. In the realm of cybersecurity, what potential complications could arise from the observed false positive and false negative rates? (10 points)

c. Identify potential data attributes that, if included, could enhance your model's predictions? (10 points)

d. Based on the feature significance, explain why certain attributes play a pivotal role in predictions, while others could potentially be omitted. (10 points)

#### Bonus 1 (10 points)
Present the code you used to perform the separate analysis on the classifier and compare the resulting model metrics and determine which classifier you would recommend for this task.

#### Bonus 2 (10 points)
Describe your new predictive model and evaluate its performance. Include a copy of the training data with your submission.
