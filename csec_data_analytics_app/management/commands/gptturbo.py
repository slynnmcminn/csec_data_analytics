import openai
import subprocess

project_directory = 'my_django_project'

virtual_environment = 'myenv'
command = f'python {project_directory}/manage.py gptturbo --endpoint v1/chat/completions'

activate_command = f'{virtual_environment}\\Scripts\\activate'

try:
    subprocess.run(activate_command, shell=True, check=True)
    subprocess.run(command, shell=True, check=True)
except subprocess.CalledProcessError as e:
    print(f"Error: {e}")

openai.api_key = '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'
original_descriptions_file_path = r'C:\Users\slynn\Downloads\vulnerability_descriptions.txt'
gpt4_extracted_data_file_path = r'C:\Users\slynn\Downloads\gpt4_extracted_features.txt'
gpt35_extracted_data_file_path = r'C:\Users\slynn\Downloads\gpt35_extracted_features.txt'

def extract_features_with_chat(model, descriptions):
    extracted_features = []
    for description in descriptions:
        try:
            prompt = "Extract the main features from the following vulnerability description:\n" + description
            response = openai.Completion.create(
                model=model,
                prompt=prompt,
                max_tokens=100,
                stop=None  # You can set stopping criteria if necessary
            )
            extracted_feature = response.choices[0].text.strip()
            extracted_features.append(extracted_feature)
        except Exception as e:
            print(f"An error occurred with model {model}: {e}")
            extracted_features.append(None)
    return extracted_features

with open(original_descriptions_file_path, 'r') as file:
    original_descriptions = [line.strip() for line in file.readlines()]

gpt35_extracted_features = extract_features_with_chat("gpt-3.5-turbo", original_descriptions)

with open(gpt35_extracted_data_file_path, 'w') as file:
    for feature in gpt35_extracted_features:
        file.write(f"{feature}\n")

with open(gpt4_extracted_data_file_path, 'r') as file:
    gpt4_extracted_features = [line.strip() for line in file.readlines()]

for i in range(len(original_descriptions)):
    print(f"Original Description: {original_descriptions[i]}")
    print(f"GPT-4 Extracted: {gpt4_extracted_features[i]}")
    print(f"GPT-3.5-Turbo Extracted: {gpt35_extracted_features[i]}")
    print("-" * 50)
