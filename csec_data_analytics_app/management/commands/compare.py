from django.core.management.base import BaseCommand
import random

def validate_extracted_data(original_descriptions, extracted_data, sample_size=10):
    # Ensure lists are not empty
    if not original_descriptions or not extracted_data:
        print("Data lists are empty or not loaded correctly.")
        return []

    # Ensure sample size is not larger than the dataset
    actual_sample_size = min(sample_size, len(original_descriptions))

    # Randomly select samples
    sample_indexes = random.sample(range(len(original_descriptions)), actual_sample_size)

    # Initialize results list
    results_list = []

    for index in sample_indexes:
        original = original_descriptions[index]
        extracted = extracted_data[index]

        print("Original Description:")
        print(original)
        print("Extracted Data:")
        print(extracted)

        is_accurate = input("Is the extracted data accurate? (yes/no): ")
        is_complete = input("Is the extracted data complete? (yes/no): ")

        results_list.append({
            "index": index,
            "is_accurate": is_accurate.lower() == 'yes',
            "is_complete": is_complete.lower() == 'yes'
        })

    return results_list

class Command(BaseCommand):
    help = 'Compare original and extracted data.'

    def handle(self, *args, **options):
        with open(r'C:\Users\slynn\Downloads\vulnerability_descriptions.txt', 'r') as file:
            original_descriptions = [line.strip() for line in file.readlines()]

        with open(r'C:\Users\slynn\Downloads\vulnerability_descriptions.txt', 'r') as file:
            extracted_data = [line.strip() for line in file.readlines()]

        if not original_descriptions or not extracted_data:
            print("Data not loaded correctly.")
            return

        validation_results = validate_extracted_data(original_descriptions, extracted_data)

        if validation_results is None:
            print("Validation results are None.")
            return

        for result in validation_results:
            print(f"Index: {result['index']}, Accurate: {result['is_accurate']}, Complete: {result['is_complete']}")
