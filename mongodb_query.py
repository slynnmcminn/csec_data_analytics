from pymongo import MongoClient

client = MongoClient('localhost', 27017)  # Replace with your MongoDB server details

db = client['django-mongo']

vulnerability_collection = db['vulnerability']

for document in vulnerability_collection.find():
    print(document)
    try:
        except Exception as e:(
            print("An error occurred:", e))

        # Don't forget to close the client connection when done
client.close()
