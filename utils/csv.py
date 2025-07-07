import csv

def read_csv(filepath):
    with open(filepath, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def write_csv(filepath, data, fieldnames):
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)