import json
import random
import string
from datetime import datetime, timedelta

# Sample customer IDs
customer_ids = ['CUST123', 'CUST456', 'CUST789', 'CUST101', 'CUST202']

# Generate sample banking transaction types
transaction_types = [
    'Account Transfer', 'Wire Transfer', 'Bill Payment', 'ATM Withdrawal', 
    'Deposit', 'Account Credit', 'Mobile Payment', 'Credit Card Payment', 
    'Online Banking Login'
]

# Generate sample transactions
transactions = []
for i in range(45):  # Generate 45 transactions
    transaction = {
        "transaction_id": f"txn_{i + 1}",
        "customer_id": random.choice(customer_ids),
        "amount": round(random.uniform(10, 500), 2),
        "transaction_type": random.choice(transaction_types),
        "timestamp": (datetime.now() - timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%d %H:%M:%S")
    }
    transactions.append(transaction)

# Save transactions to a JSON file
with open('mobile_money_transactions.json', 'w') as file:
    json.dump(transactions, file, indent=4)
