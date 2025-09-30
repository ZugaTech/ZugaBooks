import pandas as pd
import numpy as np
from datetime import date, timedelta

def get_mock_data(report_type: str) -> pd.DataFrame:
    """
    Generates realistic-looking mock financial data as a pandas DataFrame.

    Args:
        report_type (str): The type of report to generate.
                           Options: "Profit & Loss", "Balance Sheet", "Transaction List".

    Returns:
        pd.DataFrame: A DataFrame containing the mock data for the specified report.
    """
    today = date.today()

    if report_type == "Profit & Loss":
        data = {
            "Account": [
                "Income", "  Sales Revenue", "  Service Revenue", "Total Income",
                "Cost of Goods Sold", "  Purchases", "Total COGS", "Gross Profit",
                "Expenses", "  Advertising", "  Salaries & Wages", "  Rent", "  Software Subscriptions",
                "Total Expenses", "Net Profit"
            ],
            "Amount": [
                None, 250000.50, 75000.25, 325000.75,
                None, 120000.00, 120000.00, 205000.75,
                None, 15000.00, 85000.00, 24000.00, 6000.00,
                130000.00, 75000.75
            ]
        }
        df = pd.DataFrame(data)
        # Format the Amount column for better readability
        df['Amount'] = df['Amount'].apply(lambda x: f"${x:,.2f}" if pd.notna(x) else "")
        return df

    elif report_type == "Balance Sheet":
        data = {
            "Category": [
                "Assets", "  Current Assets", "    Cash and Cash Equivalents", "    Accounts Receivable",
                "  Fixed Assets", "    Property and Equipment", "Total Assets",
                "Liabilities & Equity", "  Liabilities", "    Accounts Payable", "    Long-term Debt",
                "  Equity", "    Retained Earnings", "Total Liabilities & Equity"
            ],
            "Balance": [
                None, None, 150000.00, 45000.00, None, 275000.00, 470000.00,
                None, None, 35000.00, 120000.00, None, 315000.00, 470000.00
            ]
        }
        df = pd.DataFrame(data)
        df['Balance'] = df['Balance'].apply(lambda x: f"${x:,.2f}" if pd.notna(x) else "")
        return df

    elif report_type == "Transaction List":
        num_rows = 50
        vendors = ["Stripe", "Office Depot", "AWS", "Zoom", "Slack", "Shell", "Salesforce"]
        customers = ["Client A", "Client B", "Client C"]
        names = vendors + customers
        
        data = {
            "Date": [today - timedelta(days=np.random.randint(1, 365)) for _ in range(num_rows)],
            "Transaction Type": np.random.choice(["Invoice", "Payment", "Expense"], size=num_rows),
            "Num": [np.random.randint(1000, 5000) for _ in range(num_rows)],
            "Name": np.random.choice(names, size=num_rows),
            "Memo/Description": ["Services Rendered", "Office Supplies", "Cloud Hosting", "Monthly Subscription", "Fuel"] * (num_rows // 5),
            "Account": np.random.choice(["Checking", "Sales", "Utilities", "Software"], size=num_rows),
            "Amount": np.random.uniform(-500, 2500, size=num_rows).round(2)
        }
        df = pd.DataFrame(data)
        df = df.sort_values(by="Date", ascending=False).reset_index(drop=True)
        return df

    else:
        return pd.DataFrame()