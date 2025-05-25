import pandas as pd

def get_report_dataframe(rows, report_type):
    data = []
    columns = set()

    for row in rows:
        if 'ColData' in row:
            row_data = {f"Column_{i}": col.get('value', '') for i, col in enumerate(row['ColData'])}
            data.append(row_data)
            columns.update(row_data.keys())
        elif 'Summary' in row:
            # Optional: handle summaries or totals if needed
            continue

    if not data:
        return pd.DataFrame()

    df = pd.DataFrame(data)
    
    # Optional cleaning based on report type
    if report_type == "ProfitAndLoss":
        # Try to assign meaningful column names if pattern is known
        col_names = ['Account', 'Amount'] if df.shape[1] == 2 else df.columns.tolist()
        df.columns = col_names
    elif report_type == "TransactionList":
        col_names = [
            "Date", "Transaction Type", "Num", "Name", "Account", 
            "Memo/Description", "Split", "Amount", "Balance"
        ]
        if len(df.columns) == len(col_names):
            df.columns = col_names

    return df


def apply_custom_categories(df, csv_file):
    try:
        map_df = pd.read_csv(csv_file)
        if "Vendor" not in map_df.columns or "Category" not in map_df.columns:
            raise ValueError("CSV must contain 'Vendor' and 'Category' columns.")
        
        category_map = dict(zip(map_df["Vendor"], map_df["Category"]))

        if "Name" in df.columns:
            df["Category"] = df["Name"].map(category_map).fillna("Uncategorized")
        elif "Account" in df.columns:
            df["Category"] = df["Account"].map(category_map).fillna("Uncategorized")
        else:
            df["Category"] = "Uncategorized"
    except Exception as e:
        print(f"Error applying categories: {e}")
        df["Category"] = "Uncategorized"

    return df
