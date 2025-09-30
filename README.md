
# 📊 ZugaBooks Financial Reporting Demo

ZugaBooks is a **production-ready demonstration** of a Streamlit-powered financial reporting application. It showcases a clean, intuitive user interface for fetching financial reports, visualizing data, and managing simulated connections to services like QuickBooks Online and Google Sheets.

This repository is intentionally built as a **portfolio piece** for potential employers, demonstrating best practices in UI/UX design, state management, and creating robust, user-friendly applications with Streamlit.

---

## ✨ Features

- 🔐 **Secure User Login**: A simple and clean authentication screen (try `demo`/`demo`).
- 📊 **Interactive Dashboard**: At-a-glance financial KPIs and charts for key metrics like revenue, expenses, and profit trends.
- 📄 **Dynamic Reporting**: Generate mock financial statements:
  - Profit & Loss
  - Balance Sheet
  - Transaction List
- ⚙️ **Simulated API Connections**: A settings page that demonstrates a user-friendly flow for connecting to external services like QuickBooks and Google Sheets.
- 📤 **Data Export**: Download generated reports as a CSV or use the mock "Export to Google Sheets" feature.
- 📱 **Responsive Design**: A clean, modern UI that works seamlessly on desktop and mobile devices.
- 💡 **Graceful Fallbacks**: The app is designed to be fully interactive without requiring real API keys, using high-quality mock data to simulate a live environment.

---

## 🛠️ Tech Stack

- **Frontend**: [Streamlit](https://streamlit.io/)
- **Data Manipulation**: [Pandas](https://pandas.pydata.org/) & [NumPy](https://numpy.org/)
- **Authentication**: [bcrypt](https://pypi.org/project/bcrypt/) for password hashing
- **Deployment**: Ready for services like Streamlit Community Cloud or Render.

---

## 🚀 How to Run Locally

This demo is designed to run out-of-the-box with no external dependencies or API keys required.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/ZugaBooks.git
    cd ZugaBooks
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    # Create a virtual environment (optional but recommended)
    python -m venv .venv
    source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`

    # Install the required packages
    pip install -r requirements.txt
    ```

3.  **Run the Streamlit app:**
    ```bash
    streamlit run app.py
    ```

The application will open automatically in your web browser. Enjoy the demo!

---

## 🖼️ Screenshots

*(Placeholder for app screenshots or a GIF showing the application flow)*

![ZugaBooks Dashboard](https://raw.githubusercontent.com/zugatech/ZugaBooks/main/assets/zugabooks_dashboard.png)
