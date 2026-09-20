def get_custom_css() -> str:
    """
    Returns exact CSS styles matching the target dashboard screenshot.
    """
    return """
    <style>
    /* Global Page Styling */
    .stApp {
        background-color: #f4f6fa;
        color: #0f172a;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Top Dark Header Bar */
    .top-header-bar {
        background-color: #0b1329;
        color: #ffffff;
        padding: 1rem 2rem;
        margin: -4rem -4rem 1.5rem -4rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .top-header-title {
        font-size: 1.4rem;
        font-weight: 700;
        color: #ffffff;
        margin: 0;
    }

    .top-header-sub {
        font-size: 0.85rem;
        color: #94a3b8;
        margin-top: 2px;
    }

    .system-ready-pill {
        background-color: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* Section Headings */
    .section-head {
        font-size: 1.1rem;
        font-weight: 700;
        color: #0f172a;
        margin-bottom: 0.5rem;
    }

    .section-sub {
        font-size: 0.85rem;
        color: #64748b;
        margin-top: -0.25rem;
        margin-bottom: 1rem;
    }

    /* Card Panels */
    .content-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    }

    /* Selected File Bar */
    .file-selected-bar {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 0.75rem 1.25rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-top: 1rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }

    /* Attack Result Box (Red alert matching mockup) */
    .result-box-attack {
        background-color: #fff1f2;
        border: 1px solid #ffe4e6;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1.25rem;
    }

    .result-title-attack {
        color: #e11d48;
        font-size: 1.2rem;
        font-weight: 800;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 1rem;
    }

    /* Benign Result Box */
    .result-box-benign {
        background-color: #f0fdf4;
        border: 1px solid #dcfce7;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1.25rem;
    }

    .result-title-benign {
        color: #16a34a;
        font-size: 1.2rem;
        font-weight: 800;
        margin-bottom: 0.5rem;
    }

    .metric-label {
        font-size: 0.8rem;
        color: #64748b;
        font-weight: 500;
    }

    .metric-val-red {
        font-size: 1.5rem;
        font-weight: 800;
        color: #e11d48;
    }

    .metric-val-dark {
        font-size: 1.5rem;
        font-weight: 800;
        color: #0f172a;
    }

    /* Table Badges */
    .pill-attack {
        background-color: #ffe4e6;
        color: #e11d48;
        padding: 0.15rem 0.6rem;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }

    .pill-benign {
        background-color: #dcfce7;
        color: #16a34a;
        padding: 0.15rem 0.6rem;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
    }

    /* Buttons */
    div.stButton > button[kind="primary"] {
        background-color: #2563eb !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        font-size: 0.95rem !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 0.6rem 1.4rem !important;
    }

    div.stButton > button[kind="primary"]:hover {
        background-color: #1d4ed8 !important;
    }

    /* Info Explainability Box */
    .explain-info-box {
        background-color: #eff6ff;
        border: 1px solid #dbeafe;
        border-radius: 6px;
        padding: 0.85rem 1rem;
        color: #1e40af;
        font-size: 0.85rem;
        margin-bottom: 1rem;
    }

    /* Hide default Streamlit header & footer padding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """
