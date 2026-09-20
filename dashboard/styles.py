def get_custom_css() -> str:
    """
    Returns exact CSS styles matching the target dashboard screenshot (media_1789888585094.png).
    """
    return """
    <style>
    /* Global Page Styling */
    .stApp {
        background-color: #0d1527 !important; /* Top dark header outer background */
        color: #0f172a;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Main Container Light Content Area */
    .main .block-container {
        background-color: #f4f6fa;
        max-width: 100% !important;
        padding: 0rem 2rem 2rem 2rem !important;
        margin-top: 0rem !important;
    }

    /* Top Dark Header Bar */
    .top-header-bar {
        background-color: #0d1527;
        color: #ffffff;
        padding: 1.2rem 2rem;
        margin: 0rem -2rem 1.5rem -2rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #1e293b;
    }

    .top-header-title {
        font-size: 1.35rem;
        font-weight: 700;
        color: #ffffff;
        margin: 0;
        letter-spacing: -0.2px;
    }

    .top-header-sub {
        font-size: 0.82rem;
        color: #94a3b8;
        margin-top: 2px;
    }

    .top-header-desc {
        font-size: 0.75rem;
        color: #64748b;
        margin-top: 1px;
    }

    .system-ready-pill {
        background-color: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 0.35rem 0.85rem;
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
        margin-bottom: 0.35rem;
        margin-top: 0.5rem;
    }

    .section-sub {
        font-size: 0.85rem;
        color: #64748b;
        margin-top: -0.2rem;
        margin-bottom: 1rem;
    }

    /* White Panel Cards */
    .white-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.02);
    }

    /* Selected File Bar Box */
    .file-selected-box {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 0.85rem 1.25rem;
        margin-top: 0.75rem;
        margin-bottom: 1.25rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.02);
    }

    /* Attack Result Box (Pink Background, Red Border) */
    .result-box-attack {
        background-color: #fff1f2;
        border: 1px solid #ffe4e6;
        border-radius: 6px;
        padding: 1.25rem;
        margin-bottom: 1.25rem;
    }

    .result-title-attack {
        color: #dc2626;
        font-size: 1.2rem;
        font-weight: 800;
        display: flex;
        align-items: center;
        gap: 0.6rem;
        margin-bottom: 1rem;
    }

    /* Benign Result Box (Green Background) */
    .result-box-benign {
        background-color: #f0fdf4;
        border: 1px solid #dcfce7;
        border-radius: 6px;
        padding: 1.25rem;
        margin-bottom: 1.25rem;
    }

    .result-title-benign {
        color: #16a34a;
        font-size: 1.2rem;
        font-weight: 800;
        margin-bottom: 0.5rem;
    }

    /* Result Metrics */
    .res-metric-label {
        font-size: 0.78rem;
        color: #64748b;
        font-weight: 500;
        margin-bottom: 2px;
    }

    .res-metric-val-red {
        font-size: 1.4rem;
        font-weight: 800;
        color: #dc2626;
    }

    .res-metric-val-dark {
        font-size: 1.4rem;
        font-weight: 800;
        color: #0f172a;
    }

    /* Status Pill Badges in Table */
    .pill-attack {
        background-color: #fee2e2;
        color: #dc2626;
        padding: 0.2rem 0.65rem;
        border-radius: 12px;
        font-size: 0.78rem;
        font-weight: 700;
        display: inline-block;
    }

    .pill-benign {
        background-color: #dcfce7;
        color: #16a34a;
        padding: 0.2rem 0.65rem;
        border-radius: 12px;
        font-size: 0.78rem;
        font-weight: 700;
        display: inline-block;
    }

    /* Primary Action Button (Analyze PCAP) */
    div.stButton > button[kind="primary"] {
        background-color: #2563eb !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        font-size: 0.95rem !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 0.6rem 1.4rem !important;
        box-shadow: 0 1px 2px rgba(37, 99, 235, 0.2) !important;
    }

    div.stButton > button[kind="primary"]:hover {
        background-color: #1d4ed8 !important;
    }

    /* Secondary / Clear Button (New Analysis) */
    div.stButton > button[kind="secondary"] {
        background-color: #f1f5f9 !important;
        color: #334155 !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        border: 1px solid #cbd5e1 !important;
        border-radius: 6px !important;
        padding: 0.45rem 1rem !important;
    }

    div.stButton > button[kind="secondary"]:hover {
        background-color: #e2e8f0 !important;
        color: #0f172a !important;
    }

    /* Explainability Callout Box */
    .explain-info-box {
        background-color: #eff6ff;
        border: 1px solid #dbeafe;
        border-radius: 6px;
        padding: 0.85rem 1rem;
        color: #1d4ed8;
        font-size: 0.85rem;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    /* Streamlit Table Styling */
    .stTable {
        background-color: #ffffff;
        border-radius: 6px;
        border: 1px solid #e2e8f0;
    }

    /* Hide Streamlit Default UI elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """
