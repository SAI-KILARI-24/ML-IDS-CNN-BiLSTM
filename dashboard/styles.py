def get_custom_css() -> str:
    """
    Returns clean, professional Light Theme CSS styles for academic software presentation.
    """
    return """
    <style>
    /* Clean Light Theme Global Styles */
    .stApp {
        background-color: #f8fafc;
        color: #0f172a;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Header Area */
    .app-header {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }

    .app-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #0f172a;
        margin: 0;
    }

    .app-subtitle {
        font-size: 0.9rem;
        color: #64748b;
        margin-top: 0.25rem;
    }

    /* Status Banners - Semantic Colors on Light Background */
    .status-box-attack {
        background-color: #fef2f2;
        border: 1px solid #fca5a5;
        padding: 1.25rem;
        border-radius: 6px;
        color: #991b1b;
        margin-bottom: 1.5rem;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
    }

    .status-box-benign {
        background-color: #f0fdf4;
        border: 1px solid #86efac;
        padding: 1.25rem;
        border-radius: 6px;
        color: #166534;
        margin-bottom: 1.5rem;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
    }

    .status-title {
        font-size: 1.15rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }

    /* Minimal Panel Boxes */
    .panel-box {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
    }

    /* Simple Badges */
    .badge-attack {
        background-color: #fee2e2;
        color: #dc2626;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-weight: 700;
    }

    .badge-benign {
        background-color: #dcfce7;
        color: #16a34a;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-weight: 700;
    }

    /* File Uploader Container */
    [data-testid="stFileUploader"] {
        background-color: #ffffff;
        border: 1px solid #cbd5e1;
        border-radius: 6px;
        padding: 0.75rem;
    }

    /* Normal-sized Action Button */
    div.stButton > button[kind="primary"] {
        background-color: #2563eb !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        border: 1px solid #1d4ed8 !important;
        border-radius: 6px !important;
        padding: 0.5rem 1.25rem !important;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05) !important;
    }

    div.stButton > button[kind="primary"]:hover {
        background-color: #1d4ed8 !important;
    }

    /* Hide default Streamlit clutter */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """
