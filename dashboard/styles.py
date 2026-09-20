def get_custom_css() -> str:
    """
    Returns clean, professional, minimal CSS styles for academic software presentation.
    """
    return """
    <style>
    /* Clean Academic Neutral Theme */
    .stApp {
        background-color: #0f172a;
        color: #f8fafc;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Header Area */
    .app-header {
        border-bottom: 1px solid #334155;
        padding-bottom: 1rem;
        margin-bottom: 1.5rem;
    }

    .app-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #f8fafc;
        margin: 0;
    }

    .app-subtitle {
        font-size: 0.9rem;
        color: #94a3b8;
        margin-top: 0.25rem;
    }

    /* Status Banners - Semantic Color Only */
    .status-box-attack {
        background-color: #450a0a;
        border: 1px solid #dc2626;
        padding: 1rem 1.25rem;
        border-radius: 4px;
        color: #fef2f2;
        margin-bottom: 1.5rem;
    }

    .status-box-benign {
        background-color: #052e16;
        border: 1px solid #16a34a;
        padding: 1rem 1.25rem;
        border-radius: 4px;
        color: #f0fdf4;
        margin-bottom: 1.5rem;
    }

    .status-title {
        font-size: 1.1rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }

    /* Minimal Panel Boxes */
    .panel-box {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 4px;
        padding: 1rem;
        margin-bottom: 1.25rem;
    }

    /* Simple Badges */
    .badge-attack {
        color: #ef4444;
        font-weight: 600;
    }

    .badge-benign {
        color: #22c55e;
        font-weight: 600;
    }

    /* Normal-sized Action Button */
    div.stButton > button[kind="primary"] {
        background-color: #2563eb !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
        border: 1px solid #3b82f6 !important;
        border-radius: 4px !important;
        padding: 0.5rem 1.25rem !important;
    }

    div.stButton > button[kind="primary"]:hover {
        background-color: #1d4ed8 !important;
    }

    /* Hide default Streamlit clutter */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """
