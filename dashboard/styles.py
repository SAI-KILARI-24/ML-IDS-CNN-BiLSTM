def get_custom_css() -> str:
    """
    Returns vibrant, high-contrast colorful CSS styles for the ML-IDS Streamlit dashboard.
    """
    return """
    <style>
    /* Global Colorful Dark Theme */
    .stApp {
        background: linear-gradient(180deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        color: #f8fafc;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    
    /* Header Banner */
    .soc-header-banner {
        background: linear-gradient(135deg, #1e1b4b 0%, #312e81 40%, #4338ca 100%);
        padding: 1.5rem 1.8rem;
        border-radius: 12px;
        border: 1px solid #6366f1;
        box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.3);
        margin-bottom: 1.8rem;
    }

    .soc-title {
        font-size: 1.6rem;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: 0.5px;
        text-shadow: 0 2px 4px rgba(0,0,0,0.4);
    }
    
    .soc-subtitle {
        font-size: 0.95rem;
        color: #c7d2fe;
        margin-top: 6px;
        font-weight: 500;
    }

    /* Vibrant KPI Cards */
    .kpi-card {
        padding: 1.25rem;
        border-radius: 12px;
        color: #ffffff;
        box-shadow: 0 8px 20px rgba(0,0,0,0.3);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
        margin-bottom: 1rem;
    }

    .kpi-blue {
        background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
        border: 1px solid #60a5fa;
    }

    .kpi-red {
        background: linear-gradient(135deg, #881337 0%, #e11d48 100%);
        border: 1px solid #fb7185;
    }

    .kpi-green {
        background: linear-gradient(135deg, #064e3b 0%, #10b981 100%);
        border: 1px solid #34d399;
    }

    .kpi-purple {
        background: linear-gradient(135deg, #581c87 0%, #9333ea 100%);
        border: 1px solid #c084fc;
    }

    .kpi-title {
        font-size: 0.85rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        opacity: 0.9;
    }

    .kpi-value {
        font-size: 2rem;
        font-weight: 900;
        margin: 6px 0;
    }

    .kpi-sub {
        font-size: 0.78rem;
        opacity: 0.85;
    }

    /* Status Result Banners */
    .banner-attack {
        background: linear-gradient(135deg, #4c0519 0%, #9f1239 50%, #be123c 100%);
        border: 2px solid #f43f5e;
        box-shadow: 0 10px 30px rgba(244, 63, 94, 0.4);
        padding: 1.5rem;
        border-radius: 12px;
        color: #ffffff;
        margin-bottom: 1.5rem;
    }

    .banner-benign {
        background: linear-gradient(135deg, #022c22 0%, #065f46 50%, #047857 100%);
        border: 2px solid #10b981;
        box-shadow: 0 10px 30px rgba(16, 185, 129, 0.4);
        padding: 1.5rem;
        border-radius: 12px;
        color: #ffffff;
        margin-bottom: 1.5rem;
    }

    /* Vibrant Badges */
    .badge-attack {
        background-color: #f43f5e;
        color: #ffffff;
        padding: 0.25rem 0.6rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 700;
        display: inline-block;
    }

    .badge-benign {
        background-color: #10b981;
        color: #ffffff;
        padding: 0.25rem 0.6rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 700;
        display: inline-block;
    }

    .badge-info {
        background-color: #3b82f6;
        color: #ffffff;
        padding: 0.25rem 0.6rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 700;
        display: inline-block;
    }

    /* Styled Container Cards */
    .soc-card {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1.2rem;
        backdrop-filter: blur(8px);
    }

    /* Custom Buttons */
    div.stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #6366f1 0%, #8b5cf6 50%, #d946ef 100%) !important;
        color: #ffffff !important;
        font-weight: 800 !important;
        font-size: 1.1rem !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.75rem 1.5rem !important;
        box-shadow: 0 4px 15px rgba(139, 92, 246, 0.4) !important;
        transition: all 0.3s ease !important;
    }

    div.stButton > button[kind="primary"]:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 25px rgba(217, 70, 239, 0.6) !important;
    }

    /* File Uploader Container */
    [data-testid="stFileUploader"] {
        background: rgba(30, 41, 59, 0.5);
        border: 2px dashed #6366f1;
        border-radius: 12px;
        padding: 1rem;
    }

    /* Hide default Streamlit padding & footer */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """
