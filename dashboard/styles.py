def get_custom_css() -> str:
    """
    Returns enterprise dark SOC security dashboard CSS styles for Streamlit.
    """
    return """
    <style>
    /* Dark SOC Terminal Global Theme */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    }
    
    /* Header Bar */
    .soc-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.75rem 1.25rem;
        background-color: #161b22;
        border-bottom: 1px solid #30363d;
        border-radius: 4px;
        margin-bottom: 1rem;
    }
    
    .soc-title {
        font-size: 1.25rem;
        font-weight: 700;
        color: #f0f6fc;
        letter-spacing: 0.5px;
    }
    
    .soc-status-online {
        display: inline-block;
        padding: 0.25rem 0.6rem;
        background-color: rgba(46, 160, 67, 0.15);
        color: #3fb950;
        border: 1px solid rgba(46, 160, 67, 0.4);
        border-radius: 3px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    
    /* SOC Compact Panels */
    .soc-panel {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .soc-panel-title {
        font-size: 0.85rem;
        font-weight: 600;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 0.5rem;
    }
    
    .soc-metric-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #f0f6fc;
    }
    
    .soc-metric-subtext {
        font-size: 0.75rem;
        color: #8b949e;
        margin-top: 0.2rem;
    }
    
    /* Badges */
    .badge-attack {
        background-color: rgba(248, 81, 73, 0.15);
        color: #f85149;
        border: 1px solid rgba(248, 81, 73, 0.4);
        padding: 0.2rem 0.5rem;
        border-radius: 3px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    .badge-benign {
        background-color: rgba(63, 185, 80, 0.15);
        color: #3fb950;
        border: 1px solid rgba(63, 185, 80, 0.4);
        padding: 0.2rem 0.5rem;
        border-radius: 3px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .badge-info {
        background-color: rgba(88, 166, 255, 0.15);
        color: #58a6ff;
        border: 1px solid rgba(88, 166, 255, 0.4);
        padding: 0.2rem 0.5rem;
        border-radius: 3px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    /* Terminal Log Feed */
    .soc-log-box {
        background-color: #010409;
        border: 1px solid #30363d;
        border-radius: 4px;
        padding: 0.75rem;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 0.8rem;
        color: #7d8590;
        max-height: 250px;
        overflow-y: auto;
    }
    
    .log-line-info { color: #58a6ff; }
    .log-line-warn { color: #d29922; }
    .log-line-alert { color: #f85149; }
    .log-line-success { color: #3fb950; }

    /* Hide default Streamlit padding & footer elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
    """
