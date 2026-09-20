import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import streamlit as st
from typing import Dict, Any, List

import config


class SOCDashboardComponents:
    """
    Modular UI Components for Enterprise Dark SOC IDS Security Console.
    Designed for clarity, high data density, and zero generic AI clutter.
    """

    @staticmethod
    def render_header(model_loaded: bool, pcap_loaded: bool):
        model_badge = '<span class="soc-status-online">MODEL ONLINE (PyTorch 1D-CNN+BiLSTM)</span>' if model_loaded else '<span class="badge-attack">MODEL OFFLINE</span>'
        pcap_badge = '<span class="badge-info">PCAP LOADED</span>' if pcap_loaded else '<span style="color:#8b949e;">NO PCAP ACTIVE</span>'

        st.markdown(
            f"""
            <div class="soc-header">
                <div>
                    <div class="soc-title">SECURITY OPERATIONS CENTER (SOC) // INTRUSION DETECTION SYSTEM</div>
                    <div style="font-size:0.75rem; color:#8b949e; margin-top:2px;">Real-Time Payload Inspection & Explainable AI Threat Engine</div>
                </div>
                <div>
                    {model_badge} &nbsp; {pcap_badge}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    @staticmethod
    def render_overview_kpis(stats: Dict[str, Any]):
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.markdown(
                f"""
                <div class="soc-panel">
                    <div class="soc-panel-title">System Status</div>
                    <div class="soc-metric-value" style="color:#3fb950; font-size:1.2rem;">{stats.get('status', 'SYSTEM READY')}</div>
                    <div class="soc-metric-subtext">Engine: Active</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col2:
            st.markdown(
                f"""
                <div class="soc-panel">
                    <div class="soc-panel-title">Total Packets</div>
                    <div class="soc-metric-value">{stats.get('total_packets', 'N/A')}</div>
                    <div class="soc-metric-subtext">Ingested Packets</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col3:
            total_attacks = stats.get('attacks_detected', 0)
            color = "#f85149" if total_attacks > 0 else "#f0f6fc"
            st.markdown(
                f"""
                <div class="soc-panel">
                    <div class="soc-panel-title">Attacks Detected</div>
                    <div class="soc-metric-value" style="color:{color};">{total_attacks if 'total_packets' in stats else 'N/A'}</div>
                    <div class="soc-metric-subtext">Malicious Threats</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col4:
            st.markdown(
                f"""
                <div class="soc-panel">
                    <div class="soc-panel-title">Benign Traffic</div>
                    <div class="soc-metric-value" style="color:#3fb950;">{stats.get('benign_traffic', 'N/A')}</div>
                    <div class="soc-metric-subtext">Normal Packets</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with col5:
            conf = stats.get('avg_confidence', None)
            conf_str = f"{conf * 100:.1f}%" if conf is not None else "N/A"
            st.markdown(
                f"""
                <div class="soc-panel">
                    <div class="soc-panel-title">Avg Confidence</div>
                    <div class="soc-metric-value" style="color:#58a6ff;">{conf_str}</div>
                    <div class="soc-metric-subtext">Inference Score</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    @staticmethod
    def render_detection_table(detections: List[Dict[str, Any]]):
        if not detections:
            st.info("SYSTEM READY. Upload a PCAP file and run analysis to populate live detection feed.")
            return

        df_data = []
        for d in detections:
            pred_label = d.get("pred_label", "Unknown")
            gt_label = d.get("ground_truth", "N/A")
            is_attack = "Benign" not in pred_label

            df_data.append({
                "Timestamp": d.get("timestamp_str", "N/A"),
                "Packet ID": f"Pkt #{d.get('packet_id', '0')}",
                "Src IP": d.get("src_ip", "N/A"),
                "Dst IP": d.get("dst_ip", "N/A"),
                "Proto": d.get("protocol", "N/A"),
                "Ground Truth": gt_label,
                "Predicted Attack Class": pred_label,
                "Confidence": f"{d.get('confidence', 0.0) * 100:.1f}%",
                "Threat Level": "ATTACK" if is_attack else "BENIGN"
            })

        df = pd.DataFrame(df_data)

        # Style table
        st.dataframe(
            df,
            use_container_width=True,
            column_config={
                "Confidence": st.column_config.TextColumn("Confidence"),
                "Threat Level": st.column_config.TextColumn("Threat Status"),
            },
            hide_index=True
        )

    @staticmethod
    def render_confusion_matrix_plot(cm: List[List[int]], classes: List[str]):
        fig, ax = plt.subplots(figsize=(7, 5))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#161b22")

        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=classes,
            yticklabels=classes,
            ax=ax,
            cbar=False,
            annot_kws={"size": 9, "color": "white"}
        )

        ax.set_title("PyTorch 1D-CNN+BiLSTM Confusion Matrix", color="#f0f6fc", fontsize=11, pad=12)
        ax.set_xlabel("Predicted Class", color="#8b949e", fontsize=9)
        ax.set_ylabel("True Class", color="#8b949e", fontsize=9)

        ax.tick_params(colors="#8b949e", labelsize=8)
        plt.xticks(rotation=45, ha="right")
        plt.yticks(rotation=0)
        plt.tight_layout()

        st.pyplot(fig)
        plt.close(fig)

    @staticmethod
    def render_shap_heatmap(byte_shap_scores: List[float], top_bytes: List[Dict[str, Any]]):
        scores_arr = np.array(byte_shap_scores).reshape((32, 32))  # 32x32 = 1024 bytes grid

        fig, ax = plt.subplots(figsize=(8, 4))
        fig.patch.set_facecolor("#161b22")
        ax.set_facecolor("#161b22")

        im = ax.imshow(scores_arr, cmap="coolwarm", aspect="auto")
        cbar = fig.colorbar(im, ax=ax)
        cbar.ax.yaxis.set_tick_params(color="#8b949e")
        plt.setp(plt.getp(cbar.ax, 'yticklabels'), color="#8b949e")

        ax.set_title("1024-Byte Payload SHAP Importance Grid (32 x 32 Byte Offsets)", color="#f0f6fc", fontsize=10)
        ax.set_xlabel("Byte Offset Col (0..31)", color="#8b949e", fontsize=8)
        ax.set_ylabel("Byte Offset Row (0..31)", color="#8b949e", fontsize=8)
        ax.tick_params(colors="#8b949e", labelsize=8)
        plt.tight_layout()

        st.pyplot(fig)
        plt.close(fig)

        # Top Contributing Bytes Table
        st.markdown("<div class='soc-panel-title' style='margin-top:1rem;'>Top Influential Byte Offsets</div>", unsafe_allow_html=True)
        top_df = pd.DataFrame(top_bytes)
        if not top_df.empty:
            st.dataframe(
                top_df[["byte_offset", "hex_byte", "raw_byte", "norm_value", "shap_score", "impact"]],
                use_container_width=True,
                hide_index=True
            )
