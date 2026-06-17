#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Load your existing CSV
csv_file = "bandwidth.csv"
df = pd.read_csv(csv_file)

# Recreate the exact styling from your script
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 6), facecolor="#0f1117")
for ax in (ax1, ax2):
    ax.set_facecolor("#1a1d27")
    ax.tick_params(colors="#64748b")
    for spine in ax.spines.values():
        spine.set_edgecolor("#2d3748")

# Plot 1: Bandwidth
ax1.fill_between(df["second"], df["bytes_kb"], alpha=0.7, color="#00d4ff")
ax1.plot(df["second"], df["bytes_kb"], color="#00d4ff", linewidth=1.5)
ax1.set_ylabel("KB/s", color="#e2e8f0")
ax1.set_title("Bandwidth History", color="#e2e8f0")

# Plot 2: Protocol breakdown
ax2.bar(df["second"], df["tcp"], color="#22c55e", label="TCP", alpha=0.8)
ax2.bar(df["second"], df["udp"], color="#00d4ff", label="UDP", bottom=df["tcp"], alpha=0.8)
ax2.set_xlabel("Seconds", color="#e2e8f0")
ax2.set_ylabel("Packets", color="#e2e8f0")
ax2.legend(facecolor="#1a1d27", labelcolor="#e2e8f0")

plt.tight_layout()

# Save and show
out_png = Path(csv_file).with_suffix(".png")
plt.savefig(out_png, dpi=150, facecolor="#0f1117")
print(f"Plot saved to: {out_png}")
plt.show()