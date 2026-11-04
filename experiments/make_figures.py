#!/usr/bin/env python3
"""
Render the figures used on the project site from results/:

  figures/diffusion_alignment.png   absolute vs injection-aligned diffusion curves (the v1.0 confound)
  figures/detection_matrix.png      which tier flags which function, from the full sweep

Usage:
  python experiments/make_figures.py --results results --out figures
"""

import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

BG = "#0d1117"
FG = "#e6edf3"
DIM = "#8b949e"
GRID = "#30363d"
PALETTE = {"sha3_256": "#58a6ff", "sm3": "#d2a8ff", "sha256": "#3fb950", "sha512": "#39c5bb",
           "md5": "#f0883e", "sha1": "#f85149"}
LABEL = {"sha3_256": "SHA-3-256", "sm3": "SM3", "sha256": "SHA-256", "sha512": "SHA-512", "md5": "MD5", "sha1": "SHA-1"}


def style(ax):
    ax.set_facecolor(BG)
    for s in ax.spines.values():
        s.set_color(GRID)
    ax.tick_params(colors=DIM, labelsize=9)
    ax.xaxis.label.set_color(FG)
    ax.yaxis.label.set_color(FG)
    ax.title.set_color(FG)
    ax.grid(True, color=GRID, linewidth=0.6, alpha=0.6)


def diffusion_figure(diff, out):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6), facecolor=BG)
    for ax, key, title in [(axes[0], "curve", "As measured in v1.0: by absolute round number"),
                           (axes[1], "aligned_curve", "Corrected: rounds after the flipped word enters the state")]:
        style(ax)
        for name in ["sha3_256", "sm3", "sha256", "sha512", "md5", "sha1"]:
            r = diff[name]
            pts = r[key]
            xk = "round" if key == "curve" else "rounds_since_injection"
            xs = [p[xk] for p in pts if p[xk] <= 24]
            ys = [100 * p["normalized"] for p in pts if p[xk] <= 24]
            ax.plot(xs, ys, marker="o", markersize=3, linewidth=1.8, color=PALETTE[name], label=LABEL[name])
        ax.axhline(90, color=DIM, linestyle="--", linewidth=0.8)
        ax.text(24, 91.5, "90%", color=DIM, fontsize=8, ha="right")
        ax.set_ylim(0, 105)
        ax.set_xlim(0, 24)
        ax.set_xlabel("round" if key == "curve" else "rounds since injection")
        ax.set_ylabel("state bits changed (% of ideal)")
        ax.set_title(title, fontsize=11)
    axes[1].legend(facecolor=BG, edgecolor=GRID, labelcolor=FG, fontsize=9, loc="lower right")
    fig.suptitle("Internal diffusion after a one-bit message change — six hash functions",
                 color=FG, fontsize=13, y=1.0)
    fig.text(0.5, -0.04,
             "Left: Merkle–Damgård functions look slow because most message words have not been absorbed yet at low "
             "round numbers (one word per round; the sponge absorbs the whole block at once).\n"
             "Right: aligned on injection, SHA-256 reaches 90% five rounds after a word enters; SM3's apparent lead "
             "disappears (its message expansion injects each word four rounds early).",
             color=DIM, fontsize=8.5, ha="center", va="top")
    fig.tight_layout()
    fig.savefig(out, dpi=160, bbox_inches="tight", facecolor=BG)
    plt.close(fig)


def matrix_figure(sweep, out):
    R = sweep["results"]
    tiers = ["Statistical\n(classifier)", "Differential", "Extended", "Linear"]
    names = list(R.keys())
    grid = []
    for n in names:
        r = R[n]
        ml = r.get("meta_learner") or {}
        row = [1 if ml.get("probability", 0) >= 0.4 else 0,
               1 if any(v.get("detected") for v in (r.get("differential_summary") or {}).values()) else 0,
               1 if any(v.get("detected") for v in (r.get("extended_summary") or {}).values()) else 0,
               1 if (r.get("linear_summary") or {}).get("detected") else 0]
        grid.append(row)

    cell_w = 1.25
    fig, ax = plt.subplots(figsize=(7.2, 0.3 * len(names) + 1.2), facecolor=BG)
    ax.set_facecolor(BG)
    for i, n in enumerate(names):
        y = len(names) - 1 - i
        for j in range(4):
            flagged = grid[i][j]
            color = "#f85149" if flagged else "#1f6f3f"
            ax.add_patch(plt.Rectangle((j * cell_w, y), cell_w, 1, facecolor=color, edgecolor=BG, linewidth=2))
            ax.text(j * cell_w + cell_w / 2, y + 0.5, "signal" if flagged else "clean",
                    ha="center", va="center", color=FG, fontsize=7.5)
        cat = R[n]["category"]
        ax.text(-0.12, y + 0.5, n, ha="right", va="center", color=FG, fontsize=8.5, family="monospace")
        ax.text(4 * cell_w + 0.15, y + 0.5, cat, ha="left", va="center", color=DIM, fontsize=7.5)
    for j, t in enumerate(tiers):
        ax.text(j * cell_w + cell_w / 2, len(names) + 0.2, t, ha="center", va="bottom", color=FG, fontsize=8.5)
    ax.set_xlim(-2.4, 4 * cell_w + 1.3)
    ax.set_ylim(-0.2, len(names) + 1.5)
    ax.axis("off")
    n_samples = sweep["args"]["samples"]
    fig.suptitle(f"Which tier flags which function — full level, N = {n_samples:,}", color=FG, fontsize=12, y=0.995)
    fig.text(0.5, 0.005, "Red = at least one test in the tier reported a signal. Oracle controls are seeded random functions "
             "matched to each output width.", color=DIM, fontsize=8, ha="center")
    fig.savefig(out, dpi=160, bbox_inches="tight", facecolor=BG)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "figures"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    diff = json.load(open(os.path.join(args.results, "diffusion_comparison.json")))
    sweep = json.load(open(os.path.join(args.results, "sweep_10k.json")))
    diffusion_figure(diff, os.path.join(args.out, "diffusion_alignment.png"))
    matrix_figure(sweep, os.path.join(args.out, "detection_matrix.png"))
    print(f"wrote figures to {args.out}")


if __name__ == "__main__":
    main()
