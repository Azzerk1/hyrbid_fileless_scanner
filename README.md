# ============================================================
# Fileless Memory Scanner: Python dependencies and LLM key
# ============================================================
#
# USE py -m pip install -r requirements.txt ON NEW MACHINES
# MUST BE IN THE SAME DIRECTORY
#
# PYTHON VERSION THE PROJECT WAS DEVELOPED ON 3.11.5
#
# SETUP INSTRUCTIONS
# ------------------
# 1. Install Python 3.11
#
# 2. (Recommended) Create a virtual environment:
#
#    python -m venv venv
#    venv\Scripts\activa
#
# 3. Install all dependencies:
#
#    pip install -r requirements.txt
#
# 4. Set your Anthropic API key (for LLM analysis):
#
#    Set ANTHROPIC_API_KEY in the local environment before launching the application.
#
#    LLM functionality requires an Anthropic API key supplied by the user through a local environment variable. For security and cost reasons, no API key is included in the submission.
#
# 5. Place the compiled memory_scanner.pyd (C++ extension) in the python_gui/ folder.
#
#    Build it with:
#    cd agent_module
#
#    pip install pybind11
#    python setup.py build_ext --inplace
#
# 6. Run the application:
#    python python_gui.py
# ============================================================

# ------ GUI framework ------------------------------------------
PyQt5>=5.15.9

# ------ LLM (Claude API) ---------------------------------------
anthropic>=0.25.0

# ------ Machine learning ---------------------------------------
scikit-learn>=1.4.0
joblib>=1.3.2
numpy>=1.26.0

# ------ Data handling ------------------------------------------
pandas>=2.2.0

# ------ Visualisation (Verify panel charts) --------------------
matplotlib>=3.8.0
